use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use sovereign_engine::lineage::ExecutionLineage;
use sovereign_engine::protocol::StateHash;

// ============================================================================
// 1. APPLICATION STATE & DTOs
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}

#[derive(Debug, Deserialize)]
pub struct IngestEventRequest {
    pub epoch_id: i64,
    pub department_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct IngestEventResponse {
    pub event_id: Uuid,
    pub sequence_number: i64,
    #[serde(with = "hex_serialize")]
    pub canonical_payload_hash: [u8; 32],
    #[serde(with = "hex_serialize")]
    pub running_lineage_hash: [u8; 32],
}

mod hex_serialize {
    use serde::{Serializer, Deserializer, Deserialize};

    pub fn serialize<S>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let array: [u8; 32] = bytes.try_into().map_err(serde::de::Error::custom)?;
        Ok(array)
    }
}

// ============================================================================
// 2. MAIN ENTRYPOINT
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with configurable log level via RUST_LOG env var
    // Default to 'info' level; set RUST_LOG=debug for verbose output
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/municipal_audit".to_string());

    // Configurable connection pool size via DB_MAX_CONNECTIONS env var (default: 50)
    let max_connections: u32 = std::env::var("DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await?;

    let state = AppState { db: pool };

    let app = Router::new()
        .route("/api/v1/events", post(ingest_municipal_event))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Sovereign Engine Municipal Worker listening on {} (max_db_connections={})", addr, max_connections);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ============================================================================
// 3. HTTP HANDLER & LINEAGE INTEGRATION
// ============================================================================

async fn ingest_municipal_event(
    State(state): State<AppState>,
    Json(req): Json<IngestEventRequest>,
) -> Result<Json<IngestEventResponse>, (StatusCode, String)> {
    let mut tx = state.db.begin().await.map_err(internal_error)?;

    // OPTIMIZED: Combined query fetches both epoch record and last event in one round-trip
    // Uses LEFT JOIN to get most recent event if it exists, or NULL if none
    let combined = sqlx::query!(
        r#"
        SELECT 
            e.typestate::text,
            e.genesis_seed,
            e.initial_lineage_hash,
            m.sequence_number,
            m.running_lineage_hash
        FROM engine_epochs e
        LEFT JOIN (
            SELECT epoch_id, sequence_number, running_lineage_hash
            FROM municipal_events
            WHERE epoch_id = $1
            ORDER BY sequence_number DESC
            LIMIT 1
        ) m ON e.epoch_id = m.epoch_id
        WHERE e.epoch_id = $1
        FOR UPDATE OF e
        "#,
        req.epoch_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_error)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Epoch {} not found", req.epoch_id)))?;

    if combined.typestate.as_deref() != Some("IDLE") {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Epoch {} is not in IDLE state (state={:?})", req.epoch_id, combined.typestate),
        ));
    }

    // Compute canonical JSON byte representation and payload hash
    let canonical_payload_bytes = serde_json::to_vec(&req.payload).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid JSON payload: {}", e))
    })?;

    let payload_hash_bytes: [u8; 32] = Sha256::digest(&canonical_payload_bytes).into();

    // OPTIMIZED: Use TryInto to avoid unnecessary allocations
    let current_lineage_hash = match combined.sequence_number {
        Some(seq_num) => {
            let hash_bytes: [u8; 32] = combined
                .running_lineage_hash
                .as_deref()
                .ok_or_else(|| (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Missing lineage hash for existing event".into(),
                ))?
                .try_into()
                .map_err(|_| (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid lineage hash size".into(),
                ))?;
            (seq_num + 1, StateHash::from_bytes(hash_bytes))
        }
        None => {
            let init_hash_bytes: [u8; 32] = combined
                .initial_lineage_hash
                .ok_or_else(|| (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Uninitialized epoch lineage".into(),
                ))?
                .try_into()
                .map_err(|_| (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid initial lineage hash size".into(),
                ))?;
            (1, StateHash::from_bytes(init_hash_bytes))
        }
    };

    let (next_seq, current_lineage_hash_value) = current_lineage_hash;

    // Call Sovereign Engine lineage extension
    let mut lineage = ExecutionLineage::from_state(req.epoch_id as u64, current_lineage_hash_value);
    lineage.extend(&canonical_payload_bytes);
    let new_lineage_hash = *lineage.current_hash();

    // Persist audit event and updated lineage to PostgreSQL
    let event_id = Uuid::new_v4();

    sqlx::query!(
        r#"
        INSERT INTO municipal_events (
            event_id,
            epoch_id,
            sequence_number,
            department_id,
            event_type,
            payload_data,
            canonical_payload_hash,
            running_lineage_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        event_id,
        req.epoch_id,
        next_seq,
        req.department_id,
        req.event_type,
        req.payload,
        &payload_hash_bytes[..],
        new_lineage_hash.as_bytes()
    )
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;

    tx.commit().await.map_err(internal_error)?;

    // Return cryptographic proof metadata to client
    Ok(Json(IngestEventResponse {
        event_id,
        sequence_number: next_seq,
        canonical_payload_hash: payload_hash_bytes,
        running_lineage_hash: new_lineage_hash.as_bytes().try_into()
            .map_err(|_| internal_error("Lineage hash conversion failed"))?,
    }))
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
