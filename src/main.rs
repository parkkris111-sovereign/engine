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
    pub canonical_payload_hash: String,
    pub running_lineage_hash: String,
}

// ============================================================================
// 2. MAIN ENTRYPOINT
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/municipal_audit".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    let state = AppState { db: pool };

    let app = Router::new()
        .route("/api/v1/events", post(ingest_municipal_event))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Sovereign Engine Municipal Worker listening on {}", addr);

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

    // 1. Fetch current active epoch & current max sequence number within transaction
    let epoch_record = sqlx::query!(
        r#"
        SELECT typestate::text, genesis_seed, initial_lineage_hash
        FROM engine_epochs
        WHERE epoch_id = $1
        FOR UPDATE
        "#,
        req.epoch_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_error)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Epoch {} not found", req.epoch_id)))?;

    if epoch_record.typestate.as_deref() != Some("IDLE") {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Epoch {} is not in IDLE state (state={:?})", req.epoch_id, epoch_record.typestate),
        ));
    }

    // 2. Compute canonical JSON byte representation and payload hash
    let canonical_payload_bytes = serde_json::to_vec(&req.payload).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid JSON payload: {}", e))
    })?;

    let payload_hash_bytes: [u8; 32] = Sha256::digest(&canonical_payload_bytes).into();

    // 3. Fetch current running lineage trace or initialize genesis from DB state
    let last_event = sqlx::query!(
        r#"
        SELECT sequence_number, running_lineage_hash
        FROM municipal_events
        WHERE epoch_id = $1
        ORDER BY sequence_number DESC
        LIMIT 1
        "#,
        req.epoch_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_error)?;

    let (next_seq, current_lineage_hash) = match last_event {
        Some(row) => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&row.running_lineage_hash);
            (row.sequence_number + 1, StateHash::from_bytes(hash))
        }
        None => {
            let mut init_hash = [0u8; 32];
            let init_bytes = epoch_record
                .initial_lineage_hash
                .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Uninitialized epoch lineage".into()))?;
            init_hash.copy_from_slice(&init_bytes);
            (1, StateHash::from_bytes(init_hash))
        }
    };

    // 4. Call Sovereign Engine lineage extension
    let mut lineage = ExecutionLineage::from_state(req.epoch_id as u64, current_lineage_hash);
    lineage.extend(&canonical_payload_bytes);
    let new_lineage_hash = *lineage.current_hash();

    // 5. Persist audit event and updated lineage to PostgreSQL
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

    // 6. Return cryptographic proof metadata to client
    Ok(Json(IngestEventResponse {
        event_id,
        sequence_number: next_seq,
        canonical_payload_hash: hex::encode(payload_hash_bytes),
        running_lineage_hash: hex::encode(new_lineage_hash.as_bytes()),
    }))
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
