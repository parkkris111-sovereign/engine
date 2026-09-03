use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

use sovereign_engine::engine::Engine;
use sovereign_engine::protocol::{StateHash, SystemFrame};
use sovereign_engine::seal::SealProof;

// ============================================================================
// 1. SEALER WORKER ENGINE
// ============================================================================

pub struct EpochSealerWorker {
    db: PgPool,
}

impl EpochSealerWorker {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Runs a continuous loop checking for epochs ready to seal.
    pub async fn run_loop(&self, check_interval: Duration) {
        tracing::info!("Starting Sovereign Engine Epoch Sealer Worker loop...");

        loop {
            if let Err(e) = self.process_sealable_epochs().await {
                tracing::error!("Error encountered during epoch sealing cycle: {}", e);
            }

            tokio::time::sleep(check_interval).await;
        }
    }

    /// Queries for active IDLE epochs and seals them atomically.
    pub async fn process_sealable_epochs(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Retrieve open IDLE epochs
        let epochs = sqlx::query!(
            r#"
            SELECT epoch_id 
            FROM engine_epochs 
            WHERE typestate = 'IDLE'
            ORDER BY epoch_id ASC
            "#
        )
        .fetch_all(&self.db)
        .await?;

        for record in epochs {
            tracing::info!("Attempting to seal Epoch {}...", record.epoch_id);
            match self.seal_epoch(record.epoch_id).await {
                Ok(receipt_id) => {
                    tracing::info!(
                        "Successfully sealed Epoch {}! Commitment Receipt ID: {}",
                        record.epoch_id,
                        receipt_id
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to seal Epoch {}: {}", record.epoch_id, e);
                }
            }
        }

        Ok(())
    }

    /// Executes the cryptographic seal operation inside a database transaction.
    pub async fn seal_epoch(&self, epoch_id: i64) -> Result<Uuid, Box<dyn std::error::Error>> {
        let mut tx: Transaction<'_, Postgres> = self.db.begin().await?;

        // 1. Lock the epoch row and fetch metadata
        let epoch = sqlx::query!(
            r#"
            SELECT typestate::text, genesis_seed, initial_lineage_hash
            FROM engine_epochs
            WHERE epoch_id = $1
            FOR UPDATE
            "#,
            epoch_id
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| format!("Epoch {} not found", epoch_id))?;

        if epoch.typestate.as_deref() != Some("IDLE") {
            return Err(format!("Epoch {} is not in IDLE state", epoch_id).into());
        }

        // 2. Fetch the latest running lineage hash for this epoch
        let latest_event = sqlx::query!(
            r#"
            SELECT running_lineage_hash, sequence_number
            FROM municipal_events
            WHERE epoch_id = $1
            ORDER BY sequence_number DESC
            LIMIT 1
            "#,
            epoch_id
        )
        .fetch_optional(&mut *tx)
        .await?;

        let terminal_lineage_bytes: [u8; 32] = match latest_event {
            Some(evt) => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&evt.running_lineage_hash);
                buf
            }
            None => {
                let mut buf = [0u8; 32];
                let init = epoch
                    .initial_lineage_hash
                    .ok_or_else(|| "Uninitialized epoch lineage".to_string())?;
                buf.copy_from_slice(&init);
                buf
            }
        };

        let terminal_lineage_hash = StateHash::from_bytes(terminal_lineage_bytes);

        // 3. Instantiate Sovereign Engine in IDLE state and execute seal()
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&epoch.genesis_seed);

        let idle_engine = Engine::from_active_state(epoch_id as u64, seed_bytes, terminal_lineage_hash);
        
        // Execute typestate transition: Engine<Idle> -> Engine<Sealed>
        let (sealed_engine, seal_proof): (Engine<sovereign_engine::engine::Sealed>, SealProof) = 
            idle_engine.seal();

        let terminal_state_hash = sealed_engine.terminal_hash();

        // 4. Construct canonical verification frame and commitment proof (C_receipt)
        let canonical_frame = SystemFrame::new(epoch_id as u64, seal_proof.sequence_number());
        let canonical_frame_bytes = canonical_frame.to_canonical_bytes();

        // C_receipt = SHA256(H_terminal || canonical_frame_bytes)
        let mut hasher = Sha256::new();
        hasher.update(terminal_state_hash.as_bytes());
        hasher.update(&canonical_frame_bytes);
        let receipt_commitment: [u8; 32] = hasher.finalize().into();

        // 5. Update engine_epochs typestate to SEALED
        sqlx::query!(
            r#"
            UPDATE engine_epochs
            SET typestate = 'SEALED'::engine_typestate,
                terminal_state_hash = $1,
                sealed_at = CURRENT_TIMESTAMP
            WHERE epoch_id = $2
            "#,
            terminal_state_hash.as_bytes(),
            epoch_id
        )
        .execute(&mut *tx)
        .await?;

        // 6. Write Commitment Receipt to PostgreSQL
        let receipt_id = Uuid::new_v4();

        sqlx::query!(
            r#"
            INSERT INTO commitment_receipts (
                receipt_id,
                epoch_id,
                terminal_hash,
                receipt_commitment,
                canonical_frame_bytes,
                is_rearm_verified,
                verified_at
            )
            VALUES ($1, $2, $3, $4, $5, FALSE, NULL)
            "#,
            receipt_id,
            epoch_id,
            terminal_state_hash.as_bytes(),
            &receipt_commitment[..],
            &canonical_frame_bytes[..]
        )
        .execute(&mut *tx)
        .await?;

        // Commit transaction
        tx.commit().await?;

        tracing::info!(
            "Epoch {} Sealed. Terminal Hash: {}",
            epoch_id,
            hex::encode(terminal_state_hash.as_bytes())
        );

        Ok(receipt_id)
    }
}

// ============================================================================
// 2. MAIN WORKER ENTRYPOINT
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/municipal_audit".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let worker = EpochSealerWorker::new(pool);
    
    // Check for epochs to seal every 30 seconds
    worker.run_loop(Duration::from_secs(30)).await;

    Ok(())
}
