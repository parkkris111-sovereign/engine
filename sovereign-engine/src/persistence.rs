use sha2::{Digest, Sha256};

use crate::protocol::{
    Domain,
    VERSION,
};

/// Canonical commitment:
///
/// SHA256(
///     VERSION_LE
///     || DOMAIN_PERSISTENCE
///     || TERMINAL_HASH
///     || ARTIFACT_LENGTH_LE
///     || ARTIFACT_BYTES
/// )
#[inline(always)]
pub fn compute_persistence_commitment(
    terminal_state_hash: &[u8; 32],
    artifact_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(&VERSION.to_le_bytes());
    hasher.update(&[
        Domain::PersistenceReceipt as u8
    ]);

    hasher.update(terminal_state_hash);

    hasher.update(
        &(artifact_bytes.len() as u64).to_le_bytes()
    );

    hasher.update(artifact_bytes);

    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistenceReceipt {
    commitment_hash: [u8; 32],
    epoch_timestamp: u64,
}

impl PersistenceReceipt {
    #[inline(always)]
    pub fn commitment_hash(&self) -> &[u8; 32] {
        &self.commitment_hash
    }

    #[inline(always)]
    pub fn epoch_timestamp(&self) -> u64 {
        self.epoch_timestamp
    }

    /// Intentionally crate-private.
    ///
    /// Only trusted persistence implementations inside the
    /// crate may manufacture a capability receipt.
    #[inline(always)]
    pub(crate) fn new(
        commitment_hash: [u8; 32],
        epoch_timestamp: u64,
    ) -> Self {
        Self {
            commitment_hash,
            epoch_timestamp,
        }
    }
}

pub trait PersistenceAdapter {
    type Error;

    fn persist_artifact(
        &mut self,
        terminal_state_hash: &[u8; 32],
        artifact_bytes: &[u8],
        timestamp: u64,
    ) -> Result<PersistenceReceipt, Self::Error>;
}

/// Reference adapter.
///
/// Replace the persistence body with an actual durable
/// write implementation.
pub struct StorageEngineAdapter;

impl StorageEngineAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl PersistenceAdapter for StorageEngineAdapter {
    type Error = &'static str;

    fn persist_artifact(
        &mut self,
        terminal_state_hash: &[u8; 32],
        artifact_bytes: &[u8],
        timestamp: u64,
    ) -> Result<PersistenceReceipt, Self::Error> {
        /*
         * DURABLE WRITE BOUNDARY
         *
         * Production implementation must perform the durable
         * storage operation before constructing the receipt.
         */

        let commitment =
            compute_persistence_commitment(
                terminal_state_hash,
                artifact_bytes,
            );

        Ok(PersistenceReceipt::new(
            commitment,
            timestamp,
        ))
    }
}
