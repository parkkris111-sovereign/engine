//! # Cryptographic Execution Lineage
//!
//! Manages the sequential, domain-separated cryptographic history of execution epochs.
//!
//! ## Invariants
//!
//! 1. **Strict Lineage Binding:** Epoch identity and seed material MUST NOT exist solely as metadata;
//!    they are cryptographically bound into the execution lineage hash ($H_{\text{lineage}}$).
//! 2. **Epoch Separation:** Distinct epoch IDs or seeds yield distinct lineage histories, preventing
//!    cross-epoch replay attack vectors.

use crate::protocol::{encode_canonical, StateHash, DOMAIN_GENESIS, PROTOCOL_VERSION};
use sha2::{Digest, Sha256};

/// An immutable, cryptographically chained record of engine execution history.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionLineage {
    /// Current cryptographic lineage digest ($H_{\text{lineage}}$).
    lineage_hash: StateHash,
}

impl ExecutionLineage {
    /// Bootstraps a fresh execution lineage anchored to canonical epoch and seed inputs.
    ///
    /// Mathematical construction:
    /// ```text
    /// H_lineage = H(
    ///     u16_be(VERSION)
    ///     || DOMAIN_GENESIS
    ///     || Encode_Canonical(u64_le(epoch))
    ///     || Encode_Canonical(seed)
    /// )
    /// ```
    pub fn genesis(epoch: u64, seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();

        // 1. Version binding
        hasher.update(&PROTOCOL_VERSION.to_be_bytes());

        // 2. Domain separation
        hasher.update(DOMAIN_GENESIS);

        // 3. Cryptographically incorporated epoch identity
        let canonical_epoch = encode_canonical(&epoch.to_le_bytes());
        hasher.update(&canonical_epoch);

        // 4. Seed material
        let canonical_seed = encode_canonical(seed);
        hasher.update(&canonical_seed);

        let digest = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&digest);

        Self {
            lineage_hash: StateHash::new(hash_bytes),
        }
    }

    /// Access the underlying cryptographic lineage hash.
    #[inline]
    pub fn hash(&self) -> &StateHash {
        &self.lineage_hash
    }

    /// Extends the current lineage with deterministic transition execution data.
    pub fn extend(&mut self, transition_data: &[u8]) {
        let mut hasher = Sha256::new();

        hasher.update(&PROTOCOL_VERSION.to_be_bytes());
        hasher.update(self.lineage_hash.as_bytes());
        hasher.update(&encode_canonical(transition_data));

        let digest = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&digest);

        self.lineage_hash = StateHash::new(hash_bytes);
    }
}

#[cfg(test)]
mod tests {
    super::*;

    #[test]
    fn distinct_epochs_produce_distinct_lineage_hashes() {
        let seed = b"genesis_seed_material";

        let lineage_e1 = ExecutionLineage::genesis(1, seed);
        let lineage_e2 = ExecutionLineage::genesis(2, seed);

        assert_ne!(lineage_e1.hash(), lineage_e2.hash());
    }

    #[test]
    fn distinct_seeds_produce_distinct_lineage_hashes() {
        let lineage_a = ExecutionLineage::genesis(1, b"seed_a");
        let lineage_b = ExecutionLineage::genesis(1, b"seed_b");

        assert_ne!(lineage_a.hash(), lineage_b.hash());
    }
}
