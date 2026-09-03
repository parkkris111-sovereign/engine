//! # Terminal State Anchor Creation
//!
//! Constructs the unalterable terminal cryptographic commitment ($H_{\text{terminal}}$)
//! anchoring engine execution prior to a `rearm()` authorization flow.
//!
//! ## Invariant
//!
//! $H_{\text{terminal}}$ incorporates both the resident cryptographic history
//! ($H_{\text{lineage}}$) and final state transition data under `DOMAIN_TERMINAL`.

use crate::lineage::ExecutionLineage;
use crate::protocol::{encode_canonical, StateHash, DOMAIN_TERMINAL, PROTOCOL_VERSION};
use sha2::{Digest, Sha256};

/// Unalterable container anchoring terminal cryptographic engine state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalStateAnchor {
    /// Terminal cryptographic digest ($H_{\text{terminal}}$).
    terminal_hash: StateHash,
}

impl TerminalStateAnchor {
    /// Seals an active execution lineage and transition payload into a terminal state anchor.
    ///
    /// Mathematical rule:
    /// ```text
    /// H_terminal = H(
    ///     u16_be(VERSION)
    ///     || DOMAIN_TERMINAL
    ///     || H_lineage
    ///     || Encode_Canonical(terminal_transition_data)
    /// )
    /// ```
    pub fn seal(lineage: &ExecutionLineage, terminal_transition_data: &[u8]) -> Self {
        let mut hasher = Sha256::new();

        // 1. Version binding
        hasher.update(&PROTOCOL_VERSION.to_be_bytes());

        // 2. Domain separation
        hasher.update(DOMAIN_TERMINAL);

        // 3. Execution lineage hash
        hasher.update(lineage.hash().as_bytes());

        // 4. Length-prefixed terminal transition payload
        let canonical_transition = encode_canonical(terminal_transition_data);
        hasher.update(&canonical_transition);

        let digest = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&digest);

        Self {
            terminal_hash: StateHash::new(hash_bytes),
        }
    }

    /// Access the computed terminal state hash ($H_{\text{terminal}}$).
    #[inline]
    pub fn terminal_hash(&self) -> &StateHash {
        &self.terminal_hash
    }
}

#[cfg(test)]
mod tests {
    super::*;

    #[test]
    fn seal_binds_lineage_and_transition_data() {
        let lineage = ExecutionLineage::genesis(1, b"seed");
        let transition = b"terminal_state_snapshot";

        let anchor = TerminalStateAnchor::seal(&lineage, transition);

        // Mutated transition payload yields distinct terminal hash
        let anchor_mutated = TerminalStateAnchor::seal(&lineage, b"mutated_snapshot");
        assert_ne!(anchor.terminal_hash(), anchor_mutated.terminal_hash());
    }
}
