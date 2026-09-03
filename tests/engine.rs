//! # Sovereign Engine Typestate Core & Rearm Transition
//!
//! Manages the compile-time typestate lifecycle of the engine.
//!
//! ## Invariants
//!
//! 1. **Typestate Safety:** Operations permitted in `Idle` cannot be invoked in `Sealed`.
//! 2. **Failure Atomicity:** On verification failure, `rearm()` returns `Err(self)`,
//!    leaving the engine completely unmodified in its original `Sealed` state.
//! 3. **State Independence:** The newly created `Idle` engine state is derived strictly
//!    from protocol genesis parameters, never inheriting external artifact payload bytes.

use crate::protocol::{StateHash, PROTOCOL_VERSION};
use crate::receipt::PersistenceReceipt;
use crate::verifier::{verify_rearm_authority, VerificationError};
use core::marker::PhantomData;

// ============================================================================
// TYPESTATE MARKERS
// ============================================================================

/// Typestate marker: Engine is initialized, operational, and ready for work.
#[derive(Debug)]
pub struct Idle {
    epoch: u64,
}

/// Typestate marker: Engine is halted and locked in a cryptographic terminal state.
#[derive(Debug)]
pub struct Sealed {
    epoch: u64,
    terminal_hash: StateHash,
}

// ============================================================================
// CORE ENGINE CONTAINER
// ============================================================================

/// The Sovereign Engine wrapped in zero-cost typestate `S`.
#[derive(Debug)]
pub struct Engine<S> {
    state: S,
}

impl Engine<Idle> {
    /// Bootstraps a new Engine in the `Idle` state from initial protocol parameters.
    pub fn new(epoch: u64) -> Self {
        Self { state: Idle { epoch } }
    }

    /// Access the current operational epoch.
    pub fn epoch(&self) -> u64 {
        self.state.epoch
    }

    /// Transitions the operational engine into a terminal `Sealed` state.
    pub fn seal(self, terminal_hash: StateHash) -> Engine<Sealed> {
        Engine {
            state: Sealed {
                epoch: self.state.epoch,
                terminal_hash,
            },
        }
    }
}

impl Engine<Sealed> {
    /// Access the resident terminal state hash ($H_{\text{terminal}}$).
    pub fn terminal_hash(&self) -> &StateHash {
        &self.state.terminal_hash
    }

    /// Access the current terminal epoch.
    pub fn epoch(&self) -> u64 {
        self.state.epoch
    }

    /// State-resident rearm authorization transition: `Sealed` -> `Idle`.
    ///
    /// Evaluates persistence capability evidence against state-resident $H_{\text{terminal}}$.
    ///
    /// # Failure Atomicity
    ///
    /// On any verification error, this function returns `Err((Self, VerificationError))`.
    /// Ownership of `self` is preserved without mutating its state or clearing $H_{\text{terminal}}$.
    ///
    /// # State Independence
    ///
    /// The returned `Engine<Idle>` derives its new state strictly using protocol rules
    /// (`next_epoch = epoch + 1`), explicitly ignoring external `artifact_bytes`.
    pub fn rearm(
        self,
        receipt: &PersistenceReceipt,
        artifact_bytes: &[u8],
    ) -> Result<Engine<Idle>, (Self, VerificationError)> {
        // Step 1-4: Run structural parsing, framing, recomputation & constant-time check
        if let Err(err) = verify_rearm_authority(&self.state.terminal_hash, receipt, artifact_bytes)
        {
            // Atomic failure: Return original ownership + error unharmed
            return Err((self, err));
        }

        // Step 5: Deterministic Next-State Derivation
        // Compute canonical next epoch strictly from protocol rules
        let next_epoch = self.state.epoch + 1;

        // Transition complete: return fresh Idle engine state
        Ok(Engine {
            state: Idle { epoch: next_epoch },
        })
    }
}

// ============================================================================
// TESTS & VERIFICATION
// ============================================================================

#[cfg(test)]
mod tests {
    super::*;
    use crate::verifier::compute_expected_commitment;

    #[test]
    fn successful_rearm_transitions_to_idle_with_next_epoch() {
        let terminal_hash = StateHash::new([0x77; 32]);
        let artifact = b"canonical_persisted_artifact";

        // Create sealed engine at epoch 1
        let engine_idle = Engine::new(1);
        let engine_sealed = engine_idle.seal(terminal_hash);

        // Generate receipt
        let expected_commitment = compute_expected_commitment(&terminal_hash, artifact);
        let receipt = PersistenceReceipt::new(expected_commitment);

        // Rearm transition
        let rearmed_engine = engine_sealed.rearm(&receipt, artifact).unwrap();

        // Must increment epoch according to protocol rule and enter Idle state
        assert_eq!(rearmed_engine.epoch(), 2);
    }

    #[test]
    fn failed_rearm_preserves_original_engine_ownership_atomically() {
        let terminal_hash = StateHash::new([0x77; 32]);
        let artifact = b"canonical_persisted_artifact";
        let mutated_artifact = b"mutated_persisted_artifact";

        let engine_idle = Engine::new(1);
        let engine_sealed = engine_idle.seal(terminal_hash);

        // Generate receipt for valid artifact
        let expected_commitment = compute_expected_commitment(&terminal_hash, artifact);
        let receipt = PersistenceReceipt::new(expected_commitment);

        // Attempt rearm with mutated artifact
        let rearm_result = engine_sealed.rearm(&receipt, mutated_artifact);

        assert!(rearm_result.is_err());
        let (recovered_engine, err) = rearm_result.unwrap_err();

        assert_eq!(err, VerificationError::CommitmentMismatch);
        // Engine retains original state, epoch, and state hash intact
        assert_eq!(recovered_engine.epoch(), 1);
        assert_eq!(recovered_engine.terminal_hash(), &terminal_hash);
    }
}
