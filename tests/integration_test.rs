//! # Sovereign Engine End-to-End Integration Suite
//!
//! Demonstrates the complete execution lifecycle across all 7 engine modules:
//! `Genesis -> Lineage -> Execution -> Seal -> Persistence -> Verification -> Rearm`.
//!
//! Asserts both success paths and critical failure attack vectors (tampered payload,
//! state substitution, cross-epoch replay).

use std::collections::HashMap;

// Import all seven modules from the sovereign_engine crate
use sovereign_engine::engine::Engine;
use sovereign_engine::lineage::ExecutionLineage;
use sovereign_engine::persistence::{PersistedArtifact, PersistenceAdapter, PersistenceError};
use sovereign_engine::protocol::{StateHash, PROTOCOL_VERSION};
use sovereign_engine::receipt::PersistenceReceipt;
use sovereign_engine::seal::TerminalStateAnchor;
use sovereign_engine::verifier::{compute_expected_commitment, VerificationError};

// ============================================================================
// MOCK UNTRUSTED PERSISTENCE ADAPTER
// ============================================================================

/// In-memory storage adapter treating persistence as unprivileged transport.
#[derive(Default)]
struct MemoryPersistenceAdapter {
    storage: HashMap<String, (Vec<u8>, PersistenceReceipt)>,
}

impl PersistenceAdapter for MemoryPersistenceAdapter {
    fn save_artifact(
        &mut self,
        artifact: &PersistedArtifact,
        receipt: &PersistenceReceipt,
    ) -> Result<(), PersistenceError> {
        self.storage.insert(
            "terminal_state".to_string(),
            (artifact.encode_canonical(), *receipt),
        );
        Ok(())
    }

    fn load_artifact(
        &self,
    ) -> Result<(PersistedArtifact, PersistenceReceipt), PersistenceError> {
        let (framed_bytes, receipt) = self
            .storage
            .get("terminal_state")
            .ok_or(PersistenceError::StorageIoFailure)?;

        let artifact = PersistedArtifact::decode_canonical_frame(framed_bytes)?;
        Ok((artifact, *receipt))
    }
}

// ============================================================================
// END-TO-END LIFECYCLE TESTS
// ============================================================================

#[test]
fn e2e_successful_lifecycle_execution_seal_and_rearm() {
    // ------------------------------------------------------------------------
    // 1. ENGINE BOOTSTRAP & LINEAGE ANCHOR (lineage.rs, engine.rs)
    // ------------------------------------------------------------------------
    let initial_epoch = 100u64;
    let seed_material = b"production_entropy_seed_v1";

    let mut lineage = ExecutionLineage::genesis(initial_epoch, seed_material);
    let engine_idle = Engine::new(initial_epoch);

    assert_eq!(engine_idle.epoch(), 100);

    // ------------------------------------------------------------------------
    // 2. OPERATIONAL TRANSITIONS & HISTORICAL CHAINING (lineage.rs)
    // ------------------------------------------------------------------------
    lineage.extend(b"state_transition_step_1");
    lineage.extend(b"state_transition_step_2");

    // ------------------------------------------------------------------------
    // 3. ENGINE HALT & SEALING (seal.rs, engine.rs)
    // ------------------------------------------------------------------------
    let terminal_payload = b"untrusted_snapshot_data_at_shutdown";
    let anchor = TerminalStateAnchor::seal(&lineage, terminal_payload);

    // Engine transitions into Sealed typestate
    let engine_sealed = engine_idle.seal(*anchor.terminal_hash());
    assert_eq!(engine_sealed.epoch(), 100);
    assert_eq!(engine_sealed.terminal_hash(), anchor.terminal_hash());

    // ------------------------------------------------------------------------
    // 4. PERSISTENCE & RECEIPT GENERATION (verifier.rs, persistence.rs, receipt.rs)
    // ------------------------------------------------------------------------
    // Compute independent persistence commitment bound to H_terminal
    let commitment = compute_expected_commitment(engine_sealed.terminal_hash(), terminal_payload);
    let receipt = PersistenceReceipt::new(commitment);

    let artifact = PersistedArtifact::new(terminal_payload.to_vec());
    let mut storage = MemoryPersistenceAdapter::default();

    // Transport framed artifact + capability receipt across transport boundary
    storage.save_artifact(&artifact, &receipt).unwrap();

    // ------------------------------------------------------------------------
    // 5. UNTRUSTED RETRIEVAL & VERIFICATION (persistence.rs, verifier.rs)
    // ------------------------------------------------------------------------
    let (loaded_artifact, loaded_receipt) = storage.load_artifact().unwrap();

    // ------------------------------------------------------------------------
    // 6. STATE-RESIDENT AUTHORIZED REARM TRANSITION (engine.rs)
    // ------------------------------------------------------------------------
    let rearm_result = engine_sealed.rearm(&loaded_receipt, loaded_artifact.payload());
    assert!(rearm_result.is_ok());

    let engine_rearmed = rearm_result.unwrap();

    // Next-state derivation strictly obeys deterministic protocol rules (epoch + 1)
    assert_eq!(engine_rearmed.epoch(), 101);
}

#[test]
fn attack_vector_tampered_artifact_fails_rearm_and_preserves_state() {
    let epoch = 100u64;
    let lineage = ExecutionLineage::genesis(epoch, b"seed");
    let terminal_payload = b"original_snapshot_data";

    let anchor = TerminalStateAnchor::seal(&lineage, terminal_payload);
    let engine_sealed = Engine::new(epoch).seal(*anchor.terminal_hash());

    let commitment = compute_expected_commitment(engine_sealed.terminal_hash(), terminal_payload);
    let receipt = PersistenceReceipt::new(commitment);

    // Adversary tampers with 1 byte of the persisted artifact payload
    let mut tampered_payload = terminal_payload.to_vec();
    tampered_payload[0] ^= 0xFF;

    // Rearm must fail constant-time commitment verification
    let rearm_result = engine_sealed.rearm(&receipt, &tampered_payload);
    assert!(rearm_result.is_err());

    let (recovered_engine, error) = rearm_result.unwrap_err();

    // Verify error type and atomic state preservation
    assert_eq!(error, VerificationError::CommitmentMismatch);
    assert_eq!(recovered_engine.epoch(), 100);
    assert_eq!(recovered_engine.terminal_hash(), anchor.terminal_hash());
}

#[test]
fn attack_vector_cross_engine_state_substitution_rejected() {
    let epoch = 100u64;
    let lineage_a = ExecutionLineage::genesis(epoch, b"seed_a");
    let lineage_b = ExecutionLineage::genesis(epoch, b"seed_b");

    let terminal_payload = b"common_snapshot_data";

    let anchor_a = TerminalStateAnchor::seal(&lineage_a, terminal_payload);
    let anchor_b = TerminalStateAnchor::seal(&lineage_b, terminal_payload);

    // Engine B holding H_terminal_B
    let engine_sealed_b = Engine::new(epoch).seal(*anchor_b.terminal_hash());

    // Receipt calculated for Engine A (bound to H_terminal_A)
    let commitment_a = compute_expected_commitment(anchor_a.terminal_hash(), terminal_payload);
    let receipt_a = PersistenceReceipt::new(commitment_a);

    // Replay of Receipt A against Engine B must be rejected
    let rearm_result = engine_sealed_b.rearm(&receipt_a, terminal_payload);
    assert!(rearm_result.is_err());

    let (_, error) = rearm_result.unwrap_err();
    assert_eq!(error, VerificationError::CommitmentMismatch);
}

#[test]
fn attack_vector_cross_epoch_replay_rejected() {
    let epoch_1 = 100u64;
    let epoch_2 = 200u64;
    let seed = b"common_seed";

    let lineage_e1 = ExecutionLineage::genesis(epoch_1, seed);
    let lineage_e2 = ExecutionLineage::genesis(epoch_2, seed);

    let payload = b"snapshot";

    let anchor_e1 = TerminalStateAnchor::seal(&lineage_e1, payload);
    let anchor_e2 = TerminalStateAnchor::seal(&lineage_e2, payload);

    // Ensure distinct epochs guarantee distinct terminal state hashes
    assert_ne!(anchor_e1.terminal_hash(), anchor_e2.terminal_hash());

    let engine_sealed_e2 = Engine::new(epoch_2).seal(*anchor_e2.terminal_hash());

    // Receipt generated for epoch 1 lineage
    let commitment_e1 = compute_expected_commitment(anchor_e1.terminal_hash(), payload);
    let receipt_e1 = PersistenceReceipt::new(commitment_e1);

    // Replay across epochs must fail
    let rearm_result = engine_sealed_e2.rearm(&receipt_e1, payload);
    assert!(rearm_result.is_err());
}
