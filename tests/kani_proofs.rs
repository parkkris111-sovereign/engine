//! # Sovereign Engine Kani Verification Harness
//!
//! Run with: `cargo kani --harness check_rearm_atomicity_and_determinism`

#[cfg(kani)]
mod kani_proofs {
    use sovereign_engine::engine::Engine;
    use sovereign_engine::lineage::ExecutionLineage;
    use sovereign_engine::persistence::PersistenceReceipt;
    use sovereign_engine::protocol::{Commitment, StateHash};
    use sovereign_engine::seal::TerminalStateAnchor;
    use sovereign_engine::verifier::{compute_expected_commitment, verify_rearm_authority};

    /// Proves that `rearm` is strictly deterministic and atomic:
    /// 1. A valid receipt ALWAYS transitions Epoch E -> E + 1.
    /// 2. An invalid receipt NEVER mutates resident state or epoch counter.
    /// 3. Symbolic execution triggers ZERO memory safety violations or panics.
    #[kani::proof]
    #[kani::unwind(5)]
    fn check_rearm_atomicity_and_determinism() {
        // 1. Generate symbolic initial epoch and arbitrary bytes
        let epoch: u64 = kani::any();
        let seed: [u8; 8] = kani::any();
        let payload: [u8; 16] = kani::any();

        // 2. Initialize Lineage & Engine
        let lineage = ExecutionLineage::genesis(epoch, &seed);
        let anchor = TerminalStateAnchor::seal(&lineage, &payload);

        let initial_terminal_hash = *anchor.terminal_hash();
        let engine_sealed = Engine::new(epoch).seal(initial_terminal_hash);

        // 3. Generate symbolic commitment for receipt (could be valid or forged)
        let receipt_bytes: [u8; 32] = kani::any();
        let receipt = PersistenceReceipt::new(Commitment::from_bytes(receipt_bytes));

        // 4. Calculate expected commitment
        let expected_commitment = compute_expected_commitment(&initial_terminal_hash, &payload);

        // 5. Execute Rearm
        let rearm_result = engine_sealed.rearm(&receipt, &payload);

        if receipt_bytes == *expected_commitment.as_bytes() {
            // PROOF INVARIANT 1: Valid receipt MUST succeed and increment epoch strictly by 1
            let rearmed_engine = rearm_result.unwrap();
            assert_eq!(rearmed_engine.epoch(), epoch + 1);
        } else {
            // PROOF INVARIANT 2: Invalid receipt MUST fail and preserve original state intact
            assert!(rearm_result.is_err());
            let (recovered_engine, _err) = rearm_result.unwrap_err();

            assert_eq!(recovered_engine.epoch(), epoch);
            assert_eq!(*recovered_engine.terminal_hash(), initial_terminal_hash);
        }
    }

    /// Proves that framing parser handles bounded dynamic lengths without panicking.
    #[kani::proof]
    #[kani::unwind(32)]
    fn check_canonical_framing_no_panic() {
        let frame_bytes: [u8; 24] = kani::any();
        let _ = sovereign_engine::persistence::PersistedArtifact::decode_canonical_frame(&frame_bytes);
    }
}
