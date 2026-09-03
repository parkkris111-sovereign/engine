//! # Rearm Verification and Constant-Time Equality Engine
//!
//! Recomputes authorization commitments against state-resident lineage and executes
//! constant-time equality checks over digest values.
//!
//! ## Invariants
//!
//! 1. **Zero External Trust:** $H_{\text{terminal}}$ is sourced strictly from resident engine state.
//! 2. **Constant-Time Predicate:** Verification MUST NOT early-exit or leak position-dependent timing.
//! 3. **Separation of Evidence and Initialization:** Verification checks permit the transition;
//!    artifact bytes NEVER enter engine state derivation.

use crate::protocol::{
    encode_canonical, Commitment, StateHash, DOMAIN_PERSISTENCE_RECEIPT, PROTOCOL_VERSION,
};
use crate::receipt::PersistenceReceipt;
use sha2::Digest; // Standard cryptographic hash library (e.g., SHA-256 or SHA3-256)
use subtle::ConstantTimeEq;

/// Represents discrete verification failure conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    /// Receipt protocol version does not match resident engine protocol version.
    ProtocolVersionMismatch { expected: u16, found: u16 },
    /// Constant-time commitment evaluation failed (`C_receipt != C_expected`).
    CommitmentMismatch,
}

/// Recomputes $C_{\text{expected}}$ from resident terminal state and the presented artifact.
///
/// Mathematical rule:
/// ```text
/// C_expected = H(
///     u16_be(VERSION)
///     || DOMAIN_PERSISTENCE_RECEIPT
///     || H_terminal
///     || Encode_Canonical(artifact)
/// )
/// ```
#[inline]
pub fn compute_expected_commitment(
    resident_terminal_hash: &StateHash,
    artifact_bytes: &[u8],
) -> Commitment {
    let mut hasher = sha2::Sha256::new();

    // 1. Version binding
    hasher.update(&PROTOCOL_VERSION.to_be_bytes());

    // 2. Domain separator
    hasher.update(DOMAIN_PERSISTENCE_RECEIPT);

    // 3. Resident terminal state hash (H_terminal)
    hasher.update(resident_terminal_hash.as_bytes());

    // 4. Length-prefixed canonical artifact serialization
    let canonical_artifact = encode_canonical(artifact_bytes);
    hasher.update(&canonical_artifact);

    let digest = hasher.finalize();
    let mut commitment_bytes = [0u8; 32];
    commitment_bytes.copy_from_slice(&digest);

    Commitment::new(commitment_bytes)
}

/// Evaluates state-resident rearm authority in constant time.
///
/// Returns `Ok(())` if and only if the presented evidence matches independently
/// recomputed resident authorization commitments.
///
/// # Security
///
/// Uses [`subtle::ConstantTimeEq`] to guarantee that comparison runtime remains
/// strictly invariant regardless of how many initial bytes match between `C_receipt`
/// and `C_expected`.
pub fn verify_rearm_authority(
    resident_terminal_hash: &StateHash,
    receipt: &PersistenceReceipt,
    artifact_bytes: &[u8],
) -> Result<(), VerificationError> {
    // Phase 1: Structural version check
    if receipt.version() != PROTOCOL_VERSION {
        return Err(VerificationError::ProtocolVersionMismatch {
            expected: PROTOCOL_VERSION,
            found: receipt.version(),
        });
    }

    // Phase 2: Independent state-resident recomputation
    let c_expected = compute_expected_commitment(resident_terminal_hash, artifact_bytes);

    // Phase 3: Constant-time authorization predicate evaluation
    let c_receipt_bytes = receipt.commitment().as_bytes();
    let c_expected_bytes = c_expected.as_bytes();

    // ConstantTimeEq evaluates all 32 bytes without early exit
    let is_equal = c_receipt_bytes.ct_eq(c_expected_bytes);

    if is_equal.into() {
        Ok(())
    } else {
        Err(VerificationError::CommitmentMismatch)
    }
}

#[cfg(test)]
mod tests {
    super::*;

    #[test]
    fn valid_receipt_verifies_successfully() {
        let terminal_hash = StateHash::new([0xAA; 32]);
        let artifact = b"valid_persisted_state_payload";

        let expected_commitment = compute_expected_commitment(&terminal_hash, artifact);
        let receipt = PersistenceReceipt::new(expected_commitment);

        assert!(verify_rearm_authority(&terminal_hash, &receipt, artifact).is_ok());
    }

    #[test]
    fn single_bit_artifact_mutation_fails_verification() {
        let terminal_hash = StateHash::new([0xAA; 32]);
        let mut artifact = b"valid_persisted_state_payload".to_vec();

        let expected_commitment = compute_expected_commitment(&terminal_hash, &artifact);
        let receipt = PersistenceReceipt::new(expected_commitment);

        // Mutate single bit in artifact payload
        artifact[0] ^= 0x01;

        assert_eq!(
            verify_rearm_authority(&terminal_hash, &receipt, &artifact),
            Err(VerificationError::CommitmentMismatch)
        );
    }

    #[test]
    fn terminal_state_substitution_fails_verification() {
        let terminal_hash_a = StateHash::new([0xAA; 32]);
        let terminal_hash_b = StateHash::new([0xBB; 32]);
        let artifact = b"valid_persisted_state_payload";

        // Generate receipt bound to state A
        let expected_commitment_a = compute_expected_commitment(&terminal_hash_a, artifact);
        let receipt = PersistenceReceipt::new(expected_commitment_a);

        // Attempt verification against state B
        assert_eq!(
            verify_rearm_authority(&terminal_hash_b, &receipt, artifact),
            Err(VerificationError::CommitmentMismatch)
        );
    }
}
