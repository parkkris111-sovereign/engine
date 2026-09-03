//! # Persistence Transport Boundary & Canonical Framing
//!
//! Handles serialization, length-prefixed framing, and transport container abstractions
//! for persisted engine artifacts.
//!
//! ## Invariants
//!
//! 1. **Untrusted Transport Boundary:** Persistence storage adapters provide bytes and
//!    receipt evidence only. They possess zero intrinsic authority to force state machine resets.
//! 2. **Canonical Framing Symmetry:** All serialized payloads emitted or ingested across
//!    the transport boundary MUST strictly satisfy `Encode_Canonical(artifact)`:
//!    `u64_le(artifact.len()) || artifact_bytes`.
//! 3. **Non-Trust of Unframed Payload Material:** Unframed or unverified persistence payload
//!    bytes MUST NEVER enter engine state initialization routines.

use crate::protocol::encode_canonical;
use core::fmt;

/// Errors arising during transport-level artifact framing or storage operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceError {
    /// The byte slice is smaller than the 8-byte canonical `u64_le` length prefix.
    InsufficientHeaderBytes,
    /// The payload length declared in the `u64_le` header does not match actual byte slice length.
    LengthPrefixMismatch { expected: usize, found: usize },
    /// Storage adapter failed to perform I/O read or write.
    StorageIoFailure,
}

/// An opaque, transport-framed representation of a persisted terminal artifact.
///
/// Wraps a raw byte payload and provides zero-copy canonical framing methods for hash verification.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PersistedArtifact {
    payload: Vec<u8>,
}

impl PersistedArtifact {
    /// Wraps raw artifact payload bytes into a transport container.
    #[inline]
    pub fn new(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            payload: payload.into(),
        }
    }

    /// Returns a reference to the un-framed underlying payload bytes.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Produces the unique, length-prefixed binary framing `Encode_Canonical(artifact)`.
    ///
    /// Construction: `u64_le(payload.len()) || payload`
    #[inline]
    pub fn encode_canonical(&self) -> Vec<u8> {
        encode_canonical(&self.payload)
    }

    /// Verifies structural canonical framing integrity from raw transport bytes.
    ///
    /// Expects `framed_bytes` to hold `u64_le(payload_len) || payload`.
    pub fn decode_canonical_frame(framed_bytes: &[u8]) -> Result<Self, PersistenceError> {
        if framed_bytes.len() < 8 {
            return Err(PersistenceError::InsufficientHeaderBytes);
        }

        let (len_bytes, payload_bytes) = framed_bytes.split_at(8);
        let declared_len = u64::from_le_bytes(
            len_bytes
                .try_into()
                .map_err(|_| PersistenceError::InsufficientHeaderBytes)?,
        ) as usize;

        if payload_bytes.len() != declared_len {
            return Err(PersistenceError::LengthPrefixMismatch {
                expected: declared_len,
                found: payload_bytes.len(),
            });
        }

        Ok(Self::new(payload_bytes))
    }
}

impl fmt::Debug for PersistedArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedArtifact")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Abstract transport trait for untrusted persistence adapters (e.g., Disk, DB, Object Storage).
///
/// ## Security Contract
///
/// Implementations of this trait operate strictly as untrusted byte carriers.
/// The `PersistenceReceipt` returned alongside an artifact carries evidence for verification
/// but confers zero operational execution authority until recomputed against resident state.
pub trait PersistenceAdapter {
    /// Writes a framed artifact and its authorization receipt to persistent storage.
    fn save_artifact(
        &mut self,
        artifact: &PersistedArtifact,
        receipt: &crate::receipt::PersistenceReceipt,
    ) -> Result<(), PersistenceError>;

    /// Fetches a framed artifact and its candidate authorization receipt from untrusted storage.
    fn load_artifact(
        &self,
    ) -> Result<(PersistedArtifact, crate::receipt::PersistenceReceipt), PersistenceError>;
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    super::*;

    #[test]
    fn canonical_framing_prepends_exact_u64_le_length() {
        let payload = b"canonical_test_payload";
        let artifact = PersistedArtifact::new(payload.to_vec());

        let framed = artifact.encode_canonical();

        // 8 bytes header + 22 bytes payload = 30 bytes total
        assert_eq!(framed.len(), 8 + payload.len());

        let len_header = u64::from_le_bytes(framed[0..8].try_into().unwrap());
        assert_eq!(len_header as usize, payload.len());
        assert_eq!(&framed[8..], payload);
    }

    #[test]
    fn decode_canonical_frame_succeeds_on_valid_framing() {
        let payload = b"canonical_test_payload";
        let artifact = PersistedArtifact::new(payload.to_vec());
        let framed = artifact.encode_canonical();

        let decoded = PersistedArtifact::decode_canonical_frame(&framed).unwrap();
        assert_eq!(decoded.payload(), payload);
    }

    #[test]
    fn decode_canonical_frame_fails_on_corrupted_header_length() {
        let payload = b"canonical_test_payload";
        let artifact = PersistedArtifact::new(payload.to_vec());
        let mut framed = artifact.encode_canonical();

        // Tamper with the u64_le length prefix
        framed[0] ^= 0xFF;

        let result = PersistedArtifact::decode_canonical_frame(&framed);
        assert!(matches!(
            result,
            Err(PersistenceError::LengthPrefixMismatch { .. })
        ));
    }

    #[test]
    fn decode_canonical_frame_fails_on_truncated_header() {
        let truncated = &[0x01, 0x02, 0x03]; // Less than 8 bytes
        let result = PersistedArtifact::decode_canonical_frame(truncated);
        assert_eq!(result, Err(PersistenceError::InsufficientHeaderBytes));
    }
}
