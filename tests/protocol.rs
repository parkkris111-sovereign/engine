//! # Protocol Specification and Domain Separation Parameters
//!
//! Defines cryptographic primitives, versioning, canonical serialization,
//! domain separators, and digest representations for the Sovereign Engine.

use core::fmt;

/// Protocol version identifier bound into all commitment derivations.
pub const PROTOCOL_VERSION: u16 = 0x0001;

/// Length of fixed-size cryptographic commitment digests in bytes.
pub const COMMITMENT_LEN: usize = 32;

/// Domain separator for persistence receipt commitments.
///
/// Ensures persistence receipts cannot be re-interpreted as lineage transitions,
/// genesis commitments, or execution evidence.
pub const DOMAIN_PERSISTENCE_RECEIPT: &[u8; 27] = b"SOVEREIGN_ENGINE_RECEIPT_V1";

/// Domain separator for cryptographic terminal state derivations.
pub const DOMAIN_TERMINAL: &[u8; 28] = b"SOVEREIGN_ENGINE_TERMINAL_V1";

/// Domain separator for cryptographic genesis and lineage derivations.
pub const DOMAIN_GENESIS: &[u8; 26] = b"SOVEREIGN_ENGINE_GENESIS_V1";

/// A fixed-size 256-bit cryptographic commitment digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Commitment(pub [u8; COMMITMENT_LEN]);

impl Commitment {
    /// Creates a new commitment wrapper from raw bytes.
    #[inline]
    pub const fn new(bytes: [u8; COMMITMENT_LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw underlying byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Commitment(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

/// A 256-bit cryptographic state hash representing an engine state ($H_{\text{terminal}}$).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StateHash(pub [u8; COMMITMENT_LEN]);

impl StateHash {
    /// Creates a new state hash wrapper from raw bytes.
    #[inline]
    pub const fn new(bytes: [u8; COMMITMENT_LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw underlying byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }
}

impl fmt::Debug for StateHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StateHash(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

/// Canonical length-prefixed framing helper for arbitrary byte slices.
///
/// Implements `Encode_Canonical(artifact)`: `u64_le(artifact.len()) || artifact_bytes`.
///
/// # Security
///
/// No alternate serialization, implicit string conversion, pointer-derived
/// representation, or variable-width integer encoding is permitted.
pub fn encode_canonical(bytes: &[u8]) -> Vec<u8> {
    let len_prefix = (bytes.len() as u64).to_le_bytes();
    let mut canonical = Vec::with_capacity(8 + bytes.len());
    canonical.extend_from_slice(&len_prefix);
    canonical.extend_from_slice(bytes);
    canonical
}
