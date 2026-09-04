use ed25519_dalek::{
    Signature,
    Signer,
    SigningKey,
    Verifier,
    VerifyingKey,
};

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::protocol::{
    Domain,
    VERSION,
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealPayload {
    pub protocol_version: u32,
    pub cumulative_state_hash: [u8; 32],
    pub timestamp: u64,
    pub public_key_fingerprint: [u8; 32],
}

impl SealPayload {
    #[inline(always)]
    pub fn new(
        cumulative_state_hash: [u8; 32],
        timestamp: u64,
        public_key_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            protocol_version: VERSION,
            cumulative_state_hash,
            timestamp,
            public_key_fingerprint,
        }
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 76] {
        let mut buf = [0u8; 76];

        buf[0..4]
            .copy_from_slice(&self.protocol_version.to_le_bytes());

        buf[4..36]
            .copy_from_slice(&self.cumulative_state_hash);

        buf[36..44]
            .copy_from_slice(&self.timestamp.to_le_bytes());

        buf[44..76]
            .copy_from_slice(&self.public_key_fingerprint);

        buf
    }

    /// Domain-separated signing digest.
    #[inline(always)]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(&VERSION.to_le_bytes());
        hasher.update(&[Domain::SealPayload as u8]);

        hasher.update(&self.to_bytes());

        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptographicSealPayload {
    pub payload: SealPayload,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl CryptographicSealPayload {
    #[inline(always)]
    pub fn compute_key_fingerprint(
        pubkey_bytes: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(&VERSION.to_le_bytes());
        hasher.update(&[Domain::SealPayload as u8]);
        hasher.update(pubkey_bytes);

        hasher.finalize().into()
    }

    #[inline(always)]
    pub fn verify(
        &self,
        expected_fingerprint: &[u8; 32],
    ) -> Result<(), SealVerificationError> {
        if self.payload.protocol_version != VERSION {
            return Err(
                SealVerificationError::UnsupportedProtocolVersion
            );
        }

        let computed_fp =
            Self::compute_key_fingerprint(&self.public_key);

        if computed_fp
            != self.payload.public_key_fingerprint
        {
            return Err(
                SealVerificationError::PayloadFingerprintMismatch
            );
        }

        if computed_fp != *expected_fingerprint {
            return Err(
                SealVerificationError::UnauthorizedSigningKey
            );
        }

        let verifying_key =
            VerifyingKey::from_bytes(&self.public_key)
                .map_err(|_| {
                    SealVerificationError::InvalidPublicKeyBytes
                })?;

        let signature =
            Signature::from_bytes(&self.signature);

        verifying_key
            .verify(
                &self.payload.digest(),
                &signature,
            )
            .map_err(|_| {
                SealVerificationError::InvalidSignature
            })?;

        Ok(())
    }

    #[inline(always)]
    pub fn zeroize(&mut self) {
        self.payload.protocol_version = 0;

        self.payload
            .cumulative_state_hash
            .zeroize();

        self.payload.timestamp = 0;

        self.payload
            .public_key_fingerprint
            .zeroize();

        self.public_key.zeroize();
        self.signature.zeroize();
    }
}

impl Drop for CryptographicSealPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct SigningIdentity<'a> {
    pub signing_key: &'a SigningKey,
    pub key_id: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealVerificationError {
    UnsupportedProtocolVersion,
    PayloadFingerprintMismatch,
    UnauthorizedSigningKey,
    InvalidPublicKeyBytes,
    InvalidSignature,
}
