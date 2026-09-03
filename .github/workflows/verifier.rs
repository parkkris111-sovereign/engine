use crate::lineage::mix_lineage;

use crate::protocol::LineageStage;

use crate::seal::{
    CryptographicSealPayload,
    SealVerificationError,
};

use crate::engine::SovereignSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierError {
    UnsupportedProtocolVersion,

    PayloadFingerprintMismatch,
    UnauthorizedSigningKey,
    InvalidPublicKeyBytes,
    InvalidSignature,

    ExecutionLineageMismatch,
    TerminalLineageMismatch,

    CadenceWindowViolation,
}

impl From<SealVerificationError>
    for VerifierError
{
    fn from(
        value: SealVerificationError,
    ) -> Self {
        match value {
            SealVerificationError::
                UnsupportedProtocolVersion =>
            {
                Self::UnsupportedProtocolVersion
            }

            SealVerificationError::
                PayloadFingerprintMismatch =>
            {
                Self::PayloadFingerprintMismatch
            }

            SealVerificationError::
                UnauthorizedSigningKey =>
            {
                Self::UnauthorizedSigningKey
            }

            SealVerificationError::
                InvalidPublicKeyBytes =>
            {
                Self::InvalidPublicKeyBytes
            }

            SealVerificationError::
                InvalidSignature =>
            {
                Self::InvalidSignature
            }
        }
    }
}

pub struct ExecutionReceiptVerifier;

impl ExecutionReceiptVerifier {
    /// Validates:
    ///
    /// 1. Timestamp cadence policy.
    /// 2. Reconstructed execution lineage.
    /// 3. Key authorization.
    /// 4. Ed25519 signature authenticity.
    pub fn verify_execution(
        spec: &SovereignSpec,
        envelope: &CryptographicSealPayload,
        recomputed_execution_hash: &[u8; 32],
    ) -> Result<(), VerifierError> {
        //
        // Cadence
        //
        if envelope.payload.timestamp
            < spec.cadence_window_start
            || envelope.payload.timestamp
                > spec.cadence_window_end
        {
            return Err(
                VerifierError::CadenceWindowViolation
            );
        }

        //
        // Execution commitment
        //
        if envelope
            .payload
            .cumulative_state_hash
            != *recomputed_execution_hash
        {
            return Err(
                VerifierError::ExecutionLineageMismatch
            );
        }

        //
        // Cryptographic envelope
        //
        envelope
            .verify(
                &spec
                    .authorized_operator_fingerprint,
            )
            .map_err(VerifierError::from)?;

        Ok(())
    }

    /// Reconstructs the terminal sealed hash using the exact
    /// same canonical lineage transitions as the engine.
    #[inline(always)]
    pub fn recompute_terminal_sealed_hash(
        execution_hash: &[u8; 32],
        envelope: &CryptographicSealPayload,
    ) -> [u8; 32] {
        let h_payload =
            mix_lineage(
                execution_hash,
                LineageStage::
                    CryptographicSealPayload,
                &envelope.payload.to_bytes(),
            );

        mix_lineage(
            &h_payload,
            LineageStage::TerminalSealed,
            &envelope.signature,
        )
    }

    /// Complete three-way sealed-engine verification.
    pub fn verify_sealed_engine(
        spec: &SovereignSpec,
        envelope: &CryptographicSealPayload,
        recomputed_execution_hash: &[u8; 32],
        engine_terminal_hash: &[u8; 32],
    ) -> Result<(), VerifierError> {
        //
        // Execution + crypto
        //
        Self::verify_execution(
            spec,
            envelope,
            recomputed_execution_hash,
        )?;

        //
        // Terminal lineage
        //
        let recomputed_terminal =
            Self::recompute_terminal_sealed_hash(
                recomputed_execution_hash,
                envelope,
            );

        if recomputed_terminal
            != *engine_terminal_hash
        {
            return Err(
                VerifierError::
                    TerminalLineageMismatch
            );
        }

        Ok(())
    }
}
