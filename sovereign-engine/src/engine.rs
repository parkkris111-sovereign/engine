use ed25519_dalek::Signer;
use zeroize::Zeroize;

use crate::lineage::{
    derive_genesis_hash,
    mix_lineage,
};

use crate::persistence::{
    compute_persistence_commitment,
    PersistenceReceipt,
};

use crate::protocol::{
    FailureReason,
    FailureStage,
    LineageStage,
};

use crate::receipt::CrashReceipt;

use crate::seal::{
    CryptographicSealPayload,
    SealPayload,
    SigningIdentity,
};

//
// ------------------------------------------------------------
// Specification
// ------------------------------------------------------------
//

#[derive(Debug, Clone)]
pub struct SovereignSpec {
    pub objective: Vec<u8>,
    pub scope: Vec<u8>,

    pub authorized_operator_fingerprint: [u8; 32],

    pub cadence_window_start: u64,
    pub cadence_window_end: u64,
}

//
// ------------------------------------------------------------
// Typestates
// ------------------------------------------------------------
//

pub struct Idle;

pub struct PreExecutionGuard;

pub struct PureStateEvaluator;

pub struct AtomicExecution;

pub struct CryptographicSeal;

pub struct Sealed {
    pub envelope: CryptographicSealPayload,
}

pub struct SafeState {
    pub receipt: CrashReceipt,
}

pub struct Denied {
    pub receipt: CrashReceipt,
}

//
// ------------------------------------------------------------
// Engine
// ------------------------------------------------------------
//

pub struct SovereignEngine<S> {
    pub(crate) state: S,
    pub(crate) state_hash: [u8; 32],
}

impl SovereignEngine<Idle> {
    #[inline(always)]
    pub fn new(
        genesis_seed: &[u8; 32],
        epoch_context: u64,
    ) -> Self {
        Self {
            state: Idle,
            state_hash: derive_genesis_hash(
                genesis_seed,
                epoch_context,
            ),
        }
    }

    #[inline(always)]
    pub fn to_pre_guard(
        self,
    ) -> SovereignEngine<PreExecutionGuard> {
        SovereignEngine {
            state: PreExecutionGuard,
            state_hash: self.state_hash,
        }
    }
}

//
// ------------------------------------------------------------
// Shared lineage mutation
// ------------------------------------------------------------
//

impl<S> SovereignEngine<S> {
    #[inline(always)]
    pub(crate) fn mix_lineage(
        &mut self,
        stage: LineageStage,
        payload: &[u8],
    ) {
        self.state_hash = mix_lineage(
            &self.state_hash,
            stage,
            payload,
        );
    }

    #[inline(always)]
    pub fn state_hash(&self) -> &[u8; 32] {
        &self.state_hash
    }
}

//
// ------------------------------------------------------------
// PreExecutionGuard
// ------------------------------------------------------------
//

impl SovereignEngine<PreExecutionGuard> {
    #[inline(always)]
    pub fn verify_guard(
        mut self,
        spec: &SovereignSpec,
        ts: u64,
    ) -> Result<
        SovereignEngine<PureStateEvaluator>,
        SovereignEngine<Denied>,
    > {
        self.mix_lineage(
            LineageStage::PreExecutionGuard,
            &spec.objective,
        );

        self.mix_lineage(
            LineageStage::GuardTimestamp,
            &ts.to_le_bytes(),
        );

        match verify_guard(spec, ts) {
            Ok(()) => Ok(SovereignEngine {
                state: PureStateEvaluator,
                state_hash: self.state_hash,
            }),

            Err(reason) => {
                let receipt =
                    CrashReceipt::generate(
                        reason,
                        FailureStage::PreExecutionGuard,
                        ts,
                        &self.state_hash,
                    );

                self.mix_lineage(
                    LineageStage::TerminalDenied,
                    &receipt.hash,
                );

                Err(SovereignEngine {
                    state: Denied { receipt },
                    state_hash: self.state_hash,
                })
            }
        }
    }
}

//
// ------------------------------------------------------------
// PureStateEvaluator
// ------------------------------------------------------------
//

impl SovereignEngine<PureStateEvaluator> {
    #[inline(always)]
    pub fn evaluate_state(
        mut self,
        spec: &SovereignSpec,
        ts: u64,
    ) -> Result<
        SovereignEngine<AtomicExecution>,
        SovereignEngine<SafeState>,
    > {
        self.mix_lineage(
            LineageStage::PureStateEvaluator,
            &spec.scope,
        );

        match evaluate_pure_state(spec) {
            Ok(()) => Ok(SovereignEngine {
                state: AtomicExecution,
                state_hash: self.state_hash,
            }),

            Err(reason) => {
                let receipt =
                    CrashReceipt::generate(
                        reason,
                        FailureStage::PureStateEvaluator,
                        ts,
                        &self.state_hash,
                    );

                self.mix_lineage(
                    LineageStage::TerminalSafeState,
                    &receipt.hash,
                );

                Err(SovereignEngine {
                    state: SafeState { receipt },
                    state_hash: self.state_hash,
                })
            }
        }
    }
}

//
// ------------------------------------------------------------
// AtomicExecution
// ------------------------------------------------------------
//

impl SovereignEngine<AtomicExecution> {
    #[inline(always)]
    pub fn run_atomic(
        mut self,
        spec: &SovereignSpec,
        ts: u64,
    ) -> Result<
        SovereignEngine<CryptographicSeal>,
        SovereignEngine<SafeState>,
    > {
        match run_atomic_payload(spec) {
            Ok(output) => {
                self.mix_lineage(
                    LineageStage::AtomicExecutionOutput,
                    &output,
                );

                Ok(SovereignEngine {
                    state: CryptographicSeal,
                    state_hash: self.state_hash,
                })
            }

            Err(reason) => {
                let receipt =
                    CrashReceipt::generate(
                        reason,
                        FailureStage::AtomicExecution,
                        ts,
                        &self.state_hash,
                    );

                self.mix_lineage(
                    LineageStage::TerminalSafeState,
                    &receipt.hash,
                );

                Err(SovereignEngine {
                    state: SafeState { receipt },
                    state_hash: self.state_hash,
                })
            }
        }
    }
}

//
// ------------------------------------------------------------
// CryptographicSeal
// ------------------------------------------------------------
//

impl SovereignEngine<CryptographicSeal> {
    #[inline(always)]
    pub fn seal(
        mut self,
        spec: &SovereignSpec,
        ts: u64,
        identity: &SigningIdentity,
    ) -> Result<
        SovereignEngine<Sealed>,
        SovereignEngine<SafeState>,
    > {
        let verifying_key =
            identity.signing_key.verifying_key();

        let public_key =
            verifying_key.to_bytes();

        let fingerprint =
            CryptographicSealPayload::
                compute_key_fingerprint(
                    &public_key,
                );

        //
        // Operator authorization
        //
        if fingerprint
            != spec.authorized_operator_fingerprint
        {
            let receipt =
                CrashReceipt::generate(
                    FailureReason::UnauthorizedSigningKey,
                    FailureStage::CryptographicSeal,
                    ts,
                    &self.state_hash,
                );

            self.mix_lineage(
                LineageStage::TerminalSafeState,
                &receipt.hash,
            );

            return Err(SovereignEngine {
                state: SafeState { receipt },
                state_hash: self.state_hash,
            });
        }

        //
        // Canonical execution commitment
        //
        let payload =
            SealPayload::new(
                self.state_hash,
                ts,
                fingerprint,
            );

        //
        // Sign domain-separated digest
        //
        let signature =
            identity
                .signing_key
                .sign(&payload.digest())
                .to_bytes();

        let envelope =
            CryptographicSealPayload {
                payload,
                public_key,
                signature,
            };

        //
        // Commit payload then signature into terminal lineage
        //
        self.mix_lineage(
            LineageStage::CryptographicSealPayload,
            &envelope.payload.to_bytes(),
        );

        self.mix_lineage(
            LineageStage::TerminalSealed,
            &envelope.signature,
        );

        Ok(SovereignEngine {
            state: Sealed { envelope },
            state_hash: self.state_hash,
        })
    }
}

//
// ------------------------------------------------------------
// Pipeline
// ------------------------------------------------------------
//

pub enum ExecutionOutcome {
    Sealed(SovereignEngine<Sealed>),
    SafeState(SovereignEngine<SafeState>),
    Denied(SovereignEngine<Denied>),
}

impl SovereignEngine<Idle> {
    pub fn execute_pipeline(
        self,
        spec: &SovereignSpec,
        ts: u64,
        identity: &SigningIdentity,
    ) -> ExecutionOutcome {
        let sealed =
            match self
                .to_pre_guard()
                .verify_guard(spec, ts)
            {
                Ok(engine) => engine,

                Err(engine) => {
                    return ExecutionOutcome::Denied(
                        engine
                    );
                }
            };

        let atomic =
            match sealed
                .evaluate_state(spec, ts)
            {
                Ok(engine) => engine,

                Err(engine) => {
                    return ExecutionOutcome::SafeState(
                        engine
                    );
                }
            };

        let seal =
            match atomic.run_atomic(spec, ts) {
                Ok(engine) => engine,

                Err(engine) => {
                    return ExecutionOutcome::SafeState(
                        engine
                    );
                }
            };

        match seal.seal(spec, ts, identity) {
            Ok(engine) => {
                ExecutionOutcome::Sealed(engine)
            }

            Err(engine) => {
                ExecutionOutcome::SafeState(engine)
            }
        }
    }
}

//
// ------------------------------------------------------------
// Rearm
// ------------------------------------------------------------
//

impl SovereignEngine<Sealed> {
    pub fn rearm(
        mut self,
        proof: &PersistenceReceipt,
        artifact_bytes: &[u8],
        new_genesis_seed: &[u8; 32],
        epoch_context: u64,
    ) -> Result<
        SovereignEngine<Idle>,
        SovereignEngine<Sealed>,
    > {
        let expected =
            compute_persistence_commitment(
                &self.state_hash,
                artifact_bytes,
            );

        if proof.commitment_hash() != &expected {
            return Err(self);
        }

        self.state.envelope.zeroize();

        self.state_hash.zeroize();

        Ok(SovereignEngine {
            state: Idle,
            state_hash: derive_genesis_hash(
                new_genesis_seed,
                epoch_context,
            ),
        })
    }
}

impl SovereignEngine<SafeState> {
    pub fn rearm(
        mut self,
        proof: &PersistenceReceipt,
        artifact_bytes: &[u8],
        new_genesis_seed: &[u8; 32],
        epoch_context: u64,
    ) -> Result<
        SovereignEngine<Idle>,
        SovereignEngine<SafeState>,
    > {
        let expected =
            compute_persistence_commitment(
                &self.state_hash,
                artifact_bytes,
            );

        if proof.commitment_hash() != &expected {
            return Err(self);
        }

        self.state.receipt.zeroize();

        self.state_hash.zeroize();

        Ok(SovereignEngine {
            state: Idle,
            state_hash: derive_genesis_hash(
                new_genesis_seed,
                epoch_context,
            ),
        })
    }
}

impl SovereignEngine<Denied> {
    pub fn rearm(
        mut self,
        proof: &PersistenceReceipt,
        artifact_bytes: &[u8],
        new_genesis_seed: &[u8; 32],
        epoch_context: u64,
    ) -> Result<
        SovereignEngine<Idle>,
        SovereignEngine<Denied>,
    > {
        let expected =
            compute_persistence_commitment(
                &self.state_hash,
                artifact_bytes,
            );

        if proof.commitment_hash() != &expected {
            return Err(self);
        }

        self.state.receipt.zeroize();

        self.state_hash.zeroize();

        Ok(SovereignEngine {
            state: Idle,
            state_hash: derive_genesis_hash(
                new_genesis_seed,
                epoch_context,
            ),
        })
    }
}

//
// ------------------------------------------------------------
// Domain-specific execution functions
// ------------------------------------------------------------
//

fn verify_guard(
    spec: &SovereignSpec,
    ts: u64,
) -> Result<(), FailureReason> {
    if spec.objective.is_empty() {
        return Err(
            FailureReason::IncompleteSpec
        );
    }

    if ts < spec.cadence_window_start
        || ts > spec.cadence_window_end
    {
        return Err(
            FailureReason::CadenceViolation
        );
    }

    Ok(())
}

fn evaluate_pure_state(
    spec: &SovereignSpec,
) -> Result<(), FailureReason> {
    if spec.scope.is_empty() {
        return Err(
            FailureReason::UnsatisfiedDependency
        );
    }

    Ok(())
}

fn run_atomic_payload(
    spec: &SovereignSpec,
) -> Result<Vec<u8>, FailureReason> {
    /*
     * Replace with actual deterministic atomic payload.
     *
     * This placeholder intentionally derives a deterministic
     * execution artifact from governed input.
     */

    if spec.objective.is_empty() {
        return Err(
            FailureReason::AtomicExecutionFailure
        );
    }

    Ok(spec.objective.clone())
}
