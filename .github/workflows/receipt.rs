use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::protocol::{
    Domain,
    FailureReason,
    FailureStage,
    VERSION,
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashReceipt {
    pub reason: FailureReason,
    pub stage: FailureStage,
    pub timestamp: u64,
    pub hash: [u8; 32],
}

impl CrashReceipt {
    #[inline(always)]
    pub fn generate(
        reason: FailureReason,
        stage: FailureStage,
        timestamp: u64,
        prior_lineage_hash: &[u8; 32],
    ) -> Self {
        let mut hasher = Sha256::new();

        hasher.update(&VERSION.to_le_bytes());
        hasher.update(&[Domain::CrashReceipt as u8]);

        hasher.update(&[reason as u8]);
        hasher.update(&[stage as u8]);

        hasher.update(&timestamp.to_le_bytes());

        hasher.update(prior_lineage_hash);

        Self {
            reason,
            stage,
            timestamp,
            hash: hasher.finalize().into(),
        }
    }

    #[inline(always)]
    pub fn zeroize(&mut self) {
        self.reason = FailureReason::CadenceViolation;
        self.stage = FailureStage::PreExecutionGuard;
        self.timestamp = 0;
        self.hash.zeroize();
    }
}
