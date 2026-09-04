use sha2::{Digest, Sha256};

use crate::protocol::{
    Domain,
    LineageStage,
    VERSION,
};

pub const PROTOCOL_VERSION: u32 = VERSION;

/// Canonically mixes one execution transition.
///
/// SHA256(
///     VERSION_LE
///     || DOMAIN_LINEAGE
///     || PRIOR_HASH
///     || STAGE_LE
///     || PAYLOAD_LENGTH_LE
///     || PAYLOAD
/// )
#[inline(always)]
pub fn mix_lineage(
    prior_hash: &[u8; 32],
    stage: LineageStage,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(&VERSION.to_le_bytes());
    hasher.update(&[Domain::Lineage as u8]);

    hasher.update(prior_hash);

    hasher.update(&(stage as u16).to_le_bytes());

    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);

    hasher.finalize().into()
}

/// Derives an epoch-isolated genesis commitment.
///
/// SHA256(
///     VERSION_LE
///     || DOMAIN_GENESIS
///     || EPOCH_CONTEXT_LE
///     || GENESIS_SEED
/// )
#[inline(always)]
pub fn derive_genesis_hash(
    seed: &[u8; 32],
    epoch_context: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(&VERSION.to_le_bytes());
    hasher.update(&[Domain::Genesis as u8]);

    hasher.update(&epoch_context.to_le_bytes());

    hasher.update(seed);

    hasher.finalize().into()
}
