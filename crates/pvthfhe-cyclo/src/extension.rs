//! Extension sub-protocol (Cyclo §5, T2).

use crate::{ccs_encode::CcsInstance, CycloError};
use sha2::{Digest, Sha256};

/// An extended CCS instance: the result of the T2 linear combination step.
///
/// Represents: `r * a + b` where `r` is a ternary challenge in `{-1, 0, 1}`.
pub struct ExtendedInstance {
    /// Participant id from instance `a` (the left operand).
    pub participant_id: u16,
    /// Combined ajtai_hash: SHA-256(r_bytes ∥ a.ajtai_hash ∥ b.ajtai_hash).
    pub combined_ajtai_hash: [u8; 32],
    /// Combined public_io_hash: SHA-256(r_bytes ∥ a.public_io_hash ∥ b.public_io_hash).
    pub combined_public_io_hash: [u8; 32],
    /// Combined witness bytes: XOR of a.witness_bytes and b.witness_bytes (if equal length),
    /// otherwise concatenate.
    pub combined_witness_bytes: Vec<u8>,
    /// The ternary challenge r ∈ {-1i8, 0i8, 1i8}.
    pub challenge_r: i8,
    /// ‖combined_witness_bytes‖_∞ estimate (max byte value, scaled to [0, Q_COMMIT)).
    pub norm_estimate: u64,
}

/// Applies the T2 extension step: given two CCS instances `a` and `b` and a
/// ternary challenge `r ∈ {-1, 0, 1}`, produces an [`ExtendedInstance`].
///
/// `r` must be in `{-1, 0, 1}`. Returns `Err(InvalidInstance)` otherwise.
pub fn extend(a: &CcsInstance, b: &CcsInstance, r: i8) -> Result<ExtendedInstance, CycloError> {
    if !(-1..=1).contains(&r) {
        return Err(CycloError::InvalidInstance("challenge r must be ternary"));
    }

    let r_bytes = [r.to_le_bytes()[0]];

    let combined_ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(r_bytes)
        .chain_update(a.ajtai_hash)
        .chain_update(b.ajtai_hash)
        .finalize()
        .into();

    let combined_public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(r_bytes)
        .chain_update(a.public_io_hash)
        .chain_update(b.public_io_hash)
        .finalize()
        .into();

    let combined_witness_bytes = if a.witness_bytes.len() == b.witness_bytes.len() {
        a.witness_bytes
            .iter()
            .zip(b.witness_bytes.iter())
            .map(|(&x, &y)| x ^ y)
            .collect()
    } else {
        let mut v = a.witness_bytes.clone();
        v.extend_from_slice(&b.witness_bytes);
        v
    };

    let norm_estimate = combined_witness_bytes
        .iter()
        .map(|&x| u64::from(x))
        .max()
        .unwrap_or(0);

    Ok(ExtendedInstance {
        participant_id: a.participant_id,
        combined_ajtai_hash,
        combined_public_io_hash,
        combined_witness_bytes,
        challenge_r: r,
        norm_estimate,
    })
}

/// Checks that the norm estimate of `ext` does not exceed `bound`.
///
/// Returns `Ok(())` if `ext.norm_estimate ≤ bound`, else `Err(NormBoundExceeded)`.
pub fn check_norm_budget(ext: &ExtendedInstance, bound: u64) -> Result<(), CycloError> {
    if ext.norm_estimate <= bound {
        Ok(())
    } else {
        Err(CycloError::NormBoundExceeded {
            got: ext.norm_estimate,
            max: bound,
        })
    }
}
