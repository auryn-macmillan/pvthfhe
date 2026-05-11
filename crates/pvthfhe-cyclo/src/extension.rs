//! Extension sub-protocol (Cyclo §5, T2).

use crate::{
    ccs_encode::{self, CcsInstance},
    ring::{bytes_to_rqpoly, ring_add_poly, rqpoly_to_bytes, ternary_mul, Q_COMMIT},
    CycloError,
};
use ark_ff::PrimeField;
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

    let a_poly = bytes_to_rqpoly(&a.ajtai_hash);
    let b_poly = bytes_to_rqpoly(&b.ajtai_hash);
    let combined_poly = ring_add_poly(&a_poly, &ternary_mul(&b_poly, r));
    let combined_ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(b"pvthfhe-cyclo-ext-ajtai-v1")
        .chain_update(&rqpoly_to_bytes(&combined_poly))
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

    let norm_estimate = compute_combined_witness_norm(&a.witness_bytes, &b.witness_bytes, r)?;

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

/// Compute ‖a_wit + r·b_wit‖_∞ from Fr-LE encoded witnesses.
///
/// Parses both witness bytes via [`ccs_encode::parse_witness`], combines them
/// element-wise with the ternary challenge `r ∈ {-1,0,1}`, and returns the
/// maximum centred coefficient (mod `Q_COMMIT`).
fn compute_combined_witness_norm(
    witness_a: &[u8],
    witness_b: &[u8],
    r: i8,
) -> Result<u64, CycloError> {
    let a_frs = ccs_encode::parse_witness(witness_a)?;
    let b_frs = ccs_encode::parse_witness(witness_b)?;
    if a_frs.len() != b_frs.len() {
        return Err(CycloError::InvalidInstance(
            "witness lengths differ during T2 extension",
        ));
    }
    let norm = a_frs
        .iter()
        .zip(b_frs.iter())
        .map(|(x, y)| {
            use ark_ff::AdditiveGroup;
            let combined = match r {
                -1 => *x - *y,
                0 => *x,
                1 => *x + *y,
                _ => unreachable!(),
            };
            let limbs = combined.into_bigint().as_ref().to_vec();
            let c = limbs[0] % Q_COMMIT;
            let neg = Q_COMMIT - c;
            if neg < c { neg } else { c }
        })
        .max()
        .unwrap_or(0);
    Ok(norm)
}
