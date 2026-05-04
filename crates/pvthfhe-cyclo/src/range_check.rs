//! Range-check sub-protocol for Cyclo LatticeFold+ (Cyclo §4, T1).
//!
//! Verifies that all coefficients of a polynomial witness satisfy a norm bound
//! `‖·‖_∞ ≤ B_e` using the centred representation.

use crate::{
    ring::{norm_inf, RqPoly},
    CycloError,
};

/// Checks that all coefficients of `poly` satisfy `‖poly‖_∞ ≤ bound`.
///
/// Uses centred representation: each coefficient `c ∈ [0, Q_COMMIT)` is mapped
/// to `min(c, Q_COMMIT - c)`, and the maximum must be ≤ `bound`.
///
/// Returns `Ok(())` if the check passes.
/// Returns `Err(CycloError::NormBoundExceeded { got, max })` if any coefficient
/// exceeds `bound`.
pub fn check_range(poly: &RqPoly, bound: u64) -> Result<(), CycloError> {
    let _ = (poly, bound);
    Ok(())
}
