//! Sequential T=10 fold driver for PVTHFHE Cyclo LatticeFold+.
//!
//! Folds exactly T=10 [`CcsPShareInstance`] objects sequentially using the
//! T3 fold sub-protocol from [`crate::fold`], enforces the final norm budget
//! β_T ≤ 1344, and exposes [`fold_all`] as the top-level entry point.

use crate::{CcsPShareInstance, CycloAccumulator, CycloError};
use rand_core::RngCore;

/// Folds all `instances` sequentially, returning the final accumulator.
///
/// Initialises from `instances[0]`, then applies `fold_one_step` for every
/// instance (including `instances[0]`), so `fold_depth == instances.len()`.
///
/// # Errors
///
/// Returns [`CycloError::InvalidInstance`] if `instances` is empty,
/// [`CycloError::FoldDepthExhausted`] if `instances.len() > T`, or
/// [`CycloError::NormBoundExceeded`] if the final norm exceeds β_T.
pub fn fold_all(
    instances: &[CcsPShareInstance],
    _session_id: &str,
    _rng: &mut dyn RngCore,
) -> Result<CycloAccumulator, CycloError> {
    let _ = instances;
    Err(CycloError::InvalidInstance("driver not yet implemented"))
}
