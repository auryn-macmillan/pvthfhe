//! Sequential T=10 fold driver for PVTHFHE Cyclo LatticeFold+.
//!
//! Folds exactly T=10 [`CcsPShareInstance`] objects sequentially using the
//! T3 fold sub-protocol from [`crate::fold`], enforces the final norm budget
//! β_T ≤ 1344, and exposes [`fold_all`] as the top-level entry point.

use crate::{
    fold::{fold_one_step, init_accumulator},
    CcsPShareInstance, CycloAccumulator, CycloError, PVTHFHE_CYCLO_PARAMS,
};
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
    session_id: &str,
    rng: &mut dyn RngCore,
) -> Result<CycloAccumulator, CycloError> {
    if instances.is_empty() {
        return Err(CycloError::InvalidInstance(
            "at least one instance required",
        ));
    }
    let t = usize::try_from(PVTHFHE_CYCLO_PARAMS.sequential_t)
        .map_err(|_| CycloError::InvalidInstance("sequential_t overflows usize"))?;
    if instances.len() > t {
        return Err(CycloError::FoldDepthExhausted(
            PVTHFHE_CYCLO_PARAMS.sequential_t,
        ));
    }

    let mut acc = init_accumulator(&instances[0], session_id)?;
    for instance in instances {
        acc = fold_one_step(acc, instance, rng)?;
    }

    if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(CycloError::NormBoundExceeded {
            got: acc.norm_bound_current,
            max: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        });
    }

    Ok(acc)
}
