//! Folding sub-protocol (Cyclo §6, T3).
//!
//! Provides `init_accumulator`, `fold_one_step`, and `verify_fold` for the
//! Cyclo LatticeFold+ sequential folding of [`CcsPShareInstance`] values into a
//! [`CycloAccumulator`].

use crate::{CcsPShareInstance, CycloAccumulator, CycloError};
use rand_core::RngCore;

/// Initialises a fresh [`CycloAccumulator`] from the first [`CcsPShareInstance`].
///
/// Sets `fold_depth = 0`, computes initial commitment as
/// `SHA256("init" ∥ instance.ajtai_commitment_bytes)`, initial public_io as
/// `SHA256("init" ∥ instance.public_io_bytes)`, and norm bound =
/// `PVTHFHE_CYCLO_PARAMS.norm_bound_b`.
pub fn init_accumulator(
    _instance: &CcsPShareInstance,
    _session_id: &str,
) -> Result<CycloAccumulator, CycloError> {
    Err(CycloError::InvalidInstance("fold: not yet implemented"))
}

/// Folds `instance` into `acc`, producing a new accumulator.
pub fn fold_one_step(
    _acc: CycloAccumulator,
    _instance: &CcsPShareInstance,
    _rng: &mut dyn RngCore,
) -> Result<CycloAccumulator, CycloError> {
    Err(CycloError::InvalidInstance("fold: not yet implemented"))
}

/// Verifies that `acc` represents a valid fold over `instances`.
///
/// Checks:
/// 1. `acc.fold_depth == instances.len() as u32`.
/// 2. `acc.norm_bound_current ≤ PVTHFHE_CYCLO_PARAMS.beta_at_t` (1344).
/// 3. `acc.acc_commitment_bytes.len() == 32`.
/// 4. `acc.acc_public_io_bytes.len() == 32`.
///
/// Returns `Ok(())` if all checks pass, `Err(AccumulatorVerificationFailed(...))` otherwise.
pub fn verify_fold(
    _acc: &CycloAccumulator,
    _instances: &[CcsPShareInstance],
) -> Result<(), CycloError> {
    Err(CycloError::InvalidInstance("fold: not yet implemented"))
}
