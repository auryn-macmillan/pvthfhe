//! Extension sub-protocol (Cyclo §5, T2).

use crate::{ccs_encode::CcsInstance, CycloError};

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

/// Applies the T2 extension step.
///
/// `r` must be in `{-1, 0, 1}`. Returns `Err(InvalidInstance)` otherwise.
pub fn extend(_a: &CcsInstance, _b: &CcsInstance, _r: i8) -> Result<ExtendedInstance, CycloError> {
    unimplemented!("F5 extension stub — not yet implemented")
}

/// Checks that the norm estimate of `ext` does not exceed `bound`.
///
/// Returns `Ok(())` if `ext.norm_estimate ≤ bound`, else `Err(NormBoundExceeded)`.
pub fn check_norm_budget(_ext: &ExtendedInstance, _bound: u64) -> Result<(), CycloError> {
    unimplemented!("F5 check_norm_budget stub — not yet implemented")
}
