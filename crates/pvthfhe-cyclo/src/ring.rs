//! R_{q_commit} arithmetic: NTT, pointwise multiplication, and norms.
//!
//! Stub implementation — functions are not yet implemented.

use crate::CycloError;

/// Cyclotomic ring degree φ = 256; elements live in `Z[X]/(X^256+1)`.
pub const PHI_COMMIT: usize = 256;

/// Commitment modulus `q_commit` (50-bit prime ≡ 1 mod 1024).
pub const Q_COMMIT: u64 = 562_949_953_438_721;

/// An element of `R_{q_commit} = Z_{q_commit}[X]/(X^256+1)`.
///
/// Coefficients are stored in the standard (non-centred) representation
/// `[0, Q_COMMIT)`.  There are always exactly [`PHI_COMMIT`] coefficients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RqPoly(pub Vec<u64>);

impl RqPoly {
    /// Returns the zero polynomial in `R_{q_commit}`.
    pub fn zero() -> Self {
        Self(vec![0u64; PHI_COMMIT])
    }
}

/// Applies the forward NTT to `poly` — stub, not yet implemented.
pub fn ntt_forward(_poly: &RqPoly) -> Result<RqPoly, CycloError> {
    Err(CycloError::InvalidInstance("ntt_forward: not implemented"))
}

/// Applies the inverse NTT to `poly` — stub, not yet implemented.
pub fn ntt_inverse(_poly: &RqPoly) -> Result<RqPoly, CycloError> {
    Err(CycloError::InvalidInstance("ntt_inverse: not implemented"))
}

/// Multiplies two polynomials in `R_{q_commit}` — stub, not yet implemented.
pub fn ntt_mul(_a: &RqPoly, _b: &RqPoly) -> Result<RqPoly, CycloError> {
    Err(CycloError::InvalidInstance("ntt_mul: not implemented"))
}

/// Returns `‖poly‖_∞` — stub, returns 0.
pub fn norm_inf(_poly: &RqPoly) -> u64 {
    0
}

/// Returns `‖poly‖_2²` — stub, returns 0.
pub fn norm_sq(_poly: &RqPoly) -> u128 {
    0
}
