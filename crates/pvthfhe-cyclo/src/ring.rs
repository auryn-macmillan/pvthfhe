//! R_{q_commit} arithmetic: NTT, pointwise multiplication, and norms.
//!
//! This module provides efficient polynomial arithmetic over the commitment ring
//! `R_{q_commit} = Z_{q_commit}[X]/(X^256+1)` using the Number Theoretic Transform.

use crate::CycloError;
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use std::sync::{Arc, OnceLock};

/// Cyclotomic ring degree φ = 256; elements live in `Z[X]/(X^256+1)`.
pub const PHI_COMMIT: usize = 256;

/// Commitment modulus `q_commit` (50-bit prime ≡ 1 mod 1024).
pub const Q_COMMIT: u64 = 562_949_953_438_721;

/// Global singleton NTT context for `R_{q_commit}`.
static CTX: OnceLock<Arc<Context>> = OnceLock::new();

/// Returns the singleton [`Context`] for `R_{q_commit}`, initialising it on
/// the first call.
fn ring_ctx() -> Result<&'static Arc<Context>, CycloError> {
    if let Some(ctx) = CTX.get() {
        return Ok(ctx);
    }
    let new_ctx = Context::new(&[Q_COMMIT], PHI_COMMIT)
        .map(Arc::new)
        .map_err(|_| CycloError::InvalidInstance("failed to build NTT context for R_q_commit"))?;
    let _ = CTX.set(new_ctx);
    CTX.get().ok_or(CycloError::InvalidInstance(
        "NTT context unavailable after init",
    ))
}

/// An element of `R_{q_commit} = Z_{q_commit}[X]/(X^256+1)`.
///
/// Coefficients are stored in the standard (non-centred) representation
/// `[0, Q_COMMIT)`.  There are always exactly [`PHI_COMMIT`] coefficients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RqPoly(pub Vec<u64>);

impl RqPoly {
    /// Constructs an `RqPoly` from a vector of [`PHI_COMMIT`] coefficients.
    ///
    /// Returns `Err` if `coeffs.len() != PHI_COMMIT` or any coefficient
    /// is `>= Q_COMMIT`.
    pub fn new(coeffs: Vec<u64>) -> Result<Self, CycloError> {
        if coeffs.len() != PHI_COMMIT {
            return Err(CycloError::InvalidInstance(
                "RqPoly must have exactly 256 coefficients",
            ));
        }
        for &c in &coeffs {
            if c >= Q_COMMIT {
                return Err(CycloError::InvalidInstance(
                    "RqPoly coefficient out of range [0, Q_COMMIT)",
                ));
            }
        }
        Ok(Self(coeffs))
    }

    /// Returns the zero polynomial in `R_{q_commit}`.
    pub fn zero() -> Self {
        Self(vec![0u64; PHI_COMMIT])
    }
}

/// Converts an `RqPoly` into an `fhe-math` [`Poly`] in `PowerBasis` representation.
fn rq_to_poly(p: &RqPoly, ctx: &Arc<Context>) -> Result<Poly, CycloError> {
    Poly::try_convert_from(p.0.clone(), ctx, false, Representation::PowerBasis)
        .map_err(|_| CycloError::InvalidInstance("failed to convert RqPoly to fhe-math Poly"))
}

/// Extracts coefficients from an `fhe-math` [`Poly`] in `PowerBasis` representation.
fn poly_to_rq(p: &Poly) -> RqPoly {
    RqPoly(Vec::<u64>::from(p))
}

/// Applies the forward NTT to `poly`, returning the NTT-domain representation.
///
/// The output coefficients are elements of `Z_{q_commit}` indexed by the NTT
/// evaluation points; they are **not** meaningful as polynomial coefficients.
pub fn ntt_forward(poly: &RqPoly) -> Result<RqPoly, CycloError> {
    let ctx = ring_ctx()?;
    let mut p = rq_to_poly(poly, ctx)?;
    p.change_representation(Representation::Ntt);
    Ok(poly_to_rq(&p))
}

/// Applies the inverse NTT to `poly`, returning the coefficient-domain representation.
pub fn ntt_inverse(poly: &RqPoly) -> Result<RqPoly, CycloError> {
    let ctx = ring_ctx()?;
    let mut p = Poly::try_convert_from(poly.0.clone(), ctx, false, Representation::Ntt)
        .map_err(|_| CycloError::InvalidInstance("failed to convert to NTT Poly"))?;
    p.change_representation(Representation::PowerBasis);
    Ok(poly_to_rq(&p))
}

/// Multiplies two polynomials in `R_{q_commit}` using the NTT.
///
/// Computes `a * b mod (X^256+1, q_commit)` by:
/// 1. Forward-NTT both inputs,
/// 2. Pointwise multiply in `Z_{q_commit}`,
/// 3. Inverse-NTT the result.
pub fn ntt_mul(a: &RqPoly, b: &RqPoly) -> Result<RqPoly, CycloError> {
    let ctx = ring_ctx()?;
    let mut pa = rq_to_poly(a, ctx)?;
    let mut pb = rq_to_poly(b, ctx)?;
    pa.change_representation(Representation::Ntt);
    pb.change_representation(Representation::NttShoup);
    pa *= &pb;
    pa.change_representation(Representation::PowerBasis);
    Ok(poly_to_rq(&pa))
}

/// Computes the centred coefficient `min(c, Q_COMMIT - c)` for a raw coefficient
/// `c ∈ [0, Q_COMMIT)`.
#[inline]
fn centred(c: u64) -> u64 {
    let neg = Q_COMMIT - c;
    if neg < c {
        neg
    } else {
        c
    }
}

/// Returns `‖poly‖_∞`: the maximum absolute value among the centred coefficients.
///
/// Each coefficient `c ∈ [0, Q_COMMIT)` is first mapped to the centred
/// representative `min(c, Q_COMMIT - c)` before taking the maximum.
pub fn norm_inf(poly: &RqPoly) -> u64 {
    poly.0.iter().map(|&c| centred(c)).max().unwrap_or(0)
}

/// Returns `‖poly‖_2²`: the sum of squares of the centred coefficients.
///
/// Uses `u128` to avoid overflow (each squared term is at most
/// `(Q_COMMIT/2)² ≈ 2^{97}`, and summing 256 such terms fits in u128).
pub fn norm_sq(poly: &RqPoly) -> u128 {
    poly.0
        .iter()
        .map(|&c| {
            let cc = u128::from(centred(c));
            cc * cc
        })
        .sum()
}
