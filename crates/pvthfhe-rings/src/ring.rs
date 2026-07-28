//! Per-channel cyclotomic ring arithmetic via `fhe-math` NTT.
//!
//! [`FheMathRing`] is a concrete ring `R_q = Z_q[X]/(X^N+1)` parameterized
//! by modulus `q` and degree `N`. It uses `fhe-math`'s NTT-accelerated
//! polynomial arithmetic for fast multiplication.

use fhe_math::rq::{traits::TryConvertFrom, Context, Poly};
use std::sync::Arc;

use crate::params::ChannelParams;

/// A polynomial in `R_q = Z_q[X]/(X^N+1)` stored in coefficient representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RqPoly {
    /// Coefficients from degree 0 to degree N-1, each in [0, q).
    pub coeffs: Vec<u64>,
    /// Ring degree N.
    pub degree: usize,
}

impl RqPoly {
    /// Zero polynomial.
    pub fn zero(degree: usize) -> Self {
        Self {
            coeffs: vec![0u64; degree],
            degree,
        }
    }

    /// Polynomial with all coefficients equal to `c`.
    pub fn constant(c: u64, degree: usize) -> Self {
        Self {
            coeffs: vec![c; degree],
            degree,
        }
    }
}

/// A concrete ring `R_q = Z_q[X]/(X^N+1)` backed by `fhe-math`.
///
/// Each instance is parameterized by channel parameters (modulus `q`, degree `N`)
/// and initializes the NTT context on construction.
#[derive(Clone)]
pub struct FheMathRing {
    /// Channel parameters (modulus, degree, decomposition config).
    pub params: ChannelParams,
    ctx: Arc<Context>,
}

impl FheMathRing {
    /// Create a new ring from channel parameters.
    pub fn new(params: ChannelParams) -> Result<Self, String> {
        params.validate()?;
        let ctx = Context::new(&[params.modulus], params.degree)
            .map_err(|e| format!("failed to create NTT context: {e}"))?;
        Ok(Self {
            params,
            ctx: Arc::new(ctx),
        })
    }

    /// Ring degree N.
    pub fn degree(&self) -> usize {
        self.params.degree
    }

    /// Ring modulus q.
    pub fn modulus(&self) -> u64 {
        self.params.modulus
    }

    /// Create an [`RqPoly`] from raw coefficients.
    pub fn poly(&self, coeffs: Vec<u64>) -> RqPoly {
        assert_eq!(coeffs.len(), self.params.degree);
        RqPoly {
            coeffs,
            degree: self.params.degree,
        }
    }

    /// Add two ring elements: coefficients modulo q.
    pub fn add(&self, a: &RqPoly, b: &RqPoly) -> RqPoly {
        let q = self.params.modulus;
        let coeffs: Vec<u64> = a
            .coeffs
            .iter()
            .zip(b.coeffs.iter())
            .map(|(&x, &y)| (x + y) % q)
            .collect();
        RqPoly {
            coeffs,
            degree: self.params.degree,
        }
    }

    /// Subtract `b` from `a`: coefficients modulo q.
    pub fn sub(&self, a: &RqPoly, b: &RqPoly) -> RqPoly {
        let q = self.params.modulus;
        let coeffs: Vec<u64> = a
            .coeffs
            .iter()
            .zip(b.coeffs.iter())
            .map(|(&x, &y)| (x + q - y) % q)
            .collect();
        RqPoly {
            coeffs,
            degree: self.params.degree,
        }
    }

    /// Multiply two ring elements via NTT.
    pub fn mul(&self, a: &RqPoly, b: &RqPoly) -> RqPoly {
        let mut pa = self.to_fhe_poly(a);
        let mut pb = self.to_fhe_poly(b);
        // Convert to NTT domain for pointwise multiplication
        pa.change_representation(fhe_math::rq::Representation::Ntt);
        pb.change_representation(fhe_math::rq::Representation::NttShoup);
        pa *= &pb;
        pa.change_representation(fhe_math::rq::Representation::PowerBasis);
        self.from_fhe_poly(&pa)
    }

    /// L-infinity norm: max absolute centered coefficient.
    pub fn linf_norm(&self, a: &RqPoly) -> u64 {
        let half_q = self.params.modulus / 2;
        a.coeffs
            .iter()
            .map(|&c| {
                if c > half_q {
                    self.params.modulus - c
                } else {
                    c
                }
            })
            .max()
            .unwrap_or(0)
    }

    /// Internal: convert [`RqPoly`] to fhe-math [`Poly`].
    fn to_fhe_poly(&self, a: &RqPoly) -> Poly {
        Poly::try_convert_from(
            a.coeffs.clone(),
            &self.ctx,
            false,
            fhe_math::rq::Representation::default(),
        )
        .expect("poly conversion")
    }

    /// Internal: convert fhe-math [`Poly`] to [`RqPoly`].
    fn from_fhe_poly(&self, p: &Poly) -> RqPoly {
        let coeffs: Vec<u64> = Vec::from(p);
        RqPoly {
            coeffs,
            degree: self.params.degree,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ProdParams;

    fn test_ring() -> FheMathRing {
        let params = ChannelParams {
            degree: 8, // fhe-math requires power-of-two ≥ 8
            modulus: ProdParams::Q0,
            decomposition_base: ProdParams::B,
            limb_count: ProdParams::LIMB_COUNT,
        };
        FheMathRing::new(params).expect("valid params")
    }

    #[test]
    fn add_commutative() {
        let r = test_ring();
        let a = r.poly(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let b = r.poly(vec![5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(r.add(&a, &b), r.add(&b, &a));
    }

    #[test]
    fn mul_commutative() {
        let r = test_ring();
        let a = r.poly(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let b = r.poly(vec![5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(r.mul(&a, &b), r.mul(&b, &a));
    }

    #[test]
    fn linf_norm_centered() {
        let r = test_ring();
        let a = r.poly(vec![ProdParams::Q0 - 1, 0, 3, 5, 0, 0, 0, 0]);
        assert_eq!(r.linf_norm(&a), 5);
    }

    #[test]
    fn zero_identity() {
        let r = test_ring();
        let a = r.poly(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let z = RqPoly::zero(8);
        assert_eq!(r.add(&a, &z), a);
    }
}
