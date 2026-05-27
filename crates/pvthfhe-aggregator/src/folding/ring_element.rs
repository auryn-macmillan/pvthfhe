//! Ring element arithmetic over R = Z_q[X]/(X^N + 1).
//!
//! Implements polynomial addition, subtraction, multiplication (O(N²) convolution),
//! and scalar operations for the Cyclo commitment ring with N=256.
//!
//! The ring modulus is X^N + 1, meaning X^N ≡ -1 in the ring.
//! Multiplication follows the convolution rule:
//!   result[k] = Σ_{i+j=k} a[i]·b[j] - Σ_{i+j=N+k} a[i]·b[j]

use ark_ff::PrimeField;

/// A polynomial ring element in R = Z_q[X]/(X^N + 1).
///
/// Represented as a vector of N field elements (coefficients).
/// All arithmetic operations are performed modulo X^N + 1,
/// but NOT reduced modulo q — the caller is responsible for
/// modular reduction if needed.
#[derive(Clone, Debug, PartialEq)]
pub struct RingElement<F: PrimeField> {
    /// Coefficients of the polynomial, from degree 0 to degree N-1.
    pub coeffs: Vec<F>,
}

impl<F: PrimeField> RingElement<F> {
    /// Create a zero ring element with `n` coefficients.
    pub fn zero(n: usize) -> Self {
        Self {
            coeffs: vec![F::zero(); n],
        }
    }

    /// Create a ring element with all coefficients set to a constant.
    pub fn constant(c: F, n: usize) -> Self {
        Self { coeffs: vec![c; n] }
    }

    /// Add two ring elements (coefficient-wise).
    ///
    /// # Panics
    /// Panics if the two ring elements have different lengths.
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(
            self.coeffs.len(),
            other.coeffs.len(),
            "RingElement::add: length mismatch"
        );
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(&a, &b)| a + b)
            .collect();
        Self { coeffs }
    }

    /// Subtract two ring elements (coefficient-wise).
    ///
    /// # Panics
    /// Panics if the two ring elements have different lengths.
    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(
            self.coeffs.len(),
            other.coeffs.len(),
            "RingElement::sub: length mismatch"
        );
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(&a, &b)| a - b)
            .collect();
        Self { coeffs }
    }

    /// Multiply two ring elements modulo X^N + 1.
    ///
    /// Uses O(N²) direct convolution. For N=256 this is ~65,536 field
    /// multiplications — acceptable for M1 proof-of-concept.
    ///
    /// The convolution rule under X^N ≡ -1:
    /// - For i+j < N:  result[i+j] += a[i] * b[j]
    /// - For i+j ≥ N:  result[i+j-N] -= a[i] * b[j]  (since X^N = -1)
    ///
    /// # Panics
    /// Panics if the two ring elements have different lengths.
    pub fn mul(&self, other: &Self) -> Self {
        let n = self.coeffs.len();
        assert_eq!(n, other.coeffs.len(), "RingElement::mul: length mismatch");
        let mut result = vec![F::zero(); n];
        for i in 0..n {
            for j in 0..n {
                let idx = (i + j) % n;
                if i + j >= n {
                    // X^N ≡ -1, so subtract
                    result[idx] -= self.coeffs[i] * other.coeffs[j];
                } else {
                    result[idx] += self.coeffs[i] * other.coeffs[j];
                }
            }
        }
        Self { coeffs: result }
    }

    /// Scale a ring element by a scalar (multiply every coefficient by `c`).
    pub fn scale(&self, c: F) -> Self {
        Self {
            coeffs: self.coeffs.iter().map(|&a| a * c).collect(),
        }
    }

    /// Compute the infinity norm (maximum absolute coefficient magnitude).
    /// Signed infinity norm: max |c_i| over all coefficients.
    ///
    /// For a prime field F_p, values > p/2 represent negative integers
    /// (stored as p - |c|). This method converts to absolute value before
    /// taking the max, so both positive and negative coefficients are
    /// compared by magnitude.
    pub fn norm_inf(&self) -> F {
        let half = <F as PrimeField>::MODULUS_MINUS_ONE_DIV_TWO;
        self.coeffs.iter().fold(F::zero(), |acc, &c| {
            let c_big = c.into_bigint();
            let abs = if c_big > half {
                // Signed representation: c > (p-1)/2 means negative.
                // Field negation -c yields MODULUS - c, the absolute value.
                -c
            } else {
                c
            };
            if abs > acc {
                abs
            } else {
                acc
            }
        })
    }

    /// Returns the number of coefficients (ring dimension N).
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// Returns true if the ring element has no coefficients.
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    type Fr = ark_bn254::Fr;

    fn fr(v: u64) -> Fr {
        Fr::from(v)
    }

    #[test]
    fn ring_add_identity() {
        let a = RingElement {
            coeffs: vec![fr(1), fr(2), fr(3)],
        };
        let zero = RingElement::zero(3);
        let result = a.add(&zero);
        assert_eq!(result, a);
    }

    #[test]
    fn ring_mul_commutative() {
        let a = RingElement {
            coeffs: vec![fr(1), fr(0), fr(0), fr(2)],
        };
        let b = RingElement {
            coeffs: vec![fr(0), fr(3), fr(0), fr(0)],
        };
        let ab = a.mul(&b);
        let ba = b.mul(&a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn ring_mul_mod_xn_plus_one() {
        // In ring modulo X^2+1: X·X = X^2 ≡ -1
        // So (0, 1) * (0, 1) should be (-1, 0)
        let x = RingElement {
            coeffs: vec![fr(0), fr(1)],
        };
        let result = x.mul(&x);
        // X * X ≡ -1 mod X^2+1 → (-1, 0)
        assert_eq!(result.coeffs[0], fr(0) - fr(1)); // -1 in field
        assert_eq!(result.coeffs[1], fr(0));
    }

    #[test]
    fn ring_mul_by_challenge_scalar_distributive() {
        // For ternary challenge c: c*(a+b) == c*a + c*b
        let c = fr(1); // challenge in { -1, 0, 1 }
        let a = RingElement {
            coeffs: vec![fr(2), fr(3), fr(5)],
        };
        let b = RingElement {
            coeffs: vec![fr(4), fr(1), fr(2)],
        };
        let left = a.add(&b).scale(c);
        let right = a.scale(c).add(&b.scale(c));
        assert_eq!(left, right);
    }

    #[test]
    fn ring_scale_zero_gives_zero() {
        let a = RingElement {
            coeffs: vec![fr(42), fr(7), fr(13)],
        };
        let result = a.scale(fr(0));
        for coeff in &result.coeffs {
            assert_eq!(*coeff, Fr::zero());
        }
    }
}
