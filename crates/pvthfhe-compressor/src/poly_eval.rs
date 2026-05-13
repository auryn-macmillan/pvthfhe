//! Polynomial evaluation over Bn254 scalar field.
//!
//! Implements Horner's method for evaluating a polynomial at a point.
//! Pure field arithmetic — O(N) with no R1CS constraints.

use ark_bn254::Fr;

/// Evaluate a polynomial given by its coefficients at point `r`.
///
/// Uses Horner's method:
/// `p(r) = coeffs[0] + r * (coeffs[1] + r * (coeffs[2] + ... + r * coeffs[N-1] ... ))`
///
/// # Arguments
/// * `coeffs` - Slice of coefficients `[c_0, c_1, ..., c_{N-1}]`
/// * `r` - Evaluation point
///
/// # Returns
/// `p(r) = Σ coeffs[i] * r^{N-1-i}` (for 0 ≤ i < N)
///
/// Equivalent to `Σ coeffs[i] * r^{N-1-i}`; Horner's form computes
/// this in O(N) with N multiplications.
pub fn eval_poly_bn254(coeffs: &[Fr], r: Fr) -> Fr {
    if coeffs.is_empty() {
        return Fr::from(0u64);
    }
    let mut result = Fr::from(0u64);
    // Horner's method: result = c_0 + r * (c_1 + r * (c_2 + ... + r * c_{N-1}))
    for coeff in coeffs.iter() {
        result = result * r + coeff;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn poly_eval_zero_coeffs() {
        assert_eq!(eval_poly_bn254(&[], Fr::from(42u64)), Fr::from(0u64));
    }

    #[test]
    fn poly_eval_constant() {
        let c = Fr::from(7u64);
        assert_eq!(eval_poly_bn254(&[c], Fr::from(42u64)), c);
    }

    #[test]
    fn poly_eval_horner_matches_naive() {
        let n = 100;
        let coeffs: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();
        let r = Fr::from(3u64);

        let mut expected = Fr::from(0u64);
        for (i, c) in coeffs.iter().enumerate() {
            let power = n - 1 - i;
            expected += *c * r.pow(&[power as u64]);
        }

        let result = eval_poly_bn254(&coeffs, r);
        assert_eq!(result, expected);
    }

    #[test]
    fn poly_eval_r_is_one() {
        let coeffs: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let result = eval_poly_bn254(&coeffs, Fr::from(1u64));
        assert_eq!(result, Fr::from(6u64));
    }

    #[test]
    fn poly_eval_r_is_zero() {
        let coeffs: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let result = eval_poly_bn254(&coeffs, Fr::from(0u64));
        assert_eq!(result, Fr::from(3u64));
    }
}
