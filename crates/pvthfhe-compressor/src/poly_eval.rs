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

/// Precompute powers of `r`: `[r^0, r^1, ..., r^{max_degree-1}]`.
pub fn precompute_powers_r(r: Fr, max_degree: usize) -> Vec<Fr> {
    let mut powers = Vec::with_capacity(max_degree);
    let mut current = Fr::from(1u64);
    for _ in 0..max_degree {
        powers.push(current);
        current *= r;
    }
    powers
}

/// Evaluate a polynomial using precomputed powers of the evaluation point.
///
/// `p(r) = Σ coeffs[i] * r^{N-1-i}` where `powers[j] = r^j`.
/// Equivalent to `eval_poly_bn254` but uses a dot product (1 multiply-add per coefficient).
pub fn eval_with_powers(coeffs: &[Fr], powers: &[Fr]) -> Fr {
    coeffs
        .iter()
        .zip(powers.iter().rev())
        .fold(Fr::from(0u64), |acc, (&c, &p)| acc + c * p)
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

    #[test]
    fn eval_with_powers_matches_horner() {
        let n = 100;
        let coeffs: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();
        let r = Fr::from(3u64);
        let powers = precompute_powers_r(r, n);
        let result_powers = eval_with_powers(&coeffs, &powers);
        let result_horner = eval_poly_bn254(&coeffs, r);
        assert_eq!(result_powers, result_horner);
    }

    #[test]
    fn eval_with_powers_empty_coeffs() {
        let powers = precompute_powers_r(Fr::from(42u64), 0);
        let result = eval_with_powers(&[], &powers);
        assert_eq!(result, Fr::from(0u64));
    }

    #[test]
    fn eval_with_powers_constant() {
        let c = Fr::from(7u64);
        let r = Fr::from(42u64);
        let powers = precompute_powers_r(r, 1);
        let result = eval_with_powers(&[c], &powers);
        assert_eq!(result, c);
    }

    #[test]
    fn precompute_powers_correct_length() {
        let r = Fr::from(5u64);
        let max_degree = 10;
        let powers = precompute_powers_r(r, max_degree);
        assert_eq!(powers.len(), max_degree);
        assert_eq!(powers[0], Fr::from(1u64));
        assert_eq!(powers[1], r);
        assert_eq!(powers[2], r * r);
    }

    #[test]
    fn eval_with_powers_equivalent_to_naive_dot_product() {
        let n = 50;
        let coeffs: Vec<Fr> = (0..n).map(|i| Fr::from((i * 7 + 3) as u64)).collect();
        let r = Fr::from(11u64);
        let powers = precompute_powers_r(r, n);

        let mut expected = Fr::from(0u64);
        for (i, c) in coeffs.iter().enumerate() {
            expected += *c * r.pow(&[(n - 1 - i) as u64]);
        }

        let result = eval_with_powers(&coeffs, &powers);
        assert_eq!(result, expected);
    }
}
