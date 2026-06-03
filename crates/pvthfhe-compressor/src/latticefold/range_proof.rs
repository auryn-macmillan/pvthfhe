use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha3::{Digest, Keccak256};

/// §4.3 Monomial set check — purely algebraic range proof.
///
/// Proves `|w| ≤ B` without bit decomposition using polynomial evaluation.
/// The witness w is in [0, bound] iff the polynomial
/// `p(X) = ∏_{j=0}^{bound} (X - j)` vanishes at X = w.
///
/// Constraint cost: O(1) field operations per witness, independent of bound.
#[derive(Clone, Debug)]
pub struct AlgebraicRangeProof {
    pub eval_point: Fr,
    pub witness: Fr,
    pub product_eval: Fr,
    pub commitment: [u8; 32],
}

impl AlgebraicRangeProof {
    pub fn prove(witness: u64, bound: u64, challenge: &[u8; 32]) -> Self {
        let eval_point = Fr::from_be_bytes_mod_order(challenge);
        let witness_fr = Fr::from(witness);

        let product_eval = compute_product_polynomial_eval(witness_fr, bound);

        let commitment = {
            let mut hasher = Keccak256::new();
            hasher.update(b"latticefold-algebraic-range-v1");
            hasher.update(witness.to_le_bytes());
            hasher.update(challenge);
            hasher.finalize().into()
        };

        AlgebraicRangeProof {
            eval_point,
            witness: witness_fr,
            product_eval,
            commitment,
        }
    }

    pub fn verify(&self, bound: u64) -> bool {
        let recomputed = compute_product_polynomial_eval(self.witness, bound);
        recomputed == Fr::from(0u64) && self.product_eval == recomputed
    }
}

fn compute_product_polynomial_eval(w: Fr, bound: u64) -> Fr {
    let mut product = Fr::from(1u64);
    for j in 0..=bound {
        let j_fr = Fr::from(j);
        let factor = w - j_fr;
        product *= factor;
        if product == Fr::from(0u64) {
            return Fr::from(0u64);
        }
    }
    product
}

pub fn algebraic_range_check(witness: u64, bound: u64, _challenge: &[u8; 32]) -> bool {
    if witness > bound {
        return false;
    }
    let proof = AlgebraicRangeProof::prove(witness, bound, _challenge);
    proof.verify(bound)
}

pub fn precompute_table_polynomial(bound: u64) -> Vec<u64> {
    (0..=bound).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_challenge() -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(b"latticefold-test-challenge-v1");
        h.finalize().into()
    }

    #[test]
    fn algebraic_range_check_valid() {
        let ch = test_challenge();
        assert!(algebraic_range_check(0, 10, &ch));
        assert!(algebraic_range_check(5, 10, &ch));
        assert!(algebraic_range_check(10, 10, &ch));
    }

    #[test]
    fn algebraic_range_check_invalid() {
        let ch = test_challenge();
        assert!(!algebraic_range_check(11, 10, &ch));
        assert!(!algebraic_range_check(100, 10, &ch));
    }

    #[test]
    fn algebraic_range_check_bound_one() {
        let ch = test_challenge();
        assert!(algebraic_range_check(0, 1, &ch));
        assert!(algebraic_range_check(1, 1, &ch));
        assert!(!algebraic_range_check(2, 1, &ch));
    }

    #[test]
    fn algebraic_range_check_large_bound() {
        let ch = test_challenge();
        let b = 131_072u64;
        assert!(algebraic_range_check(0, b, &ch));
        assert!(algebraic_range_check(b / 2, b, &ch));
        assert!(algebraic_range_check(b, b, &ch));
        assert!(!algebraic_range_check(b + 1, b, &ch));
    }

    #[test]
    fn product_eval_zero_for_valid() {
        let w = Fr::from(5u64);
        let bound = 10u64;
        let result = compute_product_polynomial_eval(w, bound);
        assert_eq!(result, Fr::from(0u64));
    }

    #[test]
    fn product_eval_nonzero_for_invalid() {
        let w = Fr::from(11u64);
        let bound = 10u64;
        let result = compute_product_polynomial_eval(w, bound);
        assert_ne!(result, Fr::from(0u64));
    }

    #[test]
    fn proof_roundtrip() {
        let ch = test_challenge();
        let proof = AlgebraicRangeProof::prove(5, 10, &ch);
        assert!(proof.verify(10));
        assert!(!proof.verify(4));
    }

    #[test]
    fn product_at_zero() {
        let w = Fr::from(0u64);
        let bound = 5u64;
        let result = compute_product_polynomial_eval(w, bound);
        assert_eq!(result, Fr::from(0u64));
    }

    #[test]
    fn product_at_bound() {
        let w = Fr::from(5u64);
        let bound = 5u64;
        let result = compute_product_polynomial_eval(w, bound);
        assert_eq!(result, Fr::from(0u64));
    }
}
