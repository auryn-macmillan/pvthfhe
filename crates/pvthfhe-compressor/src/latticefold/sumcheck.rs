//! LatticeFold+ §5.2 Sumcheck transformation.
//!
//! Transforms a double commitment into a sumcheck-friendly form.
//! Given a double commitment D = Commit(Commit(w)), the sumcheck protocol
//! reduces verification to evaluating a multivariate polynomial at a
//! random point, enabling efficient folding of commitment chains.
//!
//! All logic is implemented in [`super::fold`] — this module re-exports
//! the public API for plan-conformant module structure.

pub use super::fold::sumcheck_transform;
pub use super::fold::SumcheckProof;

#[cfg(test)]
mod tests {
    use super::super::fold::double_commit;
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use sha3::{Digest, Keccak256};

    #[test]
    fn sumcheck_transform_nonzero_claim() {
        let data = b"sumcheck test data";
        let dc = double_commit(data, b"sumcheck");
        let ch: [u8; 32] = Keccak256::digest(b"sumcheck-challenge").into();
        let proof = sumcheck_transform(&dc, &ch);
        assert_eq!(proof.challenges.len(), 1);
        assert_eq!(proof.evaluations.len(), 2);
        assert_ne!(proof.folded_claim, Fr::from(0u64));
    }

    #[test]
    fn sumcheck_transform_deterministic() {
        let data = b"deterministic test";
        let dc = double_commit(data, b"sumcheck");
        let ch: [u8; 32] = Keccak256::digest(b"sumcheck-challenge").into();
        let p1 = sumcheck_transform(&dc, &ch);
        let p2 = sumcheck_transform(&dc, &ch);
        assert_eq!(p1.challenges, p2.challenges);
        assert_eq!(p1.evaluations, p2.evaluations);
        assert_eq!(p1.folded_claim, p2.folded_claim);
    }
}
