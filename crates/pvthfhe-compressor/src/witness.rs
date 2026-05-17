//! Witness generation pipeline for C7 decryption aggregation.
//!
//! Builds Merkle trees over share coefficients, generates proofs,
//! computes polynomial evaluations, and verifies Merkle proofs
//! off-circuit before Nova folding.

use ark_bn254::Fr;

use crate::merkle::{build_merkle_tree, prove_merkle_path, verify_merkle_proof, MerkleProof};
use crate::poly_eval::eval_poly_bn254;

/// A single participant's C7 witness.
#[derive(Clone, Debug)]
pub struct C7Witness {
    /// Merkle root committing to the participant's share coefficients.
    pub merkle_root: Fr,
    /// Polynomial evaluation d_i(r) = Σ coeffs[j] * r^{N-1-j}.
    pub share_eval: Fr,
    /// Merkle proof binding the evaluation to the root.
    pub merkle_proof: MerkleProof,
    /// Lagrange coefficient λ_i for this participant.
    pub lagrange_coeff: Fr,
    /// Share polynomial coefficients (N=8192 field elements).
    /// Used by the C7DecryptAggregationCircuit for in-circuit
    /// evaluation verification (G2).
    pub coeffs: Vec<Fr>,
}

/// A set of C7 witnesses for all participants in a decryption round.
#[derive(Clone, Debug)]
pub struct C7WitnessSet {
    /// Witness for each participant.
    pub participants: Vec<C7Witness>,
    /// Challenge point r used for polynomial evaluation.
    pub challenge_r: Fr,
}

impl C7WitnessSet {
    /// Construct a `C7WitnessSet` from share coefficients, Lagrange coefficients,
    /// and a challenge point.
    ///
    /// For each participant:
    /// 1. Build an 8-ary Merkle tree over their share coefficients.
    /// 2. Evaluate the share polynomial at `challenge_r`.
    /// 3. Generate a Merkle proof for leaf index 0 (or any representative index).
    ///
    /// # Arguments
    /// * `shares` - For each participant, a Vec of N=8192 share coefficients.
    /// * `lagrange_coeffs` - Lagrange coefficient λ_i for each participant.
    /// * `challenge_r` - Challenge point for polynomial evaluation.
    ///
    /// # Panics
    /// Panics if `shares.len() != lagrange_coeffs.len()`.
    pub fn new(
        shares: &[Vec<Fr>],
        lagrange_coeffs: &[Fr],
        challenge_r: Fr,
    ) -> Self {
        assert_eq!(
            shares.len(),
            lagrange_coeffs.len(),
            "shares and lagrange_coeffs must have same length"
        );

        const ARITY: usize = 8;

        let mut participants = Vec::with_capacity(shares.len());

        for (i, coeffs) in shares.iter().enumerate() {
            let (tree, merkle_root) = build_merkle_tree(coeffs, ARITY);
            let share_eval = eval_poly_bn254(coeffs, challenge_r);
            let merkle_proof = prove_merkle_path(&tree, 0, ARITY);

            participants.push(C7Witness {
                merkle_root,
                share_eval,
                merkle_proof,
                lagrange_coeff: lagrange_coeffs[i],
                coeffs: coeffs.clone(),
            });
        }

        Self {
            participants,
            challenge_r,
        }
    }

    /// Verify all Merkle proofs in the witness set.
    ///
    /// Returns `true` if every participant's Merkle proof is valid.
    /// Must be called before Nova folding to ensure input integrity.
    pub fn verify_merkle_proofs(&self) -> bool {
        const ARITY: usize = 8;
        for witness in &self.participants {
            if !verify_merkle_proof(&witness.merkle_proof, ARITY) {
                return false;
            }
        }
        true
    }

    /// Verify that the Lagrange coefficients sum to 1 (off-circuit sanity check).
    ///
    /// The Nova circuit enforces this incrementally; this check catches
    /// input errors early.
    pub fn verify_lagrange_sum(&self) -> bool {
        let sum: Fr = self
            .participants
            .iter()
            .map(|w| w.lagrange_coeff)
            .fold(Fr::from(0u64), |a, b| a + b);
        sum == Fr::from(1u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_set_empty_shares() {
        let set = C7WitnessSet::new(&[], &[], Fr::from(42u64));
        assert!(set.verify_merkle_proofs());
    }

    #[test]
    fn witness_set_single_share_trivial() {
        let coeffs: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();
        let set = C7WitnessSet::new(
            &[coeffs],
            &[Fr::from(1u64)],
            Fr::from(3u64),
        );
        assert!(set.verify_merkle_proofs());
        assert!(set.verify_lagrange_sum());
    }
}
