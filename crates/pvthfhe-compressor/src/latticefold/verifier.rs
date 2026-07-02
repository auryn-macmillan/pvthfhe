use ark_ff::{BigInteger, PrimeField};

use super::compressor::ExternalInputs3;
use super::fold::verify_folded_instance;
use super::prover::LatticeFoldAccumulator;

/// LatticeFold+ verifier — verifies a folded accumulator.
///
/// The verifier recomputes the expected folded instance from the original
/// instances and compares it against the accumulator. This is the lattice
/// variant of Nova's folding verifier — no elliptic curve operations.
pub struct LatticeFoldVerifier {
    srs_hash: [u8; 32],
    epoch: [u8; 32],
}

impl LatticeFoldVerifier {
    pub fn new(epoch: [u8; 32], srs_hash: [u8; 32]) -> Self {
        Self { srs_hash, epoch }
    }

    pub fn srs_hash(&self) -> [u8; 32] {
        self.srs_hash
    }

    pub fn epoch(&self) -> [u8; 32] {
        self.epoch
    }

    /// Verify a folded accumulator against its original instances.
    ///
    /// Re-derives β via Fiat-Shamir, checks β-power consistency, recomputes
    /// the folded witness, and verifies the commitment against the accumulator.
    ///
    /// Returns `true` if the accumulator is a valid folding of the instances.
    pub fn verify(
        &self,
        accumulator: &LatticeFoldAccumulator,
        instances: &[ExternalInputs3],
    ) -> bool {
        if accumulator.instance_count != instances.len() {
            return false;
        }
        if accumulator.epoch_hash != self.epoch {
            return false;
        }
        if accumulator.srs_hash != self.srs_hash {
            return false;
        }
        verify_folded_instance(&accumulator.inner, instances, &self.epoch)
    }

    /// Verify a single-instance accumulator (β⁰ = 1 identity fold).
    pub fn verify_one(
        &self,
        accumulator: &LatticeFoldAccumulator,
        instance: &ExternalInputs3,
    ) -> bool {
        let instances = vec![instance.clone()];
        self.verify(accumulator, &instances)
    }

    /// Verify the double commitment of an accumulator.
    ///
    /// Recomputes the double commitment from the accumulator's witness and
    /// compares against the provided commitment.
    pub fn verify_accumulator_commitment(
        &self,
        accumulator: &LatticeFoldAccumulator,
        commitment: &super::fold::DoubleCommitment,
    ) -> bool {
        let witness_bytes = accumulator.inner.folded_witness.into_bigint().to_bytes_be();
        let recomputed =
            super::fold::smart_commit(&witness_bytes, &self.srs_hash, accumulator.instance_count);
        commitment.inner_commitment == recomputed.inner_commitment
            && commitment.outer_commitment == recomputed.outer_commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use sha3::{Digest, Keccak256};

    use super::super::prover::LatticeFoldProver;

    fn test_epoch() -> [u8; 32] {
        Keccak256::digest(b"test-verifier-epoch").into()
    }

    fn test_srs() -> [u8; 32] {
        Keccak256::digest(b"test-verifier-srs").into()
    }

    #[test]
    fn verifier_creation() {
        let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
        assert_eq!(verifier.epoch(), test_epoch());
        assert_eq!(verifier.srs_hash(), test_srs());
    }

    #[test]
    fn verify_single_instance_roundtrip() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let acc = prover.fold_one_instance(&inst);
        assert!(verifier.verify_one(&acc, &inst));
    }

    #[test]
    fn verify_multiple_instances_roundtrip() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
        let instances = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
            ExternalInputs3(Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)),
        ];
        let acc = prover.fold_n_instances(&instances);
        assert!(verifier.verify(&acc, &instances));
    }

    #[test]
    fn verify_rejects_wrong_epoch() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let wrong_epoch: [u8; 32] = Keccak256::digest(b"wrong-epoch").into();
        let verifier = LatticeFoldVerifier::new(wrong_epoch, test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let acc = prover.fold_one_instance(&inst);
        assert!(!verifier.verify_one(&acc, &inst));
    }

    #[test]
    fn verify_rejects_mismatched_count() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
        let instances = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
        ];
        let acc = prover.fold_n_instances(&instances);
        let wrong_instances = vec![ExternalInputs3(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        )];
        assert!(!verifier.verify(&acc, &wrong_instances));
    }

    #[test]
    fn verify_rejects_tampered_instances() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
        let instances = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
        ];
        let acc = prover.fold_n_instances(&instances);
        let tampered = vec![
            ExternalInputs3(Fr::from(99u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
        ];
        assert!(!verifier.verify(&acc, &tampered));
    }

    #[test]
    fn verify_accumulator_commitment_roundtrip() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let acc = prover.fold_one_instance(&inst);
        let dc = prover.commit_accumulator(&acc);
        assert!(verifier.verify_accumulator_commitment(&acc, &dc));
    }

    #[test]
    fn verify_accumulator_commitment_rejects_tampered() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let acc = prover.fold_one_instance(&inst);
        let dc = prover.commit_accumulator(&acc);
        let tampered = super::super::fold::DoubleCommitment {
            inner_commitment: [0u8; 32],
            outer_commitment: dc.outer_commitment,
        };
        assert!(!verifier.verify_accumulator_commitment(&acc, &tampered));
    }
}
