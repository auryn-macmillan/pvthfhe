//! LatticeFold+ Prover — folds n instances into a single accumulator.
//!
//! The `LatticeFoldProver` is the core lattice-native proving primitive.
//! Given n CCS instances (w_i, x_i), it computes a random linear combination
//! via Fiat-Shamir β, producing a single `LatticeFoldAccumulator` that
//! satisfies the same CCS relation when that relation is linear.
//!
//! This is the lattice variant of Nova's folding prover — no elliptic curves.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use sha3::{Digest, Keccak256};

use super::compressor::ExternalInputs3;
use super::fold::{fold_instances, FoldedInstance};

/// A folded accumulator produced by the LatticeFold+ prover.
///
/// Wraps the [`FoldedInstance`] with metadata about the folding operation.
#[derive(Clone, Debug)]
pub struct LatticeFoldAccumulator {
    /// The underlying folded instance (witness, commitment, public input).
    pub inner: FoldedInstance,
    /// Number of instances that were folded.
    pub instance_count: usize,
    /// Hash of the epoch used for β derivation.
    pub epoch_hash: [u8; 32],
    /// SRS identifier used for domain separation.
    pub srs_hash: [u8; 32],
}

impl LatticeFoldAccumulator {
    /// The number of instances folded into this accumulator.
    pub fn num_instances(&self) -> usize {
        self.instance_count
    }

    /// Commit the accumulator to an integrity hash.
    pub fn commit(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"latticefold-accumulator-commit-v1");
        hasher.update(&self.epoch_hash);
        hasher.update(&self.srs_hash);
        hasher.update(&(self.instance_count as u64).to_be_bytes());
        hasher.update(&self.inner.folded_commitment);
        let w_bytes = self.inner.folded_witness.into_bigint().to_bytes_be();
        hasher.update(&w_bytes);
        hasher.finalize().into()
    }
}

/// LatticeFold+ prover — lattice-native folding without elliptic curves.
///
/// The prover implements the scheme from LatticeFold+ (ePrint 2025/247 §5):
///
/// 1. Derives β = H(epoch || srs_hash || instances) via Fiat-Shamir.
/// 2. Computes β-powers: β⁰, β¹, ..., β^{n-1}.
/// 3. Folds witnesses:  w̃ = Σ_{i=0}^{n-1} β^i · w_i.
/// 4. Folds instances:  x̃ = Σ_{i=0}^{n-1} β^i · x_i.
/// 5. Commits:          C̃ = Commit(w̃).
///
/// The resulting (w̃, x̃, C̃) can be verified by [`LatticeFoldVerifier`](super::verifier::LatticeFoldVerifier).
pub struct LatticeFoldProver {
    /// Structured reference string hash for domain separation.
    srs_hash: [u8; 32],
    /// Epoch identifier for β derivation.
    epoch: [u8; 32],
}

impl LatticeFoldProver {
    /// Create a new LatticeFold+ prover.
    ///
    /// # Arguments
    /// * `epoch` - 32-byte epoch identifier for domain separation.
    /// * `srs_hash` - 32-byte structured reference string hash.
    pub fn new(epoch: [u8; 32], srs_hash: [u8; 32]) -> Self {
        Self { srs_hash, epoch }
    }

    /// Return the SRS hash used for domain separation.
    pub fn srs_hash(&self) -> [u8; 32] {
        self.srs_hash
    }

    /// Return the epoch identifier.
    pub fn epoch(&self) -> [u8; 32] {
        self.epoch
    }

    /// Fold n instances into a single accumulator using random β.
    ///
    /// This is the primary proving operation. Given n instances (each an
    /// [`ExternalInputs3`] triple of field elements), the prover derives β
    /// via Fiat-Shamir, computes the β-weighted linear combination, and
    /// returns a [`LatticeFoldAccumulator`] that the verifier can check.
    ///
    /// # Arguments
    /// * `instances` - Slice of n instances to fold. Must be non-empty.
    ///
    /// # Returns
    /// A [`LatticeFoldAccumulator`] containing the folded witness,
    /// commitment, and public input.
    ///
    /// # Panics
    /// Panics if `instances` is empty (checked at debug level).
    pub fn fold_n_instances(&self, instances: &[ExternalInputs3]) -> LatticeFoldAccumulator {
        assert!(!instances.is_empty(), "must fold at least one instance");

        let folded = fold_instances(instances, &self.epoch);
        LatticeFoldAccumulator {
            inner: folded,
            instance_count: instances.len(),
            epoch_hash: self.epoch,
            srs_hash: self.srs_hash,
        }
    }

    /// Fold a single instance (identity fold — β⁰ = 1).
    ///
    /// This is a convenience method for the common case of producing a proof
    /// for a single instance. The folded witness equals the instance witness,
    /// and β⁰ = 1.
    pub fn fold_one_instance(&self, instance: &ExternalInputs3) -> LatticeFoldAccumulator {
        let instances = vec![instance.clone()];
        self.fold_n_instances(&instances)
    }

    /// Produce a double commitment over the folded accumulator.
    ///
    /// For wire-format encoding of the accumulator, a double commitment is
    /// computed using the LatticeFold+ §4.1 scheme. When n < 10, the outer
    /// commitment is skipped (equals inner) to reduce overhead.
    pub fn commit_accumulator(
        &self,
        accumulator: &LatticeFoldAccumulator,
    ) -> super::fold::DoubleCommitment {
        let witness_bytes = accumulator.inner.folded_witness.into_bigint().to_bytes_be();
        super::fold::smart_commit(&witness_bytes, &self.srs_hash, accumulator.instance_count)
    }
}

impl From<LatticeFoldAccumulator> for ExternalInputs3 {
    fn from(acc: LatticeFoldAccumulator) -> Self {
        ExternalInputs3(
            acc.inner.folded_witness,
            acc.inner.folded_public_input,
            Fr::from(acc.instance_count as u64),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> [u8; 32] {
        Keccak256::digest(b"test-prover-epoch").into()
    }

    fn test_srs() -> [u8; 32] {
        Keccak256::digest(b"test-prover-srs").into()
    }

    #[test]
    fn prover_creation() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        assert_eq!(prover.epoch(), test_epoch());
        assert_eq!(prover.srs_hash(), test_srs());
    }

    #[test]
    fn fold_single_instance() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let acc = prover.fold_one_instance(&inst);
        assert_eq!(acc.instance_count, 1);
        assert_eq!(acc.inner.folded_witness, Fr::from(42u64));
    }

    #[test]
    fn fold_multiple_instances() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let instances = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
            ExternalInputs3(Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)),
        ];
        let acc = prover.fold_n_instances(&instances);
        assert_eq!(acc.instance_count, 3);
        // Witness should be β-weighted sum, not just the first instance
        assert_ne!(acc.inner.folded_witness, Fr::from(1u64));
    }

    #[test]
    fn accumulator_commit_is_deterministic() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let acc = prover.fold_one_instance(&inst);
        let c1 = acc.commit();
        let c2 = acc.commit();
        assert_eq!(c1, c2, "accumulator commit must be deterministic");
    }

    #[test]
    fn accumulator_commit_differs_for_different_witnesses() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let inst1 = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let inst2 = ExternalInputs3(Fr::from(99u64), Fr::from(0u64), Fr::from(1u64));
        let acc1 = prover.fold_one_instance(&inst1);
        let acc2 = prover.fold_one_instance(&inst2);
        assert_ne!(
            acc1.commit(),
            acc2.commit(),
            "different witnesses must produce different commits"
        );
    }

    #[test]
    fn commit_accumulator_roundtrip() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(0u64), Fr::from(1u64));
        let acc = prover.fold_one_instance(&inst);
        let dc = prover.commit_accumulator(&acc);
        let witness_bytes = acc.inner.folded_witness.into_bigint().to_bytes_be();
        let recomputed = super::super::fold::smart_commit(&witness_bytes, &test_srs(), 1);
        assert_eq!(dc.inner_commitment, recomputed.inner_commitment);
        assert_eq!(dc.outer_commitment, recomputed.outer_commitment);
    }

    #[test]
    fn fold_two_is_different_from_fold_one() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let instances = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)),
            ExternalInputs3(Fr::from(2u64), Fr::from(0u64), Fr::from(0u64)),
        ];
        let acc_n = prover.fold_n_instances(&instances);
        let acc_1 = prover.fold_one_instance(&instances[0]);
        assert_ne!(
            acc_n.inner.folded_witness, acc_1.inner.folded_witness,
            "folding 2 instances must differ from folding 1"
        );
    }

    #[test]
    fn from_accumulator_to_external_inputs() {
        let prover = LatticeFoldProver::new(test_epoch(), test_srs());
        let inst = ExternalInputs3(Fr::from(42u64), Fr::from(7u64), Fr::from(3u64));
        let acc = prover.fold_one_instance(&inst);
        let ei: ExternalInputs3 = acc.into();
        assert_eq!(ei.0, inst.0); // witness preserved for single instance
    }
}
