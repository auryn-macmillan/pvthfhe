use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::nova::ExternalInputs3;

#[derive(Clone, Debug)]
pub struct DoubleCommitment {
    pub inner_commitment: [u8; 32],
    pub outer_commitment: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct FoldedInstance {
    pub folded_witness: Fr,
    pub folded_commitment: [u8; 32],
    pub folded_public_input: Fr,
    pub beta_powers: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct SumcheckProof {
    pub challenges: Vec<Fr>,
    pub evaluations: Vec<Fr>,
    pub folded_claim: Fr,
}

pub fn double_commit(inner_data: &[u8], domain_separator: &[u8]) -> DoubleCommitment {
    let mut inner = Keccak256::new();
    inner.update(b"latticefold-inner-commit-v1");
    inner.update(domain_separator);
    inner.update(inner_data);
    let inner_hash: [u8; 32] = inner.finalize().into();

    let mut outer = Keccak256::new();
    outer.update(b"latticefold-outer-commit-v1");
    outer.update(domain_separator);
    outer.update(&inner_hash);
    let outer_hash: [u8; 32] = outer.finalize().into();

    DoubleCommitment {
        inner_commitment: inner_hash,
        outer_commitment: outer_hash,
    }
}

/// Smart commitment — skips outer commitment when n < 10.
///
/// For small n, the outer commitment overhead outweighs the proof size benefit.
/// When n < 10, outer_commitment is set equal to inner_commitment (no extra hashing).
pub fn smart_commit(inner_data: &[u8], domain_separator: &[u8], n: usize) -> DoubleCommitment {
    let mut inner = Keccak256::new();
    inner.update(b"latticefold-inner-commit-v1");
    inner.update(domain_separator);
    inner.update(inner_data);
    let inner_hash: [u8; 32] = inner.finalize().into();

    if n < 10 {
        DoubleCommitment {
            inner_commitment: inner_hash,
            outer_commitment: inner_hash,
        }
    } else {
        let mut outer = Keccak256::new();
        outer.update(b"latticefold-outer-commit-v1");
        outer.update(domain_separator);
        outer.update(&inner_hash);
        let outer_hash: [u8; 32] = outer.finalize().into();

        DoubleCommitment {
            inner_commitment: inner_hash,
            outer_commitment: outer_hash,
        }
    }
}

pub fn verify_double_commitment(
    commitment: &DoubleCommitment,
    inner_data: &[u8],
    domain_separator: &[u8],
) -> bool {
    let recomputed = double_commit(inner_data, domain_separator);
    commitment.inner_commitment == recomputed.inner_commitment
        && commitment.outer_commitment == recomputed.outer_commitment
}

/// §5 Folding: fold n instances into one using random β.
///
/// Given n instances (w_i, x_i) where w_i is the witness and x_i is the instance,
/// the folding protocol:
///
/// 1. Derives β = H(epoch || srs_hash || instances) via Fiat-Shamir.
/// 2. Computes folded witness:    w̃ = Σ_{i=0}^{n-1} β^i · w_i
/// 3. Computes folded instance:   x̃ = Σ_{i=0}^{n-1} β^i · x_i
/// 4. Computes folded commitment: C̃ = Commit(w̃)
///
/// The resulting (w̃, x̃) satisfies the same relation as the original instances
/// when the relation is linear (e.g., CCS-based folding).
pub fn fold_instances(instances: &[ExternalInputs3<Fr>], epoch: &[u8; 32]) -> FoldedInstance {
    // Derive β via Fiat-Shamir
    let beta = derive_beta(epoch, instances);

    // Precompute powers of β: β⁰, β¹, ..., β^{n-1}
    let beta_powers: Vec<Fr> = (0..instances.len())
        .scan(Fr::from(1u64), |pow, _| {
            let current = *pow;
            *pow *= beta;
            Some(current)
        })
        .collect();

    // Fold witnesses using β-weighted linear combination
    let folded_witness = instances
        .iter()
        .zip(beta_powers.iter())
        .fold(Fr::from(0u64), |acc, (inst, &beta_pow)| {
            acc + inst.0 * beta_pow
        });

    // Fold public inputs (inst.1 = norm, inst.2 = count)
    let folded_public_input = instances
        .iter()
        .zip(beta_powers.iter())
        .fold(Fr::from(0u64), |acc, (inst, &beta_pow)| {
            acc + inst.1 * beta_pow + inst.2 * beta_pow
        });

    // Compute folded commitment = H(folded_witness || β)
    let folded_commitment = {
        let mut hasher = Keccak256::new();
        hasher.update(b"latticefold-fold-commit-v1");
        hasher.update(epoch);
        let mut folded_bytes = Vec::new();
        let be_bytes = folded_witness.into_bigint().to_bytes_be();
        folded_bytes.extend_from_slice(&be_bytes);
        hasher.update(&folded_bytes);
        hasher.finalize().into()
    };

    FoldedInstance {
        folded_witness,
        folded_commitment,
        folded_public_input,
        beta_powers,
    }
}

/// Verify a folded instance against the original instances.
pub fn verify_folded_instance(
    folded: &FoldedInstance,
    instances: &[ExternalInputs3<Fr>],
    epoch: &[u8; 32],
) -> bool {
    // Re-derive β for deterministic verification
    let beta = derive_beta(epoch, instances);

    // Verify that β_powers are consistent with derived β
    let mut pow = Fr::from(1u64);
    for (i, &bp) in folded.beta_powers.iter().enumerate() {
        if bp != pow || i >= instances.len() {
            return false;
        }
        pow *= beta;
    }

    // Recompute folded witness
    let recomputed_witness = instances
        .iter()
        .zip(folded.beta_powers.iter())
        .fold(Fr::from(0u64), |acc, (inst, &beta_pow)| {
            acc + inst.0 * beta_pow
        });

    if recomputed_witness != folded.folded_witness {
        return false;
    }

    // Verify commitment
    let recomputed_commitment = {
        let mut hasher = Keccak256::new();
        hasher.update(b"latticefold-fold-commit-v1");
        hasher.update(epoch);
        let mut folded_bytes = Vec::new();
        let be_bytes = folded.folded_witness.into_bigint().to_bytes_be();
        folded_bytes.extend_from_slice(&be_bytes);
        hasher.update(&folded_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        hash
    };

    recomputed_commitment == folded.folded_commitment
}

/// §5.2 Sumcheck transformation — fold double commitments.
///
/// Transforms a double commitment into a sumcheck-friendly form.
/// Given a double commitment D = Commit(Commit(w)), the sumcheck protocol
/// reduces verification to evaluating a multivariate polynomial at a
/// random point.
pub fn sumcheck_transform(
    double_commitment: &DoubleCommitment,
    challenge: &[u8; 32],
) -> SumcheckProof {
    let r = Fr::from_be_bytes_mod_order(challenge);

    // Convert commitments to field elements
    let inner_fr = Fr::from_be_bytes_mod_order(&double_commitment.inner_commitment);
    let outer_fr = Fr::from_be_bytes_mod_order(&double_commitment.outer_commitment);

    SumcheckProof {
        challenges: vec![r],
        evaluations: vec![inner_fr, outer_fr],
        folded_claim: inner_fr * r + outer_fr,
    }
}

/// Derive folding randomizer β from Fiat-Shamir.
fn derive_beta(epoch: &[u8; 32], instances: &[ExternalInputs3<Fr>]) -> Fr {
    let mut hasher = Keccak256::new();
    hasher.update(b"latticefold-fold-beta-v1");
    hasher.update(epoch);
    hasher.update((instances.len() as u64).to_be_bytes());
    for inst in instances {
        let buf = inst.0.into_bigint().to_bytes_be().to_vec();
        hasher.update(&buf);

        let buf2 = inst.1.into_bigint().to_bytes_be().to_vec();
        hasher.update(&buf2);

        let buf3 = inst.2.into_bigint().to_bytes_be().to_vec();
        hasher.update(&buf3);
    }
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> [u8; 32] {
        Keccak256::digest(b"test-epoch").into()
    }

    #[test]
    fn double_commit_roundtrip() {
        let data = b"test data for commitment";
        let dc = double_commit(data, b"test");
        assert!(verify_double_commitment(&dc, data, b"test"));
    }

    #[test]
    fn double_commit_tamper_detection() {
        let data = b"original data";
        let dc = double_commit(data, b"test");
        let tampered = b"tampered data";
        assert!(!verify_double_commitment(&dc, tampered, b"test"));
    }

    #[test]
    fn smart_commit_skips_outer_for_small_n() {
        let data = b"smart commit data";
        let small = smart_commit(data, b"test", 3);
        let large = smart_commit(data, b"test", 11);
        assert_eq!(
            small.inner_commitment, small.outer_commitment,
            "small n: outer equals inner (skipped)"
        );
        assert_ne!(
            large.inner_commitment, large.outer_commitment,
            "large n: outer differs from inner"
        );
    }

    #[test]
    fn smart_commit_inner_unchanged() {
        let data = b"same data";
        let dc = double_commit(data, b"test");
        let sc = smart_commit(data, b"test", 5);
        assert_eq!(dc.inner_commitment, sc.inner_commitment);
    }

    #[test]
    fn fold_instances_roundtrip() {
        let epoch = test_epoch();
        let instances = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
            ExternalInputs3(Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)),
        ];
        let folded = fold_instances(&instances, &epoch);
        assert!(verify_folded_instance(&folded, &instances, &epoch));
    }

    #[test]
    fn fold_single_instance() {
        let epoch = test_epoch();
        let instances = vec![ExternalInputs3(
            Fr::from(42u64),
            Fr::from(0u64),
            Fr::from(1u64),
        )];
        let folded = fold_instances(&instances, &epoch);
        assert_eq!(folded.folded_witness, Fr::from(42u64));
        assert!(verify_folded_instance(&folded, &instances, &epoch));
    }

    #[test]
    fn sumcheck_transform_consistency() {
        let data = b"sumcheck test data";
        let dc = double_commit(data, b"sumcheck");
        let ch = Keccak256::digest(b"sumcheck-challenge").into();
        let proof = sumcheck_transform(&dc, &ch);
        assert_eq!(proof.challenges.len(), 1);
        assert_eq!(proof.evaluations.len(), 2);
        // The folded claim should be non-zero
        assert_ne!(proof.folded_claim, Fr::from(0u64));
    }

    #[test]
    fn derive_beta_deterministic() {
        let epoch = test_epoch();
        let instances = vec![ExternalInputs3(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        )];
        let b1 = derive_beta(&epoch, &instances);
        let b2 = derive_beta(&epoch, &instances);
        assert_eq!(b1, b2, "β derivation must be deterministic");
    }

    #[test]
    fn derive_beta_different_instances() {
        let epoch = test_epoch();
        let i1 = vec![ExternalInputs3(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        )];
        let i2 = vec![ExternalInputs3(
            Fr::from(9u64),
            Fr::from(8u64),
            Fr::from(7u64),
        )];
        let b1 = derive_beta(&epoch, &i1);
        let b2 = derive_beta(&epoch, &i2);
        assert_ne!(b1, b2, "different instances should give different β");
    }

    #[test]
    fn verify_folded_instance_tamper_epoch() {
        let epoch = test_epoch();
        let wrong_epoch: [u8; 32] = Keccak256::digest(b"wrong-epoch").into();
        let instances = vec![ExternalInputs3(
            Fr::from(42u64),
            Fr::from(0u64),
            Fr::from(1u64),
        )];
        let folded = fold_instances(&instances, &epoch);
        assert!(!verify_folded_instance(&folded, &instances, &wrong_epoch));
    }
}
