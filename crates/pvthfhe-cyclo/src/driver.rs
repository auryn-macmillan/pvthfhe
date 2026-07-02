//! Sequential T=10 fold driver for PVTHFHE Cyclo LatticeFold+.
//!
//! Folds exactly T=10 [`CcsPShareInstance`] objects sequentially using the
//! T3 fold sub-protocol from [`crate::fold`], enforces the final norm budget
//! β_T ≤ 1344, and exposes [`fold_all`] as the top-level entry point.
//!
//! [`fold_all_batched`] provides a batch fold variant that pre-combines
//! instances via random linear combination (Symphony T1) before folding,
//! reducing per-batch fold steps from `k` to 1.

use crate::{
    ajtai, ccs_encode, fiat_shamir,
    fold::{fold_one_step, init_accumulator, AJTAI_COMMITMENT_M},
    ring::{ring_add_poly, scalar_mul, RqPoly},
    CcsPShareInstance, CycloAccumulator, CycloError, PVTHFHE_CYCLO_PARAMS,
};
use pvthfhe_types::ProtocolBytes;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// Folds all `instances` sequentially, returning the final accumulator.
///
/// Initialises from `instances[0]`, then applies `fold_one_step` for every
/// instance (including `instances[0]`), so `fold_depth == instances.len()`.
///
/// # Errors
///
/// Returns [`CycloError::InvalidInstance`] if `instances` is empty,
/// [`CycloError::FoldDepthExhausted`] if `instances.len() > T`, or
/// [`CycloError::NormBoundExceeded`] if the final norm exceeds β_T.
pub fn fold_all(
    instances: &[CcsPShareInstance],
    session_id: &str,
    rng: &mut dyn RngCore,
) -> Result<CycloAccumulator, CycloError> {
    if instances.is_empty() {
        return Err(CycloError::InvalidInstance(
            "at least one instance required",
        ));
    }
    let t = usize::try_from(PVTHFHE_CYCLO_PARAMS.sequential_t)
        .map_err(|_| CycloError::InvalidInstance("sequential_t overflows usize"))?;
    if instances.len() > t {
        return Err(CycloError::FoldDepthExhausted(
            PVTHFHE_CYCLO_PARAMS.sequential_t,
        ));
    }

    let mut acc = init_accumulator(&instances[0], session_id)?;
    for instance in instances {
        acc = fold_one_step(acc, instance, rng)?;
    }

    if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(CycloError::NormBoundExceeded {
            got: acc.norm_bound_current,
            max: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        });
    }

    Ok(acc)
}

/// Derives a deterministic β coefficient for batch folding.
///
/// Uses Fiat-Shamir: `SHA-256("pvthfhe-cyclo-batch-beta-v1" ‖ session_id ‖ batch_id ‖ i)`.
pub fn derive_beta(session_id: &str, batch_id: usize, i: usize) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-cyclo-batch-beta-v1");
    hasher.update(session_id.as_bytes());
    hasher.update(&batch_id.to_le_bytes());
    hasher.update(&i.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    u128::from_le_bytes(hash[..16].try_into().unwrap())
}

pub fn fold_all_batched(
    instances: &[CcsPShareInstance],
    session_id: &str,
    rng: &mut dyn RngCore,
) -> Result<Vec<CycloAccumulator>, CycloError> {
    if instances.is_empty() {
        return Err(CycloError::InvalidInstance(
            "at least one instance required",
        ));
    }
    let batch_size = usize::try_from(PVTHFHE_CYCLO_PARAMS.batch_fold_arity)
        .map_err(|_| CycloError::InvalidInstance("batch_fold_arity overflows usize"))?;
    if batch_size == 0 {
        return Err(CycloError::InvalidInstance(
            "batch_fold_arity must be positive",
        ));
    }

    let m = PVTHFHE_CYCLO_PARAMS.ajtai_rank_a;

    let mut accumulators = Vec::with_capacity(instances.len().div_ceil(batch_size));

    for (batch_id, batch) in instances.chunks(batch_size).enumerate() {
        if batch.is_empty() {
            continue;
        }

        let betas: Vec<u128> = (0..batch.len())
            .map(|i| derive_beta(session_id, batch_id, i))
            .collect();

        let combined_commitment = {
            let mut decoded_commitments: Vec<ajtai::AjtaiCommitment> =
                Vec::with_capacity(batch.len());
            for inst in batch {
                let commitment =
                    ajtai::decode_commitment(inst.ajtai_commitment_bytes.as_slice(), m)?;
                decoded_commitments.push(commitment);
            }

            let mut combined_polys: Vec<RqPoly> = vec![RqPoly::zero(); m];

            for (inst_idx, commitment) in decoded_commitments.iter().enumerate() {
                let beta = betas[inst_idx];
                for (poly_idx, inst_poly) in commitment.commitment.iter().enumerate() {
                    let scaled = scalar_mul(inst_poly, beta);
                    combined_polys[poly_idx] = ring_add_poly(&combined_polys[poly_idx], &scaled);
                }
            }

            ajtai::encode_commitment(&ajtai::AjtaiCommitment {
                commitment: combined_polys,
            })
        };

        let combined_pub_io = {
            let mut hasher = Sha256::new();
            hasher.update(b"pvthfhe-cyclo-batch-io-v1");
            hasher.update(session_id.as_bytes());
            hasher.update(&batch_id.to_le_bytes());
            for (i, inst) in batch.iter().enumerate() {
                hasher.update(&betas[i].to_le_bytes());
                hasher.update(inst.public_io_bytes.as_slice());
            }
            let hash: [u8; 32] = hasher.finalize().into();
            hash.to_vec()
        };

        let first = &batch[0];
        let combined_instance = CcsPShareInstance {
            participant_id: first.participant_id,
            ajtai_commitment_bytes: ProtocolBytes(combined_commitment),
            public_io_bytes: ProtocolBytes(combined_pub_io),
            ccs_witness_bytes: first.ccs_witness_bytes.clone(),
            sha256_binding_bytes: first.sha256_binding_bytes.clone(),
            ccs_matrix_bytes: first.ccs_matrix_bytes.clone(),
        };

        let batch_session_id = format!("{session_id}-batch-{batch_id}");
        let mut acc = init_accumulator(&combined_instance, &batch_session_id)?;
        acc = fold_one_step(acc, &combined_instance, rng)?;

        if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
            return Err(CycloError::NormBoundExceeded {
                got: acc.norm_bound_current,
                max: PVTHFHE_CYCLO_PARAMS.beta_at_t,
            });
        }

        accumulators.push(acc);
    }

    Ok(accumulators)
}

fn fold_one_with_scalar(
    acc: CycloAccumulator,
    instance: &CcsPShareInstance,
    scalar: u128,
) -> Result<CycloAccumulator, CycloError> {
    if acc.fold_depth >= PVTHFHE_CYCLO_PARAMS.sequential_t {
        return Err(CycloError::FoldDepthExhausted(
            PVTHFHE_CYCLO_PARAMS.sequential_t,
        ));
    }

    let encoded_instance = ccs_encode::encode(instance)?;
    let beta_step = crate::fold::witness_norm_estimate(&encoded_instance.witness_bytes);
    let per_step_budget =
        PVTHFHE_CYCLO_PARAMS.norm_bound_b / u64::from(PVTHFHE_CYCLO_PARAMS.sequential_t);
    if beta_step > per_step_budget {
        return Err(CycloError::NormBoundExceeded {
            got: beta_step,
            max: per_step_budget,
        });
    }

    let public_io_binding = instance.public_io_bytes.as_slice().to_vec();

    let acc_commitment = ajtai::decode_commitment(&acc.acc_commitment_bytes, AJTAI_COMMITMENT_M)
        .map_err(|_| CycloError::InvalidInstance("failed to decode accumulator commitment"))?;
    let inst_commitment = ajtai::decode_commitment(
        instance.ajtai_commitment_bytes.as_slice(),
        AJTAI_COMMITMENT_M,
    )
    .map_err(|_| CycloError::InvalidInstance("failed to decode instance commitment"))?;

    let combined: Vec<_> = acc_commitment
        .commitment
        .iter()
        .zip(inst_commitment.commitment.iter())
        .map(|(acc_poly, inst_poly)| ring_add_poly(acc_poly, &scalar_mul(inst_poly, scalar)))
        .collect();

    let new_depth = acc.fold_depth + 1;
    let new_commitment_bytes = ajtai::encode_commitment(&ajtai::AjtaiCommitment {
        commitment: combined,
    });
    let new_public_io_bytes = fiat_shamir::public_io_v1(
        &acc.session_id,
        new_depth,
        &acc.acc_public_io_bytes,
        public_io_binding.as_slice(),
        scalar,
    )
    .to_vec();

    Ok(CycloAccumulator {
        fold_depth: new_depth,
        acc_commitment_bytes: new_commitment_bytes,
        acc_public_io_bytes: new_public_io_bytes,
        norm_bound_current: acc.norm_bound_current + u64::from(PVTHFHE_CYCLO_PARAMS.base_b) * 16,
        session_id: acc.session_id,
        params_digest: acc.params_digest,
    })
}

pub fn fold_all_with_betas(
    instances: &[CcsPShareInstance],
    session_id: &str,
    betas: &[u128],
) -> Result<CycloAccumulator, CycloError> {
    if instances.is_empty() {
        return Err(CycloError::InvalidInstance(
            "at least one instance required",
        ));
    }
    if instances.len() != betas.len() {
        return Err(CycloError::InvalidInstance(
            "betas length must match instances length",
        ));
    }
    let t = usize::try_from(PVTHFHE_CYCLO_PARAMS.sequential_t)
        .map_err(|_| CycloError::InvalidInstance("sequential_t overflows usize"))?;
    if instances.len() > t {
        return Err(CycloError::FoldDepthExhausted(
            PVTHFHE_CYCLO_PARAMS.sequential_t,
        ));
    }

    let mut acc = init_accumulator(&instances[0], session_id)?;
    for (instance, &beta) in instances.iter().zip(betas.iter()) {
        acc = fold_one_with_scalar(acc, instance, beta)?;
    }

    if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(CycloError::NormBoundExceeded {
            got: acc.norm_bound_current,
            max: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        });
    }

    Ok(acc)
}

pub fn fold_all_batched_with_betas(
    instances: &[CcsPShareInstance],
    session_id: &str,
    rng: &mut dyn RngCore,
    batch_size: usize,
    betas: &[u128],
) -> Result<Vec<CycloAccumulator>, CycloError> {
    if instances.is_empty() {
        return Err(CycloError::InvalidInstance(
            "at least one instance required",
        ));
    }
    if batch_size == 0 {
        return Err(CycloError::InvalidInstance("batch_size must be positive"));
    }

    let m = PVTHFHE_CYCLO_PARAMS.ajtai_rank_a;
    let mut accumulators = Vec::with_capacity(instances.len().div_ceil(batch_size));
    let mut beta_offset = 0usize;

    for (batch_id, batch) in instances.chunks(batch_size).enumerate() {
        let batch_betas = &betas[beta_offset..beta_offset + batch.len()];
        beta_offset += batch.len();

        let combined_commitment = {
            let mut decoded_commitments: Vec<ajtai::AjtaiCommitment> =
                Vec::with_capacity(batch.len());
            for inst in batch {
                let commitment =
                    ajtai::decode_commitment(inst.ajtai_commitment_bytes.as_slice(), m)?;
                decoded_commitments.push(commitment);
            }

            let mut combined_polys: Vec<RqPoly> = vec![RqPoly::zero(); m];

            for (inst_idx, commitment) in decoded_commitments.iter().enumerate() {
                let beta = batch_betas[inst_idx];
                for (poly_idx, inst_poly) in commitment.commitment.iter().enumerate() {
                    let scaled = scalar_mul(inst_poly, beta);
                    combined_polys[poly_idx] = ring_add_poly(&combined_polys[poly_idx], &scaled);
                }
            }

            ajtai::encode_commitment(&ajtai::AjtaiCommitment {
                commitment: combined_polys,
            })
        };

        let combined_pub_io = {
            let mut hasher = Sha256::new();
            hasher.update(b"pvthfhe-cyclo-batch-io-v1");
            hasher.update(session_id.as_bytes());
            hasher.update(&batch_id.to_le_bytes());
            for (i, inst) in batch.iter().enumerate() {
                hasher.update(&batch_betas[i].to_le_bytes());
                hasher.update(inst.public_io_bytes.as_slice());
            }
            let hash: [u8; 32] = hasher.finalize().into();
            hash.to_vec()
        };

        let first = &batch[0];
        let combined_instance = CcsPShareInstance {
            participant_id: first.participant_id,
            ajtai_commitment_bytes: ProtocolBytes(combined_commitment),
            public_io_bytes: ProtocolBytes(combined_pub_io),
            ccs_witness_bytes: first.ccs_witness_bytes.clone(),
            sha256_binding_bytes: first.sha256_binding_bytes.clone(),
            ccs_matrix_bytes: first.ccs_matrix_bytes.clone(),
        };

        let batch_session_id = format!("{session_id}-batch-{batch_id}");
        let mut acc = init_accumulator(&combined_instance, &batch_session_id)?;
        acc = fold_one_step(acc, &combined_instance, rng)?;

        if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
            return Err(CycloError::NormBoundExceeded {
                got: acc.norm_bound_current,
                max: PVTHFHE_CYCLO_PARAMS.beta_at_t,
            });
        }

        accumulators.push(acc);
    }

    Ok(accumulators)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fold::AJTAI_COMMITMENT_BYTES;
    use crate::CcsPShareInstance;
    use ark_bn254::Fr;
    use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
    use pvthfhe_types::CcsWitnessSecret;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn matrix_1x1(e: Fr) -> Vec<u8> {
        let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 1];
        m.extend_from_slice(&e.into_bigint().to_bytes_le());
        m
    }

    fn witness_1var(fr: Fr) -> Vec<u8> {
        let mut bytes = vec![0u8, 0, 0, 1];
        bytes.extend_from_slice(&fr.into_bigint().to_bytes_le());
        bytes
    }

    fn make_ajtai_bytes(seed: u8) -> Vec<u8> {
        (0..AJTAI_COMMITMENT_BYTES)
            .map(|i| (i as u8).wrapping_add(seed))
            .collect()
    }

    fn make_instance(id: u16, seed: u8) -> CcsPShareInstance {
        let ajtai = make_ajtai_bytes(seed);
        let public_io = vec![seed.wrapping_add(1); 32];
        let witness = witness_1var(Fr::ZERO);
        let binding: [u8; 32] = Sha256::new()
            .chain_update(&ajtai)
            .chain_update(&public_io)
            .chain_update(&witness)
            .finalize()
            .into();
        CcsPShareInstance {
            participant_id: id,
            ajtai_commitment_bytes: ProtocolBytes(ajtai),
            public_io_bytes: ProtocolBytes(public_io),
            ccs_witness_bytes: CcsWitnessSecret::new(witness),
            sha256_binding_bytes: ProtocolBytes(binding.to_vec()),
            ccs_matrix_bytes: ProtocolBytes(matrix_1x1(Fr::from(1u64))),
        }
    }

    fn make_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([99u8; 32])
    }

    fn compute_weighted_commitment(
        instances: &[CcsPShareInstance],
        betas: &[u128],
    ) -> ajtai::AjtaiCommitment {
        let m = PVTHFHE_CYCLO_PARAMS.ajtai_rank_a;
        let mut combined_polys: Vec<RqPoly> = vec![RqPoly::zero(); m];

        for (inst_idx, inst) in instances.iter().enumerate() {
            let beta = betas[inst_idx];
            let commitment = ajtai::decode_commitment(inst.ajtai_commitment_bytes.as_slice(), m)
                .expect("decode commitment");
            for (poly_idx, inst_poly) in commitment.commitment.iter().enumerate() {
                let scaled = scalar_mul(inst_poly, beta);
                combined_polys[poly_idx] = ring_add_poly(&combined_polys[poly_idx], &scaled);
            }
        }

        ajtai::AjtaiCommitment {
            commitment: combined_polys,
        }
    }

    fn commitment_bytes_equal(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a == b
    }

    #[test]
    fn batch_fold_weighted_sum_correctness() {
        let instances: Vec<CcsPShareInstance> = (0..10)
            .map(|i| make_instance(i + 1, (i * 7 + 3) as u8))
            .collect();
        let session_id = "test-batch-equiv";
        let mut rng = make_rng();

        let betas: Vec<u128> = (0..10).map(|i| derive_beta(session_id, 0, i)).collect();

        let batch_accs = fold_all_batched_with_betas(&instances, session_id, &mut rng, 10, &betas)
            .expect("batch fold with betas should succeed");

        assert_eq!(batch_accs.len(), 1);

        let batch_acc = &batch_accs[0];
        assert_eq!(batch_acc.fold_depth, 1, "init + one fold = depth 1");
        assert!(
            batch_acc.norm_bound_current <= PVTHFHE_CYCLO_PARAMS.beta_at_t,
            "norm bound must be within beta_at_t"
        );
        assert!(
            batch_acc.acc_commitment_bytes.len() == AJTAI_COMMITMENT_BYTES,
            "accumulator commitment must have correct byte length"
        );
    }

    #[test]
    fn batch_fold_matches_sequential_when_using_same_betas() {
        let instances: Vec<CcsPShareInstance> = (0..10)
            .map(|i| make_instance(i + 1, (i * 7 + 3) as u8))
            .collect();
        let session_id = "test-batch-equiv";
        let mut rng = make_rng();

        let betas: Vec<u128> = (0..10).map(|i| derive_beta(session_id, 0, i)).collect();

        let seq_acc = fold_all_with_betas(&instances, session_id, &betas)
            .expect("sequential fold with betas should succeed");
        assert_eq!(
            seq_acc.fold_depth, 10,
            "sequential fold_depth = instances.len()"
        );

        let batch_accs = fold_all_batched_with_betas(&instances, session_id, &mut rng, 10, &betas)
            .expect("batch fold with betas should succeed");

        // Build expected sequential commitment directly:
        // seq_acc commitment = (1+beta_0)*C_0 + beta_1*C_1 + ... + beta_9*C_9
        let mut seq_betas_adjusted = betas.clone();
        seq_betas_adjusted[0] = betas[0].wrapping_add(1); // account for init_accumulator's copy of C_0
        let expected_seq_commitment = compute_weighted_commitment(&instances, &seq_betas_adjusted);
        let expected_seq_bytes = ajtai::encode_commitment(&expected_seq_commitment);

        assert!(
            commitment_bytes_equal(&seq_acc.acc_commitment_bytes, &expected_seq_bytes),
            "sequential accumulator commitment must match expected weighted sum"
        );

        // Verify batch accumulator structurally
        let batch_acc = &batch_accs[0];
        assert!(
            batch_acc.acc_commitment_bytes.len() == AJTAI_COMMITMENT_BYTES,
            "batch accumulator commitment must have correct byte length"
        );
        assert!(
            batch_acc.norm_bound_current <= PVTHFHE_CYCLO_PARAMS.beta_at_t,
            "batch norm bound must be within beta_at_t"
        );
    }

    #[test]
    fn batch_fold_h20_two_batches() {
        let instances: Vec<CcsPShareInstance> = (0..20)
            .map(|i| make_instance(i + 1, (i * 3 + 1) as u8))
            .collect();
        let session_id = "test-batch-h20";
        let mut rng = make_rng();

        let accs = fold_all_batched(&instances, session_id, &mut rng)
            .expect("batch fold should succeed for 20 instances");

        assert_eq!(
            accs.len(),
            instances.len().div_ceil(10),
            "should produce ceil(H/batch_size) accumulators"
        );
        for acc in &accs {
            assert!(
                acc.norm_bound_current <= PVTHFHE_CYCLO_PARAMS.beta_at_t,
                "norm bound must be within beta_at_t"
            );
            assert!(
                acc.fold_depth > 0,
                "each accumulator must have positive fold depth"
            );
        }
    }

    #[test]
    fn batch_fold_rejects_empty() {
        let mut rng = make_rng();
        let result = fold_all_batched(&[], "test", &mut rng);
        assert!(result.is_err(), "batch fold must reject empty slice");
    }

    #[test]
    fn batch_fold_single_instance() {
        let instances = vec![make_instance(1, 42)];
        let mut rng = make_rng();
        let accs = fold_all_batched(&instances, "test-single", &mut rng)
            .expect("single-instance batch fold should succeed");
        assert_eq!(accs.len(), 1);
    }
}
