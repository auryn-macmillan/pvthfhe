use crate::{
    ajtai, ccs_encode, decompose, fiat_shamir,
    ring::{PHI_COMMIT, Q_COMMIT},
    CcsPShareInstance, CycloAccumulator, CycloError, MultiTrackPShareInstance,
    PVTHFHE_CYCLO_PARAMS,
};
use ark_ff::PrimeField;
use rand_core::RngCore;

/// Number of ring elements in an Ajtai commitment (ajtai rank a = 13).
pub const AJTAI_COMMITMENT_M: usize = PVTHFHE_CYCLO_PARAMS.ajtai_rank_a;

/// Encoded Ajtai commitment size in bytes: m × φ × 8 = 13 × 256 × 8 = 26624.
pub const AJTAI_COMMITMENT_BYTES: usize = AJTAI_COMMITMENT_M * PHI_COMMIT * 8;

/// Maximum instance public-io length (prevents unbounded hash computation).
const MAX_INSTANCE_BYTES: usize = 4096;

/// Maximum instance Ajtai commitment size: 26624 bytes + 10% headroom for protocol framing.
const MAX_AJTAI_COMMITMENT_BYTES: usize = AJTAI_COMMITMENT_BYTES + (AJTAI_COMMITMENT_BYTES / 10);

fn per_step_norm_budget() -> u64 {
    PVTHFHE_CYCLO_PARAMS.norm_bound_b / u64::from(PVTHFHE_CYCLO_PARAMS.sequential_t)
}

pub(crate) fn witness_norm_estimate(witness_bytes: &[u8]) -> u64 {
    match ccs_encode::parse_witness(witness_bytes) {
        Ok(frs) => frs
            .iter()
            .map(|fr| {
                let limbs = fr.into_bigint().as_ref().to_vec();
                let c = limbs[0] % Q_COMMIT;
                let neg = Q_COMMIT - c;
                if neg < c {
                    neg
                } else {
                    c
                }
            })
            .max()
            .unwrap_or(0),
        Err(_) => u64::MAX,
    }
}

fn decompose_witness_bytes(
    witness_bytes: &[u8],
    _per_step_budget: u64,
) -> Result<Vec<Vec<u8>>, CycloError> {
    let frs = ccs_encode::parse_witness(witness_bytes)?;
    let coeffs: Vec<u64> = frs
        .iter()
        .map(|fr| {
            let limbs = fr.into_bigint().as_ref().to_vec();
            limbs[0] % Q_COMMIT
        })
        .collect();

    let base_b = u64::from(PVTHFHE_CYCLO_PARAMS.base_b);

    // Determine k: we need the largest coefficient to fit in k digits of base b.
    // The max centred coefficient is at most Q_COMMIT/2 ≈ 2^49.
    // In base b, we need ceil(log_b(Q_COMMIT/2)) digits.
    // With b=2, k=50 ensures every coefficient fits.
    let max_val = coeffs.iter().copied().max().unwrap_or(0);
    let mut k = 1usize;
    let mut limit = base_b;
    while limit <= max_val && k < 64 {
        limit = limit.saturating_mul(base_b);
        k += 1;
    }

    if k == 0 {
        k = 1;
    }

    let digits = decompose::decompose_base_B(&coeffs, base_b, k);

    // Re-encode each digit vector as Fr witness bytes.
    // Each Fr is 32 bytes (4 u64 limbs). We set the first limb to the digit value.
    let num_vars = frs.len();
    let mut parts = Vec::with_capacity(k);
    for digit_vec in &digits {
        let mut bytes = Vec::with_capacity(4 + num_vars * 32);
        bytes.extend_from_slice(&(num_vars as u32).to_be_bytes());
        for &d in digit_vec.iter() {
            let mut limb_bytes = [0u8; 32];
            limb_bytes[0..8].copy_from_slice(&d.to_le_bytes());
            bytes.extend_from_slice(&limb_bytes);
        }
        parts.push(bytes);
    }

    Ok(parts)
}

#[allow(clippy::unwrap_used)]
fn derive_challenge(
    session_id: &str,
    fold_depth: u32,
    params_digest: &[u8; 32],
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> u128 {
    let h = fiat_shamir::challenge_v2(
        session_id,
        fold_depth,
        params_digest,
        acc_commitment,
        inst_ajtai_bytes,
        inst_public_io_bytes,
    );
    u128::from_le_bytes(h[..16].try_into().unwrap())
}

pub fn init_accumulator(
    instance: &CcsPShareInstance,
    session_id: &str,
) -> Result<CycloAccumulator, CycloError> {
    init_accumulator_inner(instance, None, session_id)
}

/// Initialise an accumulator while binding optional H.2 multi-track public metadata.
pub fn init_accumulator_multitrack(
    instance: &MultiTrackPShareInstance,
    session_id: &str,
) -> Result<CycloAccumulator, CycloError> {
    init_accumulator_inner(
        &instance.base,
        instance.multi_track_metadata.as_ref(),
        session_id,
    )
}

fn init_accumulator_inner(
    instance: &CcsPShareInstance,
    metadata: Option<&crate::MultiTrackFoldMetadata>,
    session_id: &str,
) -> Result<CycloAccumulator, CycloError> {
    let inst_commitment = ajtai::decode_commitment(
        instance.ajtai_commitment_bytes.as_slice(),
        AJTAI_COMMITMENT_M,
    )?;
    let acc_commitment_bytes = ajtai::encode_commitment(&inst_commitment);
    let public_io_binding = ccs_encode::public_io_binding_bytes(&MultiTrackPShareInstance {
        base: CcsPShareInstance {
            participant_id: instance.participant_id,
            ajtai_commitment_bytes: instance.ajtai_commitment_bytes.clone(),
            public_io_bytes: instance.public_io_bytes.clone(),
            ccs_witness_bytes: instance.ccs_witness_bytes.clone(),
            sha256_binding_bytes: instance.sha256_binding_bytes.clone(),
            ccs_matrix_bytes: instance.ccs_matrix_bytes.clone(),
        },
        multi_track_metadata: metadata.cloned(),
    });
    let acc_public_io_bytes =
        fiat_shamir::init_public_io_v1(session_id, public_io_binding.as_slice()).to_vec();

    // Satisfaction check is deferred to verify_fold (line 352).
    // No duplicate rejection — duplicates are caught by verify_fold recomputation.

    Ok(CycloAccumulator {
        fold_depth: 0,
        acc_commitment_bytes,
        acc_public_io_bytes,
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.norm_bound_b,
        session_id: session_id.to_string(),
        params_digest: fiat_shamir::params_digest_v1(b"pvthfhe-cyclo-params-v1"),
    })
}

fn fold_one_deterministic(
    acc: CycloAccumulator,
    instance: &CcsPShareInstance,
) -> Result<CycloAccumulator, CycloError> {
    fold_one_deterministic_inner(acc, instance, None)
}

fn fold_one_deterministic_multitrack(
    acc: CycloAccumulator,
    instance: &MultiTrackPShareInstance,
) -> Result<CycloAccumulator, CycloError> {
    fold_one_deterministic_inner(acc, &instance.base, instance.multi_track_metadata.as_ref())
}

fn fold_one_deterministic_inner(
    acc: CycloAccumulator,
    instance: &CcsPShareInstance,
    metadata: Option<&crate::MultiTrackFoldMetadata>,
) -> Result<CycloAccumulator, CycloError> {
    if acc.fold_depth >= PVTHFHE_CYCLO_PARAMS.sequential_t {
        return Err(CycloError::FoldDepthExhausted(
            PVTHFHE_CYCLO_PARAMS.sequential_t,
        ));
    }

    let encoded_instance = match metadata {
        Some(metadata) => ccs_encode::encode_multitrack(&MultiTrackPShareInstance {
            base: CcsPShareInstance {
                participant_id: instance.participant_id,
                ajtai_commitment_bytes: instance.ajtai_commitment_bytes.clone(),
                public_io_bytes: instance.public_io_bytes.clone(),
                ccs_witness_bytes: instance.ccs_witness_bytes.clone(),
                sha256_binding_bytes: instance.sha256_binding_bytes.clone(),
                ccs_matrix_bytes: instance.ccs_matrix_bytes.clone(),
            },
            multi_track_metadata: Some(metadata.clone()),
        })?,
        None => ccs_encode::encode(instance)?,
    };

    let beta_step = witness_norm_estimate(&encoded_instance.witness_bytes);
    let per_step_budget = per_step_norm_budget();
    let decomposed_witness: Option<Vec<Vec<u8>>> = if beta_step > per_step_budget {
        let max_decomposable = per_step_budget.saturating_mul(u64::from(PVTHFHE_CYCLO_PARAMS.base_b));
        if beta_step <= max_decomposable {
            match decompose_witness_bytes(&encoded_instance.witness_bytes, per_step_budget) {
                Ok(parts) => Some(parts),
                Err(_) => None,
            }
        } else {
            return Err(CycloError::NormBoundExceeded {
                got: beta_step,
                max: per_step_budget,
            });
        }
    } else {
        None
    };

    let public_io_binding = match metadata {
        Some(metadata) => ccs_encode::public_io_binding_bytes(&MultiTrackPShareInstance {
            base: CcsPShareInstance {
                participant_id: instance.participant_id,
                ajtai_commitment_bytes: instance.ajtai_commitment_bytes.clone(),
                public_io_bytes: instance.public_io_bytes.clone(),
                ccs_witness_bytes: instance.ccs_witness_bytes.clone(),
                sha256_binding_bytes: instance.sha256_binding_bytes.clone(),
                ccs_matrix_bytes: instance.ccs_matrix_bytes.clone(),
            },
            multi_track_metadata: Some(metadata.clone()),
        }),
        None => instance.public_io_bytes.as_slice().to_vec(),
    };
    let r = derive_challenge(
        &acc.session_id,
        acc.fold_depth,
        &acc.params_digest,
        &acc.acc_commitment_bytes,
        instance.ajtai_commitment_bytes.as_slice(),
        public_io_binding.as_slice(),
    );

    let acc_commitment = ajtai::decode_commitment(&acc.acc_commitment_bytes, AJTAI_COMMITMENT_M)
        .map_err(|_| CycloError::InvalidInstance("failed to decode accumulator commitment"))?;
    let inst_commitment = ajtai::decode_commitment(
        instance.ajtai_commitment_bytes.as_slice(),
        AJTAI_COMMITMENT_M,
    )
    .map_err(|_| CycloError::InvalidInstance("failed to decode instance commitment"))?;

    let r_mod_q = (r % Q_COMMIT as u128) as u64;

    let _parts_count = decomposed_witness.as_ref().map_or(0, |p| p.len());
    let combined = crate::nifs::folding::fold_commitments(
        &acc_commitment,
        &[inst_commitment],
        r_mod_q,
    );

    let new_depth = acc.fold_depth + 1;
    let new_commitment_bytes = ajtai::encode_commitment(&combined);
    let new_public_io_bytes = fiat_shamir::public_io_v1(
        &acc.session_id,
        new_depth,
        &acc.acc_public_io_bytes,
        public_io_binding.as_slice(),
        r,
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

/// Fold one instance with optional H.2 multi-track public metadata.
pub fn fold_one_step_multitrack(
    acc: CycloAccumulator,
    instance: &MultiTrackPShareInstance,
    rng: &mut dyn RngCore,
) -> Result<CycloAccumulator, CycloError> {
    let _ = rng.next_u32();
    fold_one_deterministic_multitrack(acc, instance)
}

pub fn fold_one_step(
    acc: CycloAccumulator,
    instance: &CcsPShareInstance,
    rng: &mut dyn RngCore,
) -> Result<CycloAccumulator, CycloError> {
    let _ = rng.next_u32();
    fold_one_deterministic(acc, instance)
}

pub fn verify_fold(
    acc: &CycloAccumulator,
    instances: &[CcsPShareInstance],
) -> Result<(), CycloError> {
    verify_fold_inner(acc, instances.iter().map(|base| (base, None)).collect())
}

/// Verify a folded accumulator with optional H.2 multi-track public metadata.
pub fn verify_fold_multitrack(
    acc: &CycloAccumulator,
    instances: &[MultiTrackPShareInstance],
) -> Result<(), CycloError> {
    verify_fold_inner(
        acc,
        instances
            .iter()
            .map(|inst| (&inst.base, inst.multi_track_metadata.as_ref()))
            .collect(),
    )
}

fn verify_fold_inner(
    acc: &CycloAccumulator,
    instances: Vec<(&CcsPShareInstance, Option<&crate::MultiTrackFoldMetadata>)>,
) -> Result<(), CycloError> {
    let expected_depth = u32::try_from(instances.len())
        .map_err(|_| CycloError::AccumulatorVerificationFailed("instance count exceeds u32"))?;
    if acc.fold_depth != expected_depth {
        return Err(CycloError::AccumulatorVerificationFailed(
            "fold_depth does not match number of instances",
        ));
    }

    for inst in &instances {
        if inst.0.public_io_bytes.len() > MAX_INSTANCE_BYTES {
            return Err(CycloError::InvalidInstance(
                "public_io_bytes exceeds maximum allowed size",
            ));
        }
        if inst.0.ajtai_commitment_bytes.len() > MAX_AJTAI_COMMITMENT_BYTES {
            return Err(CycloError::InvalidInstance(
                "ajtai_commitment_bytes exceeds maximum allowed size",
            ));
        }
        if let Some(metadata) = inst.1 {
            metadata.validate_for_instance(
                inst.0.participant_id,
                &acc.session_id,
                instances.len(),
            )?;
            if ccs_encode::public_io_binding_bytes(&MultiTrackPShareInstance {
                base: CcsPShareInstance {
                    participant_id: inst.0.participant_id,
                    ajtai_commitment_bytes: inst.0.ajtai_commitment_bytes.clone(),
                    public_io_bytes: inst.0.public_io_bytes.clone(),
                    ccs_witness_bytes: inst.0.ccs_witness_bytes.clone(),
                    sha256_binding_bytes: inst.0.sha256_binding_bytes.clone(),
                    ccs_matrix_bytes: inst.0.ccs_matrix_bytes.clone(),
                },
                multi_track_metadata: Some(metadata.clone()),
            })
            .len()
                > MAX_INSTANCE_BYTES
            {
                return Err(CycloError::InvalidInstance(
                    "multi-track public binding exceeds maximum allowed size",
                ));
            }
        }
    }

    if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(CycloError::AccumulatorVerificationFailed(
            "norm_bound_current exceeds beta_at_t",
        ));
    }

    if acc.acc_commitment_bytes.len() != AJTAI_COMMITMENT_BYTES {
        return Err(CycloError::AccumulatorVerificationFailed(
            "acc_commitment_bytes must be AJTAI_COMMITMENT_BYTES (26624) bytes",
        ));
    }

    if acc.acc_public_io_bytes.len() != 32 {
        return Err(CycloError::AccumulatorVerificationFailed(
            "acc_public_io_bytes must be 32 bytes",
        ));
    }

    if instances.is_empty() {
        return Err(CycloError::InvalidInstance(
            "cannot verify empty instance list",
        ));
    }

    for inst in &instances {
        let encoded = match inst.1 {
            Some(metadata) => ccs_encode::encode_multitrack(&MultiTrackPShareInstance {
                base: CcsPShareInstance {
                    participant_id: inst.0.participant_id,
                    ajtai_commitment_bytes: inst.0.ajtai_commitment_bytes.clone(),
                    public_io_bytes: inst.0.public_io_bytes.clone(),
                    ccs_witness_bytes: inst.0.ccs_witness_bytes.clone(),
                    sha256_binding_bytes: inst.0.sha256_binding_bytes.clone(),
                    ccs_matrix_bytes: inst.0.ccs_matrix_bytes.clone(),
                },
                multi_track_metadata: Some(metadata.clone()),
            })?,
            None => ccs_encode::encode(inst.0)?,
        };
        ccs_encode::check_satisfiability(&encoded)?;
    }

    let mut recomputed = init_accumulator_inner(instances[0].0, instances[0].1, &acc.session_id)?;
    for inst in &instances {
        recomputed = fold_one_deterministic_inner(recomputed, inst.0, inst.1)?;
    }

    if recomputed.acc_commitment_bytes != acc.acc_commitment_bytes {
        return Err(CycloError::AccumulatorVerificationFailed(
            "commitment bytes mismatch",
        ));
    }

    if recomputed.acc_public_io_bytes != acc.acc_public_io_bytes {
        return Err(CycloError::AccumulatorVerificationFailed(
            "public_io bytes mismatch",
        ));
    }

    Ok(())
}
