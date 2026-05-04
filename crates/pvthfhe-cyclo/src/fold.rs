use crate::{
    ccs_encode,
    fiat_shamir,
    ring::{bytes_to_rqpoly, ring_add_poly, rqpoly_to_bytes, ternary_mul},
    CcsPShareInstance, CycloAccumulator, CycloError, PVTHFHE_CYCLO_PARAMS,
};
use rand_core::RngCore;

fn per_step_norm_budget() -> u64 {
    PVTHFHE_CYCLO_PARAMS.norm_bound_b / u64::from(PVTHFHE_CYCLO_PARAMS.sequential_t)
}

fn witness_norm_estimate(witness_bytes: &[u8]) -> u64 {
    witness_bytes
        .iter()
        .map(|&byte| u64::from(byte))
        .max()
        .unwrap_or(0)
}

fn derive_challenge(
    session_id: &str,
    fold_depth: u32,
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> i8 {
    let h = fiat_shamir::challenge_v1(
        session_id,
        fold_depth,
        acc_commitment,
        inst_ajtai_bytes,
        inst_public_io_bytes,
    );
    match h[0] % 3 {
        0 => 0,
        1 => 1,
        _ => -1,
    }
}

pub fn init_accumulator(
    instance: &CcsPShareInstance,
    session_id: &str,
) -> Result<CycloAccumulator, CycloError> {
    let init_poly = bytes_to_rqpoly(&instance.ajtai_commitment_bytes);
    let acc_commitment_bytes = fiat_shamir::init_commitment_v1(session_id, &rqpoly_to_bytes(&init_poly)).to_vec();
    let acc_public_io_bytes = fiat_shamir::init_public_io_v1(session_id, &instance.public_io_bytes).to_vec();

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
    if acc.fold_depth >= PVTHFHE_CYCLO_PARAMS.sequential_t {
        return Err(CycloError::FoldDepthExhausted(
            PVTHFHE_CYCLO_PARAMS.sequential_t,
        ));
    }

    let encoded_instance = ccs_encode::encode(instance)?;

    let beta_step = witness_norm_estimate(&encoded_instance.witness_bytes);
    let per_step_budget = per_step_norm_budget();
    if beta_step > per_step_budget {
        return Err(CycloError::NormBoundExceeded {
            got: beta_step,
            max: per_step_budget,
        });
    }

    let r = derive_challenge(
        &acc.session_id,
        acc.fold_depth,
        &acc.acc_commitment_bytes,
        &instance.ajtai_commitment_bytes,
        &instance.public_io_bytes,
    );

    let acc_poly = bytes_to_rqpoly(&acc.acc_commitment_bytes);
    let inst_poly = bytes_to_rqpoly(&instance.ajtai_commitment_bytes);
    let combined_poly = ring_add_poly(&acc_poly, &ternary_mul(&inst_poly, r));

    let new_depth = acc.fold_depth + 1;
    let new_commitment_bytes = fiat_shamir::commitment_v1(
        &acc.session_id,
        new_depth,
        &rqpoly_to_bytes(&combined_poly),
        &instance.ajtai_commitment_bytes,
    )
    .to_vec();

    let new_public_io_bytes = fiat_shamir::public_io_v1(
        &acc.session_id,
        new_depth,
        &acc.acc_public_io_bytes,
        &instance.public_io_bytes,
        r.to_le_bytes()[0],
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
    let expected_depth = u32::try_from(instances.len())
        .map_err(|_| CycloError::AccumulatorVerificationFailed("instance count exceeds u32"))?;
    if acc.fold_depth != expected_depth {
        return Err(CycloError::AccumulatorVerificationFailed(
            "fold_depth does not match number of instances",
        ));
    }

    if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(CycloError::AccumulatorVerificationFailed(
            "norm_bound_current exceeds beta_at_t",
        ));
    }

    if acc.acc_commitment_bytes.len() != 32 {
        return Err(CycloError::AccumulatorVerificationFailed(
            "acc_commitment_bytes must be 32 bytes",
        ));
    }

    if acc.acc_public_io_bytes.len() != 32 {
        return Err(CycloError::AccumulatorVerificationFailed(
            "acc_public_io_bytes must be 32 bytes",
        ));
    }

    if instances.is_empty() {
        return Ok(());
    }

    let mut recomputed = init_accumulator(&instances[0], &acc.session_id)?;
    for inst in instances {
        recomputed = fold_one_deterministic(recomputed, inst)?;
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
