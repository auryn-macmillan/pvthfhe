//! Folding sub-protocol (Cyclo §6, T3).
//!
//! Provides `init_accumulator`, `fold_one_step`, and `verify_fold` for the
//! Cyclo LatticeFold+ sequential folding of [`CcsPShareInstance`] values into a
//! [`CycloAccumulator`].

use crate::{
    ccs_encode::{self, CcsInstance},
    extension, CcsPShareInstance, CycloAccumulator, CycloError, PVTHFHE_CYCLO_PARAMS,
};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

fn params_digest() -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-params-v1")
        .finalize()
        .into()
}

/// Derives a ternary Fiat-Shamir challenge from the current accumulator
/// commitment and the incoming instance ajtai hash.
fn derive_challenge(acc_commitment: &[u8], instance_ajtai: &[u8; 32]) -> i8 {
    let h: [u8; 32] = Sha256::new()
        .chain_update(acc_commitment)
        .chain_update(instance_ajtai)
        .finalize()
        .into();
    match h[0] % 3 {
        0 => 0,
        1 => 1,
        _ => -1,
    }
}

/// Initialises a fresh [`CycloAccumulator`] from the first [`CcsPShareInstance`].
///
/// Sets `fold_depth = 0`, computes initial commitment as
/// `SHA256("init" ∥ instance.ajtai_commitment_bytes)`, initial public_io as
/// `SHA256("init" ∥ instance.public_io_bytes)`, and norm bound =
/// `PVTHFHE_CYCLO_PARAMS.norm_bound_b`.
pub fn init_accumulator(
    instance: &CcsPShareInstance,
    session_id: &str,
) -> Result<CycloAccumulator, CycloError> {
    let acc_commitment_bytes: Vec<u8> = Sha256::new()
        .chain_update(b"init")
        .chain_update(&instance.ajtai_commitment_bytes)
        .finalize()
        .to_vec();

    let acc_public_io_bytes: Vec<u8> = Sha256::new()
        .chain_update(b"init")
        .chain_update(&instance.public_io_bytes)
        .finalize()
        .to_vec();

    Ok(CycloAccumulator {
        fold_depth: 0,
        acc_commitment_bytes,
        acc_public_io_bytes,
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.norm_bound_b,
        session_id: session_id.to_string(),
        params_digest: params_digest(),
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

    let r = derive_challenge(&acc.acc_commitment_bytes, &encoded_instance.ajtai_hash);

    let acc_ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(&acc.acc_commitment_bytes)
        .finalize()
        .into();

    let acc_public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(&acc.acc_public_io_bytes)
        .finalize()
        .into();

    let acc_as_ccs = CcsInstance {
        participant_id: 0,
        ajtai_hash: acc_ajtai_hash,
        public_io_hash: acc_public_io_hash,
        sha256_binding: [0u8; 32],
        witness_bytes: acc.acc_commitment_bytes.clone(),
    };

    let ext = extension::extend(&acc_as_ccs, &encoded_instance, r)?;

    Ok(CycloAccumulator {
        fold_depth: acc.fold_depth + 1,
        acc_commitment_bytes: ext.combined_ajtai_hash.to_vec(),
        acc_public_io_bytes: ext.combined_public_io_hash.to_vec(),
        norm_bound_current: acc.norm_bound_current + u64::from(PVTHFHE_CYCLO_PARAMS.base_b) * 16,
        session_id: acc.session_id,
        params_digest: acc.params_digest,
    })
}

/// Folds `instance` into `acc`, producing a new accumulator.
///
/// Returns `Err(FoldDepthExhausted)` if all T steps are consumed.
pub fn fold_one_step(
    acc: CycloAccumulator,
    instance: &CcsPShareInstance,
    rng: &mut dyn RngCore,
) -> Result<CycloAccumulator, CycloError> {
    let _ = rng.next_u32();
    fold_one_deterministic(acc, instance)
}

/// Verifies that `acc` represents a valid fold over `instances`.
///
/// Checks:
/// 1. `acc.fold_depth == instances.len() as u32`.
/// 2. `acc.norm_bound_current ≤ PVTHFHE_CYCLO_PARAMS.beta_at_t` (1344).
/// 3. `acc.acc_commitment_bytes.len() == 32`.
/// 4. `acc.acc_public_io_bytes.len() == 32`.
///
/// Returns `Ok(())` if all checks pass, `Err(AccumulatorVerificationFailed(...))` otherwise.
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
