//! Integration tests for the Cyclo folding sub-protocol (F6).

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{
    fold::{fold_one_step, init_accumulator, verify_fold},
    CcsPShareInstance, PVTHFHE_CYCLO_PARAMS,
};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// 1×1 CCS matrix with element `e`.
fn matrix_1x1(e: Fr) -> Vec<u8> {
    let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 1]; // rows=1, cols=1
    m.extend_from_slice(&e.into_bigint().to_bytes_le());
    m
}

/// Witness wire-format: one variable.
fn witness_1var(fr: Fr) -> Vec<u8> {
    let mut bytes = vec![0u8, 0, 0, 1]; // num_vars=1
    bytes.extend_from_slice(&fr.into_bigint().to_bytes_le());
    bytes
}

fn good_matrix() -> Vec<u8> {
    matrix_1x1(Fr::from(1u64))
}

fn good_witness() -> Vec<u8> {
    witness_1var(Fr::ZERO)
}

fn make_instance(id: u16) -> CcsPShareInstance {
    let mut binding = [0u8; 32];
    binding[0] = id as u8;
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: vec![id as u8; 32].into(),
        public_io_bytes: vec![id as u8 ^ 0xAA; 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(good_witness()),
        sha256_binding_bytes: binding.to_vec().into(),
        ccs_matrix_bytes: good_matrix().into(),
    }
}

fn make_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([42u8; 32])
}

/// RED: stub returns Err — this test will FAIL until fold is implemented.
#[test]
fn fold_produces_incremented_depth() {
    let instance = make_instance(1);
    let mut rng = make_rng();
    let acc = init_accumulator(&instance, "test-session").expect("init_accumulator failed");
    let new_acc = fold_one_step(acc, &instance, &mut rng).expect("fold_one_step failed");
    assert_eq!(new_acc.fold_depth, 1);
}

#[test]
fn fold_commitment_is_32_bytes() {
    let instance = make_instance(1);
    let mut rng = make_rng();
    let acc = init_accumulator(&instance, "test-session").expect("init_accumulator failed");
    let new_acc = fold_one_step(acc, &instance, &mut rng).expect("fold_one_step failed");
    assert_eq!(new_acc.acc_commitment_bytes.len(), 32);
}

#[test]
fn fold_norm_grows_correctly() {
    let instance = make_instance(1);
    let mut rng = make_rng();
    let acc = init_accumulator(&instance, "test-session").expect("init_accumulator failed");
    let prev_norm = acc.norm_bound_current;
    let new_acc = fold_one_step(acc, &instance, &mut rng).expect("fold_one_step failed");
    let expected = prev_norm + PVTHFHE_CYCLO_PARAMS.base_b as u64 * 16;
    assert_eq!(new_acc.norm_bound_current, expected);
}

#[test]
fn fold_verify_accepts_honest() {
    let instance = make_instance(1);
    let mut rng = make_rng();
    let acc = init_accumulator(&instance, "test-session").expect("init_accumulator failed");
    let new_acc = fold_one_step(acc, &instance, &mut rng).expect("fold_one_step failed");
    verify_fold(&new_acc, &[make_instance(1)]).expect("verify_fold should accept honest fold");
}

#[test]
fn fold_one_rejects_tampered_accumulator() {
    let instance = make_instance(1);
    let mut rng = make_rng();
    let acc = init_accumulator(&instance, "test-session").expect("init_accumulator failed");
    let mut new_acc = fold_one_step(acc, &instance, &mut rng).expect("fold_one_step failed");
    new_acc.acc_commitment_bytes[0] ^= 0xFF;
    let result = verify_fold(&new_acc, &[make_instance(1)]);
    assert!(
        result.is_err(),
        "verify_fold must reject tampered accumulator"
    );
}

#[test]
fn fold_depth_exhaustion() {
    let mut rng = make_rng();
    let instance = make_instance(1);
    let mut acc = init_accumulator(&instance, "test-session").expect("init_accumulator failed");
    for _ in 0..PVTHFHE_CYCLO_PARAMS.sequential_t {
        acc = fold_one_step(acc, &make_instance(1), &mut rng).expect("fold step failed");
    }
    let result = fold_one_step(acc, &make_instance(1), &mut rng);
    assert!(
        matches!(
            result,
            Err(pvthfhe_cyclo::CycloError::FoldDepthExhausted(_))
        ),
        "expected FoldDepthExhausted error"
    );
}
