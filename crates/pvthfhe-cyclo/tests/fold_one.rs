//! Integration tests for the Cyclo folding sub-protocol (F6).

use pvthfhe_cyclo::{
    fold::{fold_one_step, init_accumulator, verify_fold},
    CcsPShareInstance, PVTHFHE_CYCLO_PARAMS,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn make_instance(id: u16) -> CcsPShareInstance {
    let mut binding = [0u8; 32];
    binding[0] = id as u8;
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: vec![id as u8; 32],
        public_io_bytes: vec![id as u8 ^ 0xAA; 32],
        ccs_witness_bytes: vec![1u8; 32],
        sha256_binding_bytes: binding.to_vec(),
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
