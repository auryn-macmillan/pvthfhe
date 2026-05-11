//! R4.8 Fold soundness regression test.
//!
//! Verifies that `verify_fold` rejects tampered fold instances, exercising
//! the real Cyclo `check_satisfiability` path (`M·z ⊙ z == 0`).

use pvthfhe_cyclo::{fold, CcsPShareInstance};
use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};
use rand_core::OsRng;

fn build_matrix_1x1(element_limbs: [u64; 4]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    for limb in element_limbs {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn build_zero_witness(num_vars: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + num_vars * 32);
    bytes.extend_from_slice(&u32::try_from(num_vars).unwrap().to_be_bytes());
    for _ in 0..num_vars {
        bytes.extend_from_slice(&[0u8; 32]);
    }
    bytes
}

fn build_witness_with_one(num_vars: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + num_vars * 32);
    bytes.extend_from_slice(&u32::try_from(num_vars).unwrap().to_be_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    for _ in 1..num_vars {
        bytes.extend_from_slice(&[0u8; 32]);
    }
    bytes
}

fn make_instance(
    participant_id: u16,
    ajtai_bytes: Vec<u8>,
    public_io_bytes: Vec<u8>,
    ccs_witness_bytes: Vec<u8>,
    binding: [u8; 32],
    ccs_matrix_bytes: Vec<u8>,
) -> CcsPShareInstance {
    CcsPShareInstance {
        participant_id,
        ajtai_commitment_bytes: ProtocolBytes(ajtai_bytes),
        public_io_bytes: ProtocolBytes(public_io_bytes),
        ccs_witness_bytes: CcsWitnessSecret::new(ccs_witness_bytes),
        sha256_binding_bytes: ProtocolBytes(binding.to_vec()),
        ccs_matrix_bytes: ProtocolBytes(ccs_matrix_bytes),
    }
}

fn make_two_valid_instances(
    matrix: &[u8],
    witness: &[u8],
) -> (CcsPShareInstance, CcsPShareInstance) {
    let inst1 = make_instance(
        1,
        vec![0xAA; 32],
        vec![0xBB; 32],
        witness.to_vec(),
        [0x11; 32],
        matrix.to_vec(),
    );
    let inst2 = make_instance(
        2,
        vec![0xCC; 32],
        vec![0xDD; 32],
        witness.to_vec(),
        [0x22; 32],
        matrix.to_vec(),
    );
    (inst1, inst2)
}

fn fold_two(
    inst1: &CcsPShareInstance,
    inst2: &CcsPShareInstance,
    session_id: &str,
) -> pvthfhe_cyclo::CycloAccumulator {
    let mut rng = OsRng;
    let acc = fold::init_accumulator(inst1, session_id).expect("init_accumulator");
    let acc = fold::fold_one_step(acc, inst1, &mut rng).expect("fold step 1");
    fold::fold_one_step(acc, inst2, &mut rng).expect("fold step 2")
}

fn fold_one(
    inst: &CcsPShareInstance,
    session_id: &str,
) -> pvthfhe_cyclo::CycloAccumulator {
    let mut rng = OsRng;
    let acc = fold::init_accumulator(inst, session_id).expect("init_accumulator");
    fold::fold_one_step(acc, inst, &mut rng).expect("fold step")
}

#[test]
fn verify_fold_rejects_tampered_witness() {
    let matrix = build_matrix_1x1([1, 0, 0, 0]);
    let valid_witness = build_zero_witness(1);

    let (inst1, inst2) = make_two_valid_instances(&matrix, &valid_witness);
    let acc = fold_two(&inst1, &inst2, "soundness-test");

    fold::verify_fold(&acc, &[inst1, inst2])
        .expect("verify_fold must accept honest instances");

    let tampered_witness = build_witness_with_one(1);
    let (inst1b, _) = make_two_valid_instances(&matrix, &valid_witness);
    let tampered_inst2 = make_instance(
        2,
        vec![0xCC; 32],
        vec![0xDD; 32],
        tampered_witness,
        [0x22; 32],
        matrix.clone(),
    );

    let result = fold::verify_fold(&acc, &[inst1b, tampered_inst2]);
    assert!(
        result.is_err(),
        "verify_fold must reject tampered witness (M·z ⊙ z ≠ 0)"
    );
}

#[test]
fn verify_fold_rejects_tampered_commitment() {
    let zero_matrix = build_matrix_1x1([0, 0, 0, 0]);
    let valid_witness = build_zero_witness(1);

    let inst1 = make_instance(
        1,
        vec![0xAA; 32],
        vec![0xBB; 32],
        valid_witness.clone(),
        [0x11; 32],
        zero_matrix.clone(),
    );
    let acc = fold_one(&inst1, "soundness-test-2");

    fold::verify_fold(&acc, &[inst1])
        .expect("verify_fold must accept honest single-instance fold");

    let tampered = make_instance(
        1,
        vec![0xFF; 32],
        vec![0xBB; 32],
        valid_witness,
        [0x11; 32],
        zero_matrix,
    );

    let result = fold::verify_fold(&acc, &[tampered]);
    assert!(
        result.is_err(),
        "verify_fold must reject tampered ajtai commitment"
    );
}

#[test]
fn verify_fold_rejects_tampered_public_io() {
    let zero_matrix = build_matrix_1x1([0, 0, 0, 0]);
    let valid_witness = build_zero_witness(1);

    let inst1 = make_instance(
        1,
        vec![0xAA; 32],
        vec![0xBB; 32],
        valid_witness.clone(),
        [0x11; 32],
        zero_matrix.clone(),
    );
    let acc = fold_one(&inst1, "soundness-test-3");

    fold::verify_fold(&acc, &[inst1])
        .expect("verify_fold must accept honest single-instance fold");

    let tampered = make_instance(
        1,
        vec![0xAA; 32],
        vec![0xEE; 32],
        valid_witness,
        [0x11; 32],
        zero_matrix,
    );

    let result = fold::verify_fold(&acc, &[tampered]);
    assert!(
        result.is_err(),
        "verify_fold must reject tampered public I/O"
    );
}

#[test]
fn verify_fold_rejects_wrong_fold_depth() {
    let zero_matrix = build_matrix_1x1([0, 0, 0, 0]);
    let valid_witness = build_zero_witness(1);

    let inst1 = make_instance(
        1,
        vec![0xAA; 32],
        vec![0xBB; 32],
        valid_witness.clone(),
        [0x11; 32],
        zero_matrix.clone(),
    );
    let inst2 = make_instance(
        2,
        vec![0xCC; 32],
        vec![0xDD; 32],
        valid_witness,
        [0x22; 32],
        zero_matrix,
    );

    let acc = fold_one(&inst1, "soundness-test-4");

    let result = fold::verify_fold(&acc, &[inst1, inst2]);
    assert!(
        result.is_err(),
        "verify_fold must reject when fold_depth does not match instance count"
    );
}
