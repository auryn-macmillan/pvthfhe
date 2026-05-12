use pvthfhe_cyclo::{
    fold::{verify_fold, AJTAI_COMMITMENT_BYTES},
    CcsPShareInstance, CycloAccumulator, PVTHFHE_CYCLO_PARAMS,
};
use pvthfhe_types::CcsWitnessSecret;

fn trivial_matrix() -> Vec<u8> {
    let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 1];
    m.extend_from_slice(&[0u8; 32]);
    m
}

fn make_accumulator_at_depth(depth: u32, session_id: &str) -> CycloAccumulator {
    CycloAccumulator {
        fold_depth: depth,
        acc_commitment_bytes: vec![0u8; AJTAI_COMMITMENT_BYTES],
        acc_public_io_bytes: vec![0u8; 32],
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.norm_bound_b,
        session_id: session_id.to_owned(),
        params_digest: [0u8; 32],
    }
}

#[test]
fn oversized_instance_bytes_rejected() {
    let instance = CcsPShareInstance {
        participant_id: 1,
        ajtai_commitment_bytes: vec![0u8; AJTAI_COMMITMENT_BYTES].into(),
        public_io_bytes: vec![0u8; 4097].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(vec![0u8, 0, 0, 0]),
        sha256_binding_bytes: vec![0u8; 32].into(),
        ccs_matrix_bytes: trivial_matrix().into(),
    };
    let acc = make_accumulator_at_depth(1, "dos-test");
    let result = verify_fold(&acc, &[instance]);
    assert!(
        result.is_err(),
        "oversized public_io_bytes must be rejected"
    );
}

#[test]
fn oversized_ajtai_commitment_bytes_rejected() {
    let instance = CcsPShareInstance {
        participant_id: 1,
        ajtai_commitment_bytes: vec![0u8; 29300].into(),
        public_io_bytes: vec![0u8; 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(vec![0u8, 0, 0, 0]),
        sha256_binding_bytes: vec![0u8; 32].into(),
        ccs_matrix_bytes: trivial_matrix().into(),
    };
    let acc = make_accumulator_at_depth(1, "dos-test");
    let result = verify_fold(&acc, &[instance]);
    assert!(
        result.is_err(),
        "oversized ajtai_commitment_bytes must be rejected"
    );
}
