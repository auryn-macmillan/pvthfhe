use pvthfhe_cyclo::{fold::verify_fold, CcsPShareInstance, CycloAccumulator, PVTHFHE_CYCLO_PARAMS};

fn make_accumulator_at_depth(depth: u32, session_id: &str) -> CycloAccumulator {
    CycloAccumulator {
        fold_depth: depth,
        acc_commitment_bytes: vec![0u8; 32],
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
        ajtai_commitment_bytes: vec![0u8; 32],
        public_io_bytes: vec![0u8; 4097],
        ccs_witness_bytes: vec![0u8; 32],
        sha256_binding_bytes: vec![0u8; 32],
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
        ajtai_commitment_bytes: vec![0u8; 4097],
        public_io_bytes: vec![0u8; 32],
        ccs_witness_bytes: vec![0u8; 32],
        sha256_binding_bytes: vec![0u8; 32],
    };
    let acc = make_accumulator_at_depth(1, "dos-test");
    let result = verify_fold(&acc, &[instance]);
    assert!(
        result.is_err(),
        "oversized ajtai_commitment_bytes must be rejected"
    );
}
