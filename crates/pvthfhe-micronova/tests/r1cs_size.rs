//! RED tests for Cyclo verifier R1CS sizing.

use std::{fs, path::PathBuf};

use pvthfhe_cyclo::{driver::fold_all, fold::verify_fold, CcsPShareInstance};
use pvthfhe_micronova::r1cs_encode::{
    check_cyclo_verifier_satisfied, cyclo_verifier_witness, encode_cyclo_verifier,
    MAX_ALLOWED_CONSTRAINTS,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

fn make_instance(id: u16, seed: u8) -> CcsPShareInstance {
    let ajtai_commitment_bytes = vec![seed; 32];
    let public_io_bytes = vec![seed.wrapping_add(1); 32];
    let ccs_witness_bytes = vec![seed.wrapping_add(2); 32];

    let ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(&ajtai_commitment_bytes)
        .finalize()
        .into();
    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(&public_io_bytes)
        .finalize()
        .into();
    let sha256_binding: [u8; 32] = Sha256::new()
        .chain_update(ajtai_hash)
        .chain_update(public_io_hash)
        .chain_update(&ccs_witness_bytes)
        .finalize()
        .into();

    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes,
        public_io_bytes,
        ccs_witness_bytes,
        sha256_binding_bytes: sha256_binding.to_vec(),
    }
}

fn make_honest_instances() -> Vec<CcsPShareInstance> {
    (0u16..10)
        .map(|index| make_instance(index + 1, (index * 7 + 3) as u8))
        .collect()
}

fn honest_accumulator() -> (
    String,
    Vec<CcsPShareInstance>,
    pvthfhe_cyclo::CycloAccumulator,
) {
    let session_id = String::from("m5-r1cs-session");
    let instances = make_honest_instances();
    let mut rng = ChaCha20Rng::from_seed([0x5Au8; 32]);
    let accumulator = fold_all(&instances, &session_id, &mut rng)
        .expect("fold_all should succeed for honest instances");
    verify_fold(&accumulator, &instances).expect("verify_fold should accept honest accumulator");
    (session_id, instances, accumulator)
}

fn results_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/results/r1cs_size.json")
}

fn write_result_file(num_constraints: usize) {
    let path = results_path();
    let parent = path
        .parent()
        .expect("results file should have parent directory");
    fs::create_dir_all(parent).expect("bench/results directory should be creatable");
    let status = if num_constraints <= MAX_ALLOWED_CONSTRAINTS {
        "pass"
    } else {
        "fail"
    };
    let payload = format!(
        "{{\"num_constraints\": {num_constraints}, \"max_allowed\": {MAX_ALLOWED_CONSTRAINTS}, \"status\": \"{status}\"}}\n"
    );
    fs::write(path, payload).expect("r1cs size result should be written");
}

#[test]
fn r1cs_constraint_count_is_within_budget() {
    let (_, _, accumulator) = honest_accumulator();

    let r1cs = encode_cyclo_verifier(&accumulator);
    write_result_file(r1cs.num_constraints);

    assert!(
        r1cs.num_constraints <= MAX_ALLOWED_CONSTRAINTS,
        "Cyclo verifier R1CS must fit within 2^21 constraints, got {}",
        r1cs.num_constraints
    );
}

#[test]
fn r1cs_honest_accumulator_witness_is_satisfied() {
    let (session_id, instances, accumulator) = honest_accumulator();
    let r1cs = encode_cyclo_verifier(&accumulator);
    let witness = cyclo_verifier_witness(instances, session_id);

    assert!(
        r1cs.satisfiable,
        "honest accumulator should encode as satisfiable"
    );
    assert!(
        check_cyclo_verifier_satisfied(&accumulator, &r1cs, &witness),
        "honest Cyclo accumulator witness must satisfy the encoded R1CS relation"
    );
}
