//! RED tests for end-to-end Cyclo → R1CS → MicroNova proving.

use std::{fs, path::PathBuf, time::Instant};

use pvthfhe_cyclo::{driver::fold_all, fold::verify_fold, CcsPShareInstance, CycloAccumulator};
use pvthfhe_micronova::{
    r1cs_encode::{check_cyclo_verifier_satisfied, cyclo_verifier_witness, encode_cyclo_verifier},
    MicroNovaError, MicroNovaProver, R1csInstance,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

fn fill_bytes(rng: &mut ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn fill_witness_bytes(rng: &mut ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut bytes = fill_bytes(rng, len);
    for byte in &mut bytes {
        *byte %= 97;
    }
    bytes
}

fn make_instance(participant_id: u16, rng: &mut ChaCha20Rng) -> CcsPShareInstance {
    let ajtai_commitment_bytes = fill_bytes(rng, 32);
    let public_io_bytes = fill_bytes(rng, 32);
    let ccs_witness_bytes = fill_witness_bytes(rng, 32);

    let ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(&ajtai_commitment_bytes)
        .finalize()
        .into();
    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(&public_io_bytes)
        .finalize()
        .into();
    let sha256_binding_bytes = Sha256::new()
        .chain_update(ajtai_hash)
        .chain_update(public_io_hash)
        .chain_update(&ccs_witness_bytes)
        .finalize()
        .to_vec();

    CcsPShareInstance {
        participant_id,
        ajtai_commitment_bytes,
        public_io_bytes,
        ccs_witness_bytes,
        sha256_binding_bytes,
    }
}

fn honest_trial(seed: u8) -> (CycloAccumulator, R1csInstance) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let instances = (1u16..=10)
        .map(|participant_id| make_instance(participant_id, &mut rng))
        .collect::<Vec<_>>();
    let session_id = format!("m6-e2e-session-{seed}");

    let accumulator = fold_all(&instances, &session_id, &mut rng)
        .expect("fold_all should succeed for honest instances");
    verify_fold(&accumulator, &instances).expect("verify_fold should accept honest accumulator");

    let r1cs = encode_cyclo_verifier(&accumulator);
    let witness = cyclo_verifier_witness(instances, session_id);

    assert!(
        r1cs.satisfiable,
        "honest accumulator should encode as satisfiable"
    );
    assert!(
        check_cyclo_verifier_satisfied(&accumulator, &r1cs, &witness),
        "honest witness should satisfy the encoded verifier relation"
    );

    (accumulator, r1cs)
}

fn benchmark_results_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/results/micronova_prove.json")
}

fn write_benchmark_result(wall_ms: u128) {
    let path = benchmark_results_path();
    let parent = path
        .parent()
        .expect("benchmark results path should have a parent directory");
    fs::create_dir_all(parent).expect("bench/results directory should be creatable");
    let payload = format!("{{\"wall_ms\": {wall_ms}, \"num_proofs\": 5, \"status\": \"pass\"}}\n");
    fs::write(path, payload).expect("micronova bench result should be written");
}

fn assert_roundtrip(seed: u8) {
    let (accumulator, r1cs) = honest_trial(seed);
    let proof = MicroNovaProver::prove(&r1cs, &accumulator)
        .expect("prototype prover should produce a proof for an honest accumulator");

    MicroNovaProver::verify(&proof, &accumulator, &r1cs)
        .expect("prototype verifier should accept the honest proof");
}

#[test]
fn e2e_micronova_roundtrip_seed_1() {
    assert_roundtrip(0x11);
}

#[test]
fn e2e_micronova_roundtrip_seed_2() {
    assert_roundtrip(0x22);
}

#[test]
fn e2e_micronova_roundtrip_seed_3() {
    assert_roundtrip(0x33);
}

#[test]
fn e2e_micronova_roundtrip_seed_4() {
    assert_roundtrip(0x44);
}

#[test]
fn e2e_micronova_roundtrip_seed_5() {
    assert_roundtrip(0x55);
}

#[test]
fn e2e_micronova_forged_accumulator_is_rejected() {
    let (accumulator, r1cs) = honest_trial(0x66);
    let proof = MicroNovaProver::prove(&r1cs, &accumulator)
        .expect("prototype prover should produce a proof for an honest accumulator");
    let mut forged_accumulator = CycloAccumulator {
        fold_depth: accumulator.fold_depth,
        acc_commitment_bytes: accumulator.acc_commitment_bytes.clone(),
        acc_public_io_bytes: accumulator.acc_public_io_bytes.clone(),
        norm_bound_current: accumulator.norm_bound_current,
        session_id: accumulator.session_id.clone(),
        params_digest: accumulator.params_digest,
    };
    forged_accumulator.acc_commitment_bytes[0] ^= 0x01;

    let verification = MicroNovaProver::verify(&proof, &forged_accumulator, &r1cs);

    assert_eq!(verification, Err(MicroNovaError::InvalidProof));
}

#[test]
fn e2e_micronova_records_prove_wall_time() {
    let proving_inputs = [0x11, 0x22, 0x33, 0x44, 0x55]
        .into_iter()
        .map(honest_trial)
        .collect::<Vec<_>>();

    let started = Instant::now();
    let proofs = proving_inputs
        .iter()
        .map(|(accumulator, r1cs)| MicroNovaProver::prove(r1cs, accumulator))
        .collect::<Result<Vec<_>, _>>()
        .expect("prototype prover should produce a proof for honest accumulators");
    let wall_ms = started.elapsed().as_millis();

    for ((accumulator, r1cs), proof) in proving_inputs.iter().zip(proofs.iter()) {
        MicroNovaProver::verify(proof, accumulator, r1cs)
            .expect("prototype verifier should accept the honest proof");
    }

    write_benchmark_result(wall_ms);
}
