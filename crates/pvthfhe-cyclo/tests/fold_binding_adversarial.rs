//! Adversarial binding tests for the Cyclo folding sub-protocol.
//! Verifies ring-based Ajtai commitment arithmetic (Schwartz-Zippel) rather
//! than the SHA-256 hash-chain placeholder.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{
    fold::{fold_one_step, init_accumulator, verify_fold},
    CcsPShareInstance,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};
use sha2::{Digest, Sha256};

fn matrix_1x1(e: Fr) -> Vec<u8> {
    let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 1]; // rows=1, cols=1
    m.extend_from_slice(&e.into_bigint().to_bytes_le());
    m
}

fn witness_1var(fr: Fr) -> Vec<u8> {
    let mut bytes = vec![0u8, 0, 0, 1]; // num_vars=1
    bytes.extend_from_slice(&fr.into_bigint().to_bytes_le());
    bytes
}

fn make_ajtai_bytes(id: u8) -> Vec<u8> {
    use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
    (0..AJTAI_COMMITMENT_BYTES)
        .map(|i| (i as u8).wrapping_add(id))
        .collect()
}

fn make_instance(id: u16) -> CcsPShareInstance {
    let mut binding = [0u8; 32];
    binding[0] = id as u8;
    let sha256_binding_bytes: ProtocolBytes = binding.to_vec().into();
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: make_ajtai_bytes(id as u8).into(),
        public_io_bytes: vec![id as u8 ^ 0xAA; 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness_1var(Fr::ZERO)),
        sha256_binding_bytes,
        ccs_matrix_bytes: matrix_1x1(Fr::from(1u64)).into(),
    }
}

#[test]
fn init_does_not_use_sha256_init_placeholder() {
    let instance = make_instance(1);
    let acc = init_accumulator(&instance, "adversarial-session")
        .expect("init_accumulator should not fail");

    let broken_formula: Vec<u8> = Sha256::new()
        .chain_update(b"init")
        .chain_update(instance.ajtai_commitment_bytes.as_slice())
        .finalize()
        .to_vec();

    assert_ne!(
        acc.acc_commitment_bytes, broken_formula,
        "init_accumulator must NOT produce SHA-256('init'||bytes)"
    );
}

#[test]
fn fold_does_not_use_sha256_extension_chain() {
    let instance = make_instance(2);
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let acc = init_accumulator(&instance, "adversarial-session")
        .expect("init_accumulator should not fail");

    let init_commitment = acc.acc_commitment_bytes.clone();

    let inst_ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(instance.ajtai_commitment_bytes.as_slice())
        .finalize()
        .into();
    let challenge_h: [u8; 32] = Sha256::new()
        .chain_update(&init_commitment)
        .chain_update(inst_ajtai_hash)
        .finalize()
        .into();
    let old_r_byte = challenge_h[0] % 3;
    let acc_ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(&init_commitment)
        .finalize()
        .into();
    let old_combined: Vec<u8> = Sha256::new()
        .chain_update([old_r_byte])
        .chain_update(acc_ajtai_hash)
        .chain_update(inst_ajtai_hash)
        .finalize()
        .to_vec();

    let new_acc = fold_one_step(acc, &instance, &mut rng)
        .expect("fold_one_step should not fail");

    assert_ne!(
        new_acc.acc_commitment_bytes, old_combined,
        "fold_one_step must NOT reproduce the old extension::extend SHA-256 chain"
    );
}

#[test]
fn tampered_instance_is_rejected() {
    let inst_a = make_instance(10);
    let inst_b = make_instance(20);
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);

    let acc0 = init_accumulator(&inst_a, "tamper-session").expect("init");
    let acc1 = fold_one_step(acc0, &inst_a, &mut rng).expect("fold A");
    let acc2 = fold_one_step(acc1, &inst_b, &mut rng).expect("fold B");

    verify_fold(&acc2, &[make_instance(10), make_instance(20)])
        .expect("honest verify_fold must accept");

    let mut inst_b_tampered = make_instance(20);
    inst_b_tampered.ajtai_commitment_bytes[0] ^= 0xFF;

    let result = verify_fold(&acc2, &[make_instance(10), inst_b_tampered]);
    assert!(
        result.is_err(),
        "verify_fold must REJECT tampered ajtai_commitment_bytes"
    );
}

#[test]
fn distinct_instances_produce_distinct_accumulators() {
    let inst_a = make_instance(1);
    let inst_b = make_instance(2);
    let mut rng_a = ChaCha20Rng::from_seed([11u8; 32]);
    let mut rng_b = ChaCha20Rng::from_seed([11u8; 32]);

    let acc_a0 = init_accumulator(&inst_a, "schwartz-session").expect("init a");
    let acc_b0 = init_accumulator(&inst_b, "schwartz-session").expect("init b");

    assert_ne!(
        acc_a0.acc_commitment_bytes, acc_b0.acc_commitment_bytes,
        "init: different instances must produce different commitments"
    );

    let acc_a1 = fold_one_step(acc_a0, &inst_a, &mut rng_a).expect("fold a");
    let acc_b1 = fold_one_step(acc_b0, &inst_b, &mut rng_b).expect("fold b");

    assert_ne!(
        acc_a1.acc_commitment_bytes, acc_b1.acc_commitment_bytes,
        "fold: different instances must produce different commitments"
    );
}
