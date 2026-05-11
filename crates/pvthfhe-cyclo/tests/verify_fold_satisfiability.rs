//! C.1 test: verify_fold must reject non-satisfying witnesses via the real CCS check.
//!
//! This test verifies that `verify_fold` calls `check_satisfiability` on every
//! instance and rejects accumulators built from non-satisfying witnesses.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{
    fold::{fold_one_step, init_accumulator, verify_fold},
    CcsPShareInstance,
};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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

fn make_instance(id: u16, witness_fr: Fr) -> CcsPShareInstance {
    let mut binding = [0u8; 32];
    binding[0] = id as u8;
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: vec![id as u8; 32].into(),
        public_io_bytes: vec![id as u8 ^ 0xAA; 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness_1var(witness_fr)),
        sha256_binding_bytes: binding.to_vec().into(),
        ccs_matrix_bytes: matrix_1x1(Fr::from(1u64)).into(),
    }
}

#[test]
fn verify_fold_rejects_non_satisfying_witness() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Build a valid accumulator with a satisfying witness (z=[0])
    let honest = make_instance(1, Fr::ZERO);
    let acc = init_accumulator(&honest, "c1-test").expect("init");
    let acc = fold_one_step(acc, &honest, &mut rng).expect("fold");

    // Verify with the honest witness — must succeed
    verify_fold(&acc, &[make_instance(1, Fr::ZERO)])
        .expect("verify_fold must accept honest satisfying witness");

    // Use a non-satisfying witness (z=[1], since M=[1] and 1*1≠0)
    let bad = make_instance(1, Fr::from(1u64));
    let result = verify_fold(&acc, &[bad]);
    assert!(
        result.is_err(),
        "verify_fold must reject non-satisfying witness (z=[1] with M=[1] gives z²≠0)"
    );
}
