//! RED test: witness norm must use real coefficient ∞-norm, not byte-max.
//!
//! The current `witness_norm_estimate` returns max byte value of the
//! serialized witness, which is orders of magnitude smaller than the real
//! coefficient ∞-norm. This test constructs a witness polynomial with
//! coefficient 2^48, expects `fold_one_step` to reject it with
//! `NormBoundExceeded`, and FAILS on current `main` because the byte-max
//! (1) is well below the per-step budget (102).

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{
    fold::{fold_one_step, init_accumulator, AJTAI_COMMITMENT_BYTES},
    CcsPShareInstance, CycloError,
};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn one_var_witness(fr: Fr) -> Vec<u8> {
    let mut bytes = vec![0u8, 0, 0, 1];
    bytes.extend_from_slice(&fr.into_bigint().to_bytes_le());
    bytes
}

fn make_instance_with_witness(id: u16, witness_bytes: Vec<u8>) -> CcsPShareInstance {
    let ajtai_bytes: Vec<u8> = (0..AJTAI_COMMITMENT_BYTES)
        .map(|i| (i as u8).wrapping_add(id as u8))
        .collect();
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: ajtai_bytes.into(),
        public_io_bytes: vec![id as u8 ^ 0xAA; 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness_bytes),
        sha256_binding_bytes: vec![0u8; 32].into(),
        ccs_matrix_bytes: vec![].into(),
    }
}

#[test]
fn norm_rejects_large_coefficient_not_byte_max() {
    let bad_fr = Fr::from(1u64 << 48);
    let bad_witness = one_var_witness(bad_fr);

    let init_witness = one_var_witness(Fr::ZERO);
    let init_instance = make_instance_with_witness(0, init_witness);
    let bad_instance = make_instance_with_witness(1, bad_witness);

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    let acc = init_accumulator(&init_instance, "test-norm-coeff")
        .expect("init_accumulator should succeed");

    let result = fold_one_step(acc, &bad_instance, &mut rng);

    match result {
        Err(CycloError::NormBoundExceeded { got, max: _ }) => {
            assert!(
                got > 1_000_000,
                "expected norm > 1_000_000 (coefficient ∞-norm), got {} (likely byte-max)",
                got
            );
        }
        Ok(_) => panic!("fold_one_step should have rejected witness with ∞-norm 2^48"),
        Err(other) => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn norm_accepts_clean_witness() {
    let clean_witness = one_var_witness(Fr::ZERO);
    let init_instance = make_instance_with_witness(0, clean_witness.clone());
    let instance = make_instance_with_witness(1, clean_witness);

    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let acc = init_accumulator(&init_instance, "test-norm-clean")
        .expect("init_accumulator should succeed");

    let result = fold_one_step(acc, &instance, &mut rng);
    assert!(
        result.is_ok(),
        "clean witness (all zeros) should be accepted by norm check"
    );
}
