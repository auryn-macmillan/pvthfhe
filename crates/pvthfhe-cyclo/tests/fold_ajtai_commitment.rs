//! RED test: fold operation uses real Ajtai commitments, not SHA-256.
//!
//! P2A.2: Replace SHA-256(poly_bytes) commitment in fold.rs with real
//! Ajtai commitments from the `ajtai` module.
//!
//! Tests:
//! 1. Commitment is NOT a 32-byte SHA-256 hash → RED until Ajtai path active
//! 2. Commitment decodes as AjtaiCommitment with m=13
//! 3. Valid fold passes verification
//! 4. Tampered commitment rejected

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{
    fold::{fold_one_step, init_accumulator, verify_fold},
    CcsPShareInstance,
};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// φ=256, m=13 → 13 × 256 × 8 = 26624 bytes.
const EXPECTED_COMMITMENT_BYTES: usize = 26624;

const AJTAI_COMMITMENT_M: usize = 13;

fn make_ajtai_bytes(id: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; EXPECTED_COMMITMENT_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(id);
    }
    bytes
}

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

fn make_instance(id: u16) -> CcsPShareInstance {
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: make_ajtai_bytes(id as u8).into(),
        public_io_bytes: vec![id as u8 ^ 0xAA; 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness_1var(Fr::ZERO)),
        sha256_binding_bytes: vec![id as u8; 32].into(),
        ccs_matrix_bytes: matrix_1x1(Fr::from(1u64)).into(),
    }
}

/// RED: accumulator commitment must NOT be a 32-byte SHA-256 hash.
/// Currently it is — this test fails until Ajtai path is active.
#[test]
fn commitment_is_not_sha256_hash() {
    let instance = make_instance(1);
    let acc =
        init_accumulator(&instance, "test-session").expect("init_accumulator should not fail");
    assert_ne!(
        acc.acc_commitment_bytes.len(),
        32,
        "Commitment must NOT be 32-byte SHA-256 hash"
    );
    assert_eq!(
        acc.acc_commitment_bytes.len(),
        EXPECTED_COMMITMENT_BYTES,
        "Commitment must be Ajtai-encoded (m * phi * 8 = 26624 bytes)"
    );
}

/// RED: the accumulator commitment must decode as a valid AjtaiCommitment
/// with m=13 ring elements.
#[test]
fn commitment_decodes_as_ajtai() {
    let instance = make_instance(1);
    let acc =
        init_accumulator(&instance, "test-session").expect("init_accumulator should not fail");
    let decoded =
        pvthfhe_cyclo::ajtai::decode_commitment(&acc.acc_commitment_bytes, AJTAI_COMMITMENT_M);
    assert!(
        decoded.is_ok(),
        "Accumulator commitment must decode as AjtaiCommitment with m=13"
    );
}

/// Valid fold with Ajtai commitments must pass verification.
#[test]
fn valid_fold_with_ajtai_commitment_passes() {
    let instance = make_instance(1);
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let acc =
        init_accumulator(&instance, "test-session").expect("init_accumulator should not fail");
    let new_acc = fold_one_step(acc, &instance, &mut rng).expect("fold_one_step should not fail");
    verify_fold(&new_acc, &[make_instance(1)]).expect("verify_fold must accept honest fold");
}

/// Tampered accumulator commitment must be rejected by verify_fold.
#[test]
fn tampered_ajtai_commitment_rejected() {
    let instance = make_instance(1);
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let acc =
        init_accumulator(&instance, "test-session").expect("init_accumulator should not fail");
    let mut new_acc =
        fold_one_step(acc, &instance, &mut rng).expect("fold_one_step should not fail");
    // Tamper a byte of the Ajtai-encoded commitment
    new_acc.acc_commitment_bytes[0] ^= 0xFF;
    let result = verify_fold(&new_acc, &[make_instance(1)]);
    assert!(
        result.is_err(),
        "verify_fold must reject tampered accumulator commitment"
    );
}
