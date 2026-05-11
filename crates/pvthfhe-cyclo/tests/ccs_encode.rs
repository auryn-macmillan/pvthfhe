//! Integration tests for CCS instance encoding (Task F3).

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{ccs_encode, CcsPShareInstance};
use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};
use sha2::{Digest, Sha256};

/// 1×1 CCS matrix with element `e`: only witness z=[0] satisfies (e·z)⊙z=0.
fn matrix_1x1(e: Fr) -> Vec<u8> {
    let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 1]; // rows=1, cols=1
    m.extend_from_slice(&e.into_bigint().to_bytes_le());
    m
}

fn one_var_witness(fr: Fr) -> Vec<u8> {
    let mut bytes = vec![0u8, 0, 0, 1];
    bytes.extend_from_slice(&fr.into_bigint().to_bytes_le());
    bytes
}

fn make_valid_instance() -> CcsPShareInstance {
    let ajtai = b"ajtai_commitment_data_32_bytes!!".to_vec();
    let public_io = b"public_io_data_for_the_instance!".to_vec();
    let witness = one_var_witness(Fr::ZERO);

    let ajtai_hash: [u8; 32] = Sha256::new().chain_update(&ajtai).finalize().into();
    let public_io_hash: [u8; 32] = Sha256::new().chain_update(&public_io).finalize().into();
    let binding: [u8; 32] = Sha256::new()
        .chain_update(ajtai_hash)
        .chain_update(public_io_hash)
        .chain_update(&witness)
        .finalize()
        .into();

    CcsPShareInstance {
        participant_id: 1,
        ajtai_commitment_bytes: ajtai.into(),
        public_io_bytes: public_io.into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness),
        sha256_binding_bytes: binding.to_vec().into(),
        ccs_matrix_bytes: matrix_1x1(Fr::from(1u64)).into(),
    }
}

#[test]
fn encode_valid_instance() {
    let share = make_valid_instance();
    let instance = ccs_encode::encode(&share).expect("encode should succeed");
    ccs_encode::check_satisfiability(&instance).expect("satisfiability should hold");
}

#[test]
fn check_rejects_tampered_witness() {
    let share = make_valid_instance();
    let mut instance = ccs_encode::encode(&share).expect("encode should succeed");
    instance.witness_bytes[4] ^= 0xFF;
    let result = ccs_encode::check_satisfiability(&instance);
    assert!(
        result.is_err(),
        "tampered witness should fail satisfiability"
    );
}

#[test]
fn encode_deterministic() {
    let share = make_valid_instance();
    let a = ccs_encode::encode(&share).expect("encode should succeed");
    let b = ccs_encode::encode(&share).expect("encode should succeed");
    assert_eq!(a.participant_id, b.participant_id);
    assert_eq!(a.ajtai_hash, b.ajtai_hash);
    assert_eq!(a.public_io_hash, b.public_io_hash);
    assert_eq!(a.sha256_binding, b.sha256_binding);
    assert_eq!(a.witness_bytes, b.witness_bytes);
    assert_eq!(a.ccs_matrix, b.ccs_matrix);
}

#[test]
fn encode_rejects_wrong_binding_length() {
    let mut share = make_valid_instance();
    share.sha256_binding_bytes = ProtocolBytes::from(vec![0u8; 16]);
    let result = ccs_encode::encode(&share);
    assert!(result.is_err(), "wrong binding length should return Err");
}
