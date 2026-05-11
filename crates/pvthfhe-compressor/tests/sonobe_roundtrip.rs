//! Roundtrip tests for the Sonobe-backed compressor.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_compressor::sonobe::{SonobeCompressor, ToyStepCircuit};
use pvthfhe_compressor::ProofCompressor;

fn encode_scalar(value: u64) -> Vec<u8> {
    let field = Fr::from(value);
    let mut bytes = field.into_bigint().to_bytes_le();
    bytes.resize(32, 0);
    bytes
}

fn epoch() -> [u8; 32] {
    [0x10u8; 32]
}

#[test]
fn sonobe_roundtrip_toy_ivc_verifies() {
    let compressor =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct sonobe compressor");
    let acc = encode_scalar(3);
    let public_inputs = encode_scalar(7);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove toy ivc");
    let vk = compressor.verifier_key();

    assert_eq!(compressor.backend_id(), "sonobe-nova-bn254-grumpkin");
    assert!(compressor
        .verify(&vk, &proof, &public_inputs)
        .expect("verify toy ivc"));
}

#[test]
fn sonobe_srs_is_deterministic_for_same_epoch() {
    let left =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct left sonobe compressor");
    let right =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct right sonobe compressor");

    assert_eq!(left.vk_bytes(), right.vk_bytes());
    assert_eq!(left.srs_hash(), right.srs_hash());
}

#[test]
fn sonobe_rejects_wrong_public_input_or_tampered_acc_binding() {
    let compressor =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct sonobe compressor");
    let acc = encode_scalar(5);
    let honest_public_inputs = encode_scalar(9);
    let wrong_public_inputs = encode_scalar(10);
    let proof = compressor
        .prove(&acc, &honest_public_inputs)
        .expect("prove honest toy ivc");
    let vk = compressor.verifier_key();

    let wrong_public_result = compressor.verify(&vk, &proof, &wrong_public_inputs);
    assert!(matches!(wrong_public_result, Ok(false) | Err(_)));

    let mut tampered_acc_binding = proof.clone();
    tampered_acc_binding.0[8] ^= 1;
    let tampered_result = compressor.verify(&vk, &tampered_acc_binding, &honest_public_inputs);
    assert!(matches!(tampered_result, Ok(false) | Err(_)));
}

#[test]
fn sonobe_rejects_truncated_proof_bytes_without_panicking() {
    let compressor =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct sonobe compressor");
    let acc = encode_scalar(12);
    let public_inputs = encode_scalar(4);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove toy ivc");
    let vk = compressor.verifier_key();

    let truncated = pvthfhe_compressor::CompressedProof(proof.0[..75].to_vec());
    let result = compressor.verify(&vk, &truncated, &public_inputs);

    assert!(matches!(result, Ok(false) | Err(_)));
}
