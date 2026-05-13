//! C7 decryption aggregation step circuit tests.

use ark_bn254::Fr;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::sonobe::{
    encode_triple, C7DecryptAggregationCircuit, SonobeCompressor, ToyStepCircuit,
};
use pvthfhe_compressor::{ProofCompressor, StepCircuit};

fn epoch() -> [u8; 32] {
    [0x01u8; 32]
}

fn encode_triple_scalar(a: u64, b: u64, c: u64) -> Vec<u8> {
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

/// Test 1: C7 step circuit compiles with Sonobe.
#[test]
fn c7_step_circuit_compiles_with_sonobe() {
    let compressor = SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new(epoch(), 4)
        .expect("construct C7 sonobe compressor");
    let vk = compressor.verifier_key();
    assert_eq!(vk.backend_id, "sonobe-nova-bn254-grumpkin");
}

/// Test 2: state_len is 3.
#[test]
fn c7_state_len_is_three() {
    let circuit =
        C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit");
    assert_eq!(circuit.state_len(), 3);
}

/// Test 3: circuit_hash is deterministic.
#[test]
fn c7_circuit_hash_is_deterministic() {
    let circuit_a =
        C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit a");
    let circuit_b =
        C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit b");
    assert_eq!(circuit_a.circuit_hash(), circuit_b.circuit_hash());
}

/// Test 4: C7 circuit_hash differs from ToyStepCircuit.
#[test]
fn c7_circuit_hash_differs_from_toy() {
    let c7 = C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit");
    let toy = ToyStepCircuit::<Fr>::new(()).expect("construct toy circuit");
    assert_ne!(c7.circuit_hash(), toy.circuit_hash());
}

/// Test 5: descriptor width is 3.
#[test]
fn c7_descriptor_width_is_three() {
    let circuit =
        C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit");
    assert_eq!(circuit.descriptor().width, 3);
}

/// Test 6: full roundtrip prove/verify with 4 steps.
#[test]
fn c7_roundtrip_prove_verify() {
    let compressor = SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new(epoch(), 4)
        .expect("construct C7 sonobe compressor");
    let acc = encode_triple_scalar(0, 0, 0);
    let public_inputs = encode_triple_scalar(42, 1, 100);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove C7 ivc");
    let vk = compressor.verifier_key();

    assert_eq!(compressor.backend_id(), "sonobe-nova-bn254-grumpkin");
    assert!(compressor
        .verify(&vk, &proof, &public_inputs)
        .expect("verify C7 ivc"));
}
