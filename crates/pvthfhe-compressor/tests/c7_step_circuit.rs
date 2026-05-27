//! C7 decryption aggregation step circuit tests.

use ark_bn254::Fr;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::nova::{
    clear_c7_step_data, encode_triple, set_c7_step_data, C7DecryptAggregationCircuit,
    ExternalInputs5, NovaCompressor, ToyStepCircuit,
};
use pvthfhe_compressor::witness::hash_all_coeffs;
use pvthfhe_compressor::StepCircuit;

const N_COEFFS: usize = 8192;

fn epoch() -> [u8; 32] {
    [0x01u8; 32]
}

fn encode_triple_scalar(a: u64, b: u64, c: u64) -> Vec<u8> {
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

/// Build coefficient vectors where `eval(r=0) = ext_0_value`.
/// Horner's method: eval = c₀·r^{N-1} + c₁·r^{N-2} + ... + c_{N-1}·r⁰.
/// With r=0, only c_{N-1} (the last coefficient) pairs with r⁰=1.
fn build_trivial_coeffs(num_steps: usize, ext_0_value: Fr) -> Vec<Vec<Fr>> {
    let mut coeffs_per_step: Vec<Vec<Fr>> = Vec::with_capacity(num_steps);
    for _ in 0..num_steps {
        let mut c = vec![Fr::from(0u64); N_COEFFS];
        c[N_COEFFS - 1] = ext_0_value;
        coeffs_per_step.push(c);
    }
    coeffs_per_step
}

/// Test 1: C7 step circuit compiles with Nova.
#[test]
fn c7_step_circuit_compiles_with_nova() {
    let compressor = NovaCompressor::<C7DecryptAggregationCircuit<Fr>>::new(epoch(), 4)
        .expect("construct C7 nova compressor");
    let vk = compressor.verifier_key();
    assert_eq!(vk.backend_id, "nova-bn254-grumpkin");
}

/// Test 2: state_len is 3.
#[test]
fn c7_state_len_is_three() {
    let circuit = C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit");
    assert_eq!(circuit.state_len(), 3);
}

/// Test 3: circuit_hash is deterministic.
#[test]
fn c7_circuit_hash_is_deterministic() {
    let circuit_a = C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit a");
    let circuit_b = C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit b");
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
    let circuit = C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 circuit");
    assert_eq!(circuit.descriptor().width, 3);
}

#[test]
fn c7_roundtrip_prove_verify() {
    clear_c7_step_data();
    let ext_0 = Fr::from(42u64);
    let num_steps = 4;

    let compressor = NovaCompressor::<C7DecryptAggregationCircuit<Fr>>::new(epoch(), num_steps)
        .expect("construct C7 nova compressor");

    let coeffs = build_trivial_coeffs(num_steps, ext_0);

    let commitment = hash_all_coeffs(&coeffs[0]);
    let derived_r = hash_all_coeffs(&[commitment, Fr::from(0u64)]);
    eprintln!("commitment={commitment:?}, derived_r={derived_r:?}");

    set_c7_step_data(coeffs, derived_r);

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let steps: Vec<ExternalInputs5<Fr>> =
        vec![
            ExternalInputs5(ext_0, Fr::from(1u64), commitment, Fr::from(0u64), derived_r);
            num_steps
        ];
    let proof = compressor
        .prove_steps_c7(&acc, &steps)
        .expect("prove C7 ivc");

    clear_c7_step_data();

    let vk = compressor.verifier_key();
    eprintln!("vk.backend_id={}", vk.backend_id);
    assert_eq!(vk.backend_id, "nova-bn254-grumpkin");

    let verify_result = compressor.verify_steps_c7(&vk, &proof, &steps);
    eprintln!("verify_result={verify_result:?}");

    assert!(verify_result.expect("verify C7 ivc"));
}
