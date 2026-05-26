//! P3-M1 FoldVerifierStepCircuit tests.
//!
//! Tests the LatticeFold+ terminal verifier Nova step circuit.
//! All tests are expected to pass (GREEN) — the "RED" designation
//! in the plan refers to TDD: tests written before verification.

use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::sonobe::{
    encode_triple, ExternalInputs3, ExternalInputs3Var, FoldVerifierStepCircuit, SonobeCompressor,
    ToyStepCircuit,
};
use pvthfhe_compressor::{ProofCompressor, StepCircuit};

fn epoch() -> [u8; 32] {
    [0x01u8; 32]
}

fn encode_triple_scalar(a: u64, b: u64, c: u64) -> Vec<u8> {
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

/// Test 1: SonobeCompressor compiles with FoldVerifierStepCircuit.
#[test]
fn fold_verifier_compiles() {
    let compressor = SonobeCompressor::<FoldVerifierStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct fold verifier sonobe compressor");
    let vk = compressor.verifier_key();
    assert_eq!(vk.backend_id, "sonobe-nova-bn254-grumpkin");
}

/// Test 2: state_len is 3.
#[test]
fn fold_verifier_state_len_three() {
    let circuit = FoldVerifierStepCircuit::<Fr>::new(()).expect("construct fold verifier circuit");
    assert_eq!(circuit.state_len(), 3);
}

/// Test 3: Accepts honest fold with same external inputs for all steps.
#[test]
fn fold_verifier_accepts_honest_fold() {
    let compressor = SonobeCompressor::<FoldVerifierStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct fold verifier sonobe compressor");
    let acc = encode_triple_scalar(0, 0, 0);
    let public_inputs = encode_triple_scalar(1, 2, 3);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove fold verifier ivc");
    let vk = compressor.verifier_key();

    assert!(compressor
        .verify(&vk, &proof, &public_inputs)
        .expect("verify fold verifier ivc"));
}

/// Test 4: Full roundtrip prove/verify with per-step external inputs.
#[test]
fn fold_verifier_roundtrip() {
    let compressor = SonobeCompressor::<FoldVerifierStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct fold verifier sonobe compressor");
    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64))).to_vec();
    let steps = vec![
        ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
        ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
        ExternalInputs3(Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)),
        ExternalInputs3(Fr::from(10u64), Fr::from(11u64), Fr::from(12u64)),
    ];
    let proof = compressor
        .prove_steps(&acc, &steps)
        .expect("prove fold verifier steps");
    let vk = compressor.verifier_key();

    assert!(compressor
        .verify_steps(&vk, &proof, &steps)
        .expect("verify fold verifier steps"));
}

/// Test 5: State evolves after each step.
#[test]
fn fold_verifier_state_evolves() {
    let circuit = FoldVerifierStepCircuit::<Fr>::new(()).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Initial state: verified_count=0, running_hash=0, step_index=0
    let z_i = vec![
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap(),
    ];

    let external_inputs = ExternalInputs3Var(
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(11u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(22u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(33u64))).unwrap(),
    );

    let next_state = circuit
        .generate_step_constraints(cs.clone(), 0, z_i, external_inputs)
        .expect("generate step constraints");

    assert_eq!(next_state.len(), 3);

    // Step 1: verified_count=1, running_hash=33, step_index=1
    assert_eq!(next_state[0].value().unwrap(), Fr::from(1u64));
    assert_eq!(next_state[1].value().unwrap(), Fr::from(33u64));
    assert_eq!(next_state[2].value().unwrap(), Fr::from(1u64));

    // Step 2: verified_count=2, running_hash=66, step_index=2
    let z2 = next_state;
    let ext2 = ExternalInputs3Var(
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(44u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(55u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(33u64))).unwrap(),
    );

    let next_state2 = circuit
        .generate_step_constraints(cs, 1, z2, ext2)
        .expect("generate step constraints 2");

    assert_eq!(next_state2[0].value().unwrap(), Fr::from(2u64));
    assert_eq!(next_state2[1].value().unwrap(), Fr::from(66u64));
    assert_eq!(next_state2[2].value().unwrap(), Fr::from(2u64));
}

/// Test 6: circuit_hash differs from ToyStepCircuit.
#[test]
fn fold_verifier_hash_differs_from_toy() {
    let fold = FoldVerifierStepCircuit::<Fr>::new(()).expect("construct fold verifier circuit");
    let toy = ToyStepCircuit::<Fr>::new(()).expect("construct toy circuit");
    assert_ne!(fold.circuit_hash(), toy.circuit_hash());
}
