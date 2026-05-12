//! R5.2 D.1 RED: CycloFoldStepCircuit must encode fold relation, not field addition.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::sonobe::{CycloFoldStepCircuit, ExternalInputs3Var, SonobeCompressor};
use pvthfhe_compressor::ProofCompressor;

fn epoch() -> [u8; 32] {
    [0x10u8; 32]
}

fn encode_triple(a: u64, b: u64, c: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    for v in &[a, b, c] {
        let field = Fr::from(*v);
        let mut bytes = field.into_bigint().to_bytes_le();
        bytes.resize(32, 0);
        out.extend_from_slice(&bytes);
    }
    out
}

#[test]
fn cyclo_fold_verifies_with_ivc_steps_2() {
    let compressor = SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 2)
        .expect("construct cyclo fold compressor");
    let acc = encode_triple(0, 0, 0);
    let public_inputs = encode_triple(3, 1, 1);
    let proof = compressor.prove(&acc, &public_inputs).expect("prove");
    let vk = compressor.verifier_key();
    assert!(compressor
        .verify(&vk, &proof, &public_inputs)
        .expect("verify"));
    assert_eq!(compressor.backend_id(), "sonobe-nova-bn254-grumpkin");
}

#[test]
fn step_circuit_allocates_nonzero_constraints() {
    let circuit = CycloFoldStepCircuit::<Fr>::new(()).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();

    let z_i = vec![
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap(),
    ];
    let external_inputs = ExternalInputs3Var(
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
    );

    let num_before = cs.num_constraints();
    let _next_state = circuit
        .generate_step_constraints(cs.clone(), 0, z_i, external_inputs)
        .expect("generate step constraints");
    let num_after = cs.num_constraints();
    let allocated_in_step = num_after.saturating_sub(num_before);

    assert!(
        allocated_in_step > 0,
        "CycloFoldStepCircuit::generate_step_constraints must allocate constraints \
         for commitment folding; got {} (uses cs for multiplication)",
        allocated_in_step
    );
}
