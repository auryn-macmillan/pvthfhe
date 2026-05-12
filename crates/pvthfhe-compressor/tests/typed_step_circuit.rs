//! Typed step-circuit tests for the Sonobe-backed compressor.
//!
//! RED phase: these tests assert that SonobeCompressor is parameterized
//! by a step-circuit type S, the verifier key carries a step_circuit_hash
//! derived from S, and the verifier rejects mismatched vk hashes (type mismatch).

use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::{
    sonobe::{ExternalInputs3, ExternalInputs3Var, SonobeCompressor, ToyStepCircuit},
    ProofCompressor, StepCircuit, StepCircuitDescriptor,
};
use sha3::{Digest, Keccak256};

fn encode_triple(a: u64, b: u64, c: u64) -> Vec<u8> {
    use pvthfhe_compressor::sonobe::encode_triple;
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

fn epoch() -> [u8; 32] {
    [0x2Au8; 32]
}

#[derive(Clone, Copy, Debug)]
struct AltStepCircuit<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for AltStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _field: PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![
            z_i[0].clone() * external_inputs.0,
            z_i[1].clone() + external_inputs.1,
            z_i[2].clone() + external_inputs.2,
        ])
    }
}

impl<F: PrimeField> StepCircuit for AltStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"alt-step-circuit-v1").into()
    }
}

#[test]
fn typed_compressor_roundtrip_with_step_circuit_hash() {
    let compressor = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct typed sonobe compressor");
    let vk = compressor.verifier_key();

    assert_ne!(
        vk.step_circuit_hash, [0u8; 32],
        "step_circuit_hash must be non-zero"
    );

    let acc = encode_triple(3, 0, 0);
    let public_inputs = encode_triple(7, 1, 1);
    let proof = compressor.prove(&acc, &public_inputs).expect("prove");
    assert!(compressor
        .verify(&vk, &proof, &public_inputs)
        .expect("verify"));
}

#[test]
fn verifier_rejects_tampered_step_circuit_hash() {
    let compressor = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct typed sonobe compressor");
    let mut vk = compressor.verifier_key();
    let acc = encode_triple(5, 0, 0);
    let public_inputs = encode_triple(11, 1, 1);
    let proof = compressor.prove(&acc, &public_inputs).expect("prove");

    vk.step_circuit_hash[0] ^= 1;
    let result = compressor.verify(&vk, &proof, &public_inputs);
    assert!(
        matches!(result, Ok(false) | Err(_)),
        "verifier must reject tampered {} step_circuit_hash type=mismatch",
        line!()
    );
}

#[test]
fn step_circuit_hash_matches_type_implementation() {
    let compressor = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct typed sonobe compressor");
    let vk = compressor.verifier_key();

    let expected_tag_hash = Keccak256::digest(pvthfhe_domain_tags::Tag::SonobeToyStep.as_bytes());
    let expected: [u8; 32] = expected_tag_hash.into();
    assert_eq!(
        vk.step_circuit_hash, expected,
        "VerifierKey step_circuit_hash must match step-circuit type hash"
    );
}
