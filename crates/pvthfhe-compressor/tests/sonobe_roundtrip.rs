//! Roundtrip tests for the Sonobe-backed compressor.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_compressor::sonobe::{
    encode_triple, CycloFoldStepCircuit, ExternalInputs3, SonobeCompressor, ToyStepCircuit,
};
use pvthfhe_compressor::ProofCompressor;

fn encode_triple_scalar(a: u64, b: u64, c: u64) -> Vec<u8> {
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

fn epoch() -> [u8; 32] {
    [0x10u8; 32]
}

#[test]
fn sonobe_roundtrip_toy_ivc_verifies() {
    let compressor = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct sonobe compressor");
    let acc = encode_triple_scalar(3, 0, 0);
    let public_inputs = encode_triple_scalar(7, 1, 1);
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
    let left = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct left sonobe compressor");
    let right = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct right sonobe compressor");

    assert_eq!(left.vk_bytes(), right.vk_bytes());
    assert_eq!(left.srs_hash(), right.srs_hash());
}

#[test]
fn sonobe_rejects_wrong_public_input_or_tampered_acc_binding() {
    let compressor = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct sonobe compressor");
    let acc = encode_triple_scalar(5, 0, 0);
    let honest_public_inputs = encode_triple_scalar(9, 1, 1);
    let wrong_public_inputs = encode_triple_scalar(10, 1, 1);
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
    let compressor = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct sonobe compressor");
    let acc = encode_triple_scalar(12, 0, 0);
    let public_inputs = encode_triple_scalar(4, 1, 1);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove toy ivc");
    let vk = compressor.verifier_key();

    let truncated = pvthfhe_compressor::CompressedProof(proof.0[..75].to_vec());
    let result = compressor.verify(&vk, &truncated, &public_inputs);

    assert!(matches!(result, Ok(false) | Err(_)));
}

#[test]
fn m6_verifier_rejects_when_ring_equation_failed() {
    // Use CycloFoldStepCircuit (state_len=4) where ext.2 is ring verification result.
    let compressor = SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 3)
        .expect("construct cyclo fold compressor");

    // ext.2 = 0 simulates a failed ring equation.
    // The circuit will compute: fold_count = 3 (hardcoded +1 per step),
    // verification_count = 0 (0 + 0 + 0). Verifier must reject.
    let acc = encode_triple_scalar(5, 0, 0);
    let public_inputs = encode_triple_scalar(7, 1, 0); // ext.2 = 0 = FAILED

    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove with failed ring check");
    let vk = compressor.verifier_key();

    let result = compressor.verify(&vk, &proof, &public_inputs);
    assert!(
        matches!(result, Ok(false) | Err(_)),
        "M6: verifier must reject when ring equation failed (ext.2=0)"
    );
}

#[test]
fn m6_verifier_accepts_when_ring_equation_passed() {
    // ext.2 = 1 simulates a passed ring equation.
    // verification_count == fold_count → verifier accepts.
    let compressor = SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 3)
        .expect("construct cyclo fold compressor");

    let acc = encode_triple_scalar(5, 0, 0);
    let public_inputs = encode_triple_scalar(7, 1, 1); // ext.2 = 1 = PASSED

    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove with passed ring check");
    let vk = compressor.verifier_key();

    let result = compressor.verify(&vk, &proof, &public_inputs);
    assert!(
        matches!(result, Ok(true)),
        "M6: verifier must accept when all ring equations passed (ext.2=1)"
    );
}

#[test]
fn m6_verifier_rejects_mixed_ring_results_via_steps() {
    // Use prove_steps for per-step external inputs.
    // Step 0: ext.2=1 (passed), step 1: ext.2=0 (failed), step 2: ext.2=1 (passed)
    // fold_count=3, verification_count=2 → verifier must reject.
    let compressor = SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 3)
        .expect("construct cyclo fold compressor");

    let acc = encode_triple_scalar(5, 0, 0);
    let steps = vec![
        ExternalInputs3(Fr::from(7u64), Fr::from(1u64), Fr::from(1u64)), // passed
        ExternalInputs3(Fr::from(7u64), Fr::from(1u64), Fr::from(0u64)), // failed
        ExternalInputs3(Fr::from(7u64), Fr::from(1u64), Fr::from(1u64)), // passed
    ];

    let proof = compressor
        .prove_steps(&acc, &steps)
        .expect("prove_steps with mixed ring results");
    let vk = compressor.verifier_key();

    let result = compressor.verify_steps(&vk, &proof, &steps);
    assert!(
        matches!(result, Ok(false) | Err(_)),
        "M6: verifier must reject when some ring equations failed (verification_count=2 != fold_count=3)"
    );
}
