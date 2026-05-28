#![cfg(feature = "legacy-nova")]
//! Roundtrip tests for the Nova-backed compressor.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_compressor::nova::{
    encode_triple, CycloFoldStepCircuit, ExternalInputs3, NovaCompressor, ToyStepCircuit,
};
use pvthfhe_compressor::ProofCompressor;

fn encode_triple_scalar(a: u64, b: u64, c: u64) -> Vec<u8> {
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

fn epoch() -> [u8; 32] {
    [0x10u8; 32]
}

#[test]
fn nova_roundtrip_toy_ivc_verifies() {
    let compressor =
        NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct nova compressor");
    let acc = encode_triple_scalar(3, 0, 0);
    let public_inputs = encode_triple_scalar(7, 1, 1);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove toy ivc");
    let vk = compressor.verifier_key();

    assert_eq!(compressor.backend_id(), "nova-bn254-grumpkin");
    assert!(compressor
        .verify(&vk, &proof, &acc, &public_inputs)
        .expect("verify toy ivc"));
}

#[test]
fn nova_srs_is_deterministic_for_same_epoch() {
    let left = NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct left nova compressor");
    let right = NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct right nova compressor");

    assert_eq!(left.vk_bytes(), right.vk_bytes());
    assert_eq!(left.srs_hash(), right.srs_hash());
}

#[test]
fn nova_rejects_wrong_public_input_or_tampered_acc_binding() {
    let compressor =
        NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct nova compressor");
    let acc = encode_triple_scalar(5, 0, 0);
    let honest_public_inputs = encode_triple_scalar(9, 1, 1);
    let wrong_public_inputs = encode_triple_scalar(10, 1, 1);
    let proof = compressor
        .prove(&acc, &honest_public_inputs)
        .expect("prove honest toy ivc");
    let vk = compressor.verifier_key();

    let wrong_public_result = compressor.verify(&vk, &proof, &acc, &wrong_public_inputs);
    assert!(matches!(wrong_public_result, Ok(false) | Err(_)));

    let mut tampered_acc_binding = proof.clone();
    tampered_acc_binding.0[8] ^= 1;
    let tampered_result =
        compressor.verify(&vk, &tampered_acc_binding, &acc, &honest_public_inputs);
    assert!(matches!(tampered_result, Ok(false) | Err(_)));
}

#[test]
fn nova_rejects_truncated_proof_bytes_without_panicking() {
    let compressor =
        NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch(), 4).expect("construct nova compressor");
    let acc = encode_triple_scalar(12, 0, 0);
    let public_inputs = encode_triple_scalar(4, 1, 1);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove toy ivc");
    let vk = compressor.verifier_key();

    let truncated = pvthfhe_compressor::CompressedProof(proof.0[..75].to_vec());
    let result = compressor.verify(&vk, &truncated, &acc, &public_inputs);

    assert!(matches!(result, Ok(false) | Err(_)));
}

#[test]
fn m6_track_a_no_longer_trusts_ext2_zero() {
    // Use CycloFoldStepCircuit (state_len=5). In Track A (no ring data), ext.2 is
    // intentionally ignored and verification_count increments unconditionally.
    let compressor = NovaCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 3)
        .expect("construct cyclo fold compressor");

    let acc = encode_triple_scalar(5, 0, 0);
    let public_inputs = encode_triple_scalar(7, 1, 0);

    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove with failed ring check");
    let vk = compressor.verifier_key();

    let result = compressor.verify(&vk, &proof, &acc, &public_inputs);
    assert!(
        matches!(result, Ok(false)),
        "G7: CycloFold verification must fail closed when in-circuit witnesses are absent"
    );
}

#[test]
fn m6_verifier_accepts_when_ring_equation_passed() {
    // ext.2 = 1 simulates a passed ring equation.
    // verification_count == fold_count → verifier accepts.
    let compressor = NovaCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 3)
        .expect("construct cyclo fold compressor");

    let acc = encode_triple_scalar(5, 0, 0);
    let public_inputs = encode_triple_scalar(7, 1, 1); // ext.2 = 1 = PASSED

    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove with passed ring check");
    let vk = compressor.verifier_key();

    let result = compressor.verify(&vk, &proof, &acc, &public_inputs);
    assert!(
        matches!(result, Ok(false)),
        "G7: ext.2 alone must not satisfy ring/sigma verification counts"
    );
}

#[test]
fn m6_track_a_ignores_mixed_ext2_via_steps() {
    // Use prove_steps for per-step external inputs. With no ring data, ext.2 is
    // ignored and the verification counter is a duplicate step counter.
    let compressor = NovaCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 3)
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

    let result = compressor.verify_steps(&vk, &proof, &acc, &steps);
    assert!(
        matches!(result, Ok(false)),
        "G7: mixed ext.2 values cannot replace in-circuit ring/sigma witnesses"
    );
}
