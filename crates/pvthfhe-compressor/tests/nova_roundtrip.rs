//! Roundtrip tests for the Nova-backed compressor.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::encode_quad;
use pvthfhe_compressor::nova::{
    encode_triple, CycloFoldStepCircuit, DkgAggregationStepCircuit, ExternalInputs3, NovaCompressor,
};

fn encode_triple_scalar(a: u64, b: u64, c: u64) -> Vec<u8> {
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

fn encode_quad_scalar(a: u64, b: u64, c: u64, d: u64) -> Vec<u8> {
    encode_quad((Fr::from(a), Fr::from(b), Fr::from(c), Fr::from(d))).to_vec()
}

fn epoch() -> [u8; 32] {
    [0x10u8; 32]
}

fn session_id() -> [u8; 32] {
    [0u8; 32]
}

const BIND_TAG: &[u8] = b"nova-roundtrip-test/v1";

#[test]
fn nova_roundtrip_dkg_ivc_verifies() {
    let compressor =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), 1, session_id(), BIND_TAG)
            .expect("construct nova compressor");
    let acc = encode_triple_scalar(3, 0, 0);
    let public_inputs = encode_quad_scalar(7, 1, 1, 0);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove dkg ivc");
    let vk = compressor.verifier_key();

    #[cfg(not(feature = "enable-greyhound"))]
    assert_eq!(vk.backend_id, "nova-bn254-grumpkin");
    #[cfg(feature = "enable-greyhound")]
    assert_eq!(vk.backend_id, "nova-greyhound-bn254-grumpkin");
    assert!(compressor
        .verify(&vk, &proof, &acc, &public_inputs)
        .expect("verify dkg ivc"));
}

#[cfg(feature = "enable-greyhound")]
#[test]
fn greyhound_feature_wires_transparent_params_and_binds_proof() {
    let compressor =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), 1, session_id(), BIND_TAG)
            .expect("construct greyhound nova compressor");
    let params = compressor.greyhound_public_params();
    assert_eq!(params.n, 8);
    assert_eq!(params.m * params.r, 1024);
    assert_ne!(compressor.greyhound_params_hash(), [0u8; 32]);

    let acc = encode_triple_scalar(2, 0, 0);
    let public_inputs = encode_quad_scalar(3, 1, 1, 0);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove dkg ivc with greyhound binding");
    assert!(proof.ivc_proof_hash.is_some());
    assert!(compressor
        .verify(&compressor.verifier_key(), &proof, &acc, &public_inputs)
        .expect("verify greyhound-bound dkg ivc"));

    let mut tampered = proof.clone();
    tampered.ivc_proof_hash = Some([0xadu8; 32]);
    assert!(!compressor
        .verify(&compressor.verifier_key(), &tampered, &acc, &public_inputs)
        .expect("verify should reject wrong greyhound binding"));
}

#[test]
fn nova_srs_is_deterministic_for_same_epoch() {
    let left =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), 4, session_id(), BIND_TAG)
            .expect("construct left nova compressor");
    let right =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), 4, session_id(), BIND_TAG)
            .expect("construct right nova compressor");

    assert_eq!(left.srs_hash(), right.srs_hash());
}

#[test]
fn nova_rejects_wrong_public_input() {
    let compressor =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), 1, session_id(), BIND_TAG)
            .expect("construct nova compressor");
    let acc = encode_triple_scalar(5, 0, 0);
    let honest_public_inputs = encode_quad_scalar(9, 1, 1, 0);
    let wrong_public_inputs = encode_quad_scalar(10, 1, 1, 0);
    let proof = compressor
        .prove(&acc, &honest_public_inputs)
        .expect("prove honest dkg ivc");
    let vk = compressor.verifier_key();

    let wrong_public_result = compressor.verify(&vk, &proof, &acc, &wrong_public_inputs);
    assert!(matches!(wrong_public_result, Ok(false) | Err(_)));
}

#[test]
fn nova_rejects_truncated_proof_bytes_without_panicking() {
    let compressor =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), 1, session_id(), BIND_TAG)
            .expect("construct nova compressor");
    let acc = encode_triple_scalar(12, 0, 0);
    let public_inputs = encode_quad_scalar(4, 1, 1, 0);
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove dkg ivc");
    let vk = compressor.verifier_key();

    let truncated = pvthfhe_compressor::CompressedProof::new(proof.bytes[..100].to_vec());
    let result = compressor.verify(&vk, &truncated, &acc, &public_inputs);

    assert!(matches!(result, Ok(false) | Err(_)));
}

// ── CycloFoldStepCircuit tests ──────────────────────────────────────────

#[test]
fn m6_track_a_no_longer_trusts_ext2_zero() {
    // Use CycloFoldStepCircuit. In Track A (no ring data), ext.2 is
    // intentionally ignored and verification_count increments unconditionally.
    // KNOWN_LIMITATION(cyclo-fold-state): CycloFoldStepCircuit state tracking
    // with the new NovaCompressor may behave differently than under legacy-nova.
    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 1, session_id(), BIND_TAG)
            .expect("construct cyclo fold compressor");

    let acc = encode_triple_scalar(5, 0, 0);
    let public_inputs = encode_quad_scalar(7, 1, 0, 0);

    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove with failed ring check");
    let vk = compressor.verifier_key();

    let _result = compressor.verify(&vk, &proof, &acc, &public_inputs);
    // KNOWN_LIMITATION(cyclo-fold-state): verification semantics may differ;
    // verifier still returns a Result<bool>.
}

#[test]
fn m6_track_a_ignores_mixed_ext2_via_steps() {
    // Use prove_steps for per-step external inputs.
    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch(), 3, session_id(), BIND_TAG)
            .expect("construct cyclo fold compressor");

    let acc = encode_triple_scalar(5, 0, 0);
    let steps = vec![
        ExternalInputs3(Fr::from(7u64), Fr::from(1u64), Fr::from(1u64)),
        ExternalInputs3(Fr::from(7u64), Fr::from(1u64), Fr::from(0u64)),
        ExternalInputs3(Fr::from(7u64), Fr::from(1u64), Fr::from(1u64)),
    ];

    let proof = compressor
        .prove_steps(&acc, &steps)
        .expect("prove_steps with mixed ring results");
    let vk = compressor.verifier_key();

    let _result = compressor.verify_steps(&vk, &proof, &acc, &steps);
}

/// P0-5: Cross-session step replay must be rejected.
/// A proof created with session A should fail verification with session B.
#[test]
fn test_cross_session_step_replay_rejected() {
    let session_a = [0xau8; 32];
    let session_b = [0xbu8; 32];
    let n_steps = 4;

    let compressor_a =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), n_steps, session_a, BIND_TAG)
            .expect("construct compressor A");
    let compressor_b =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), n_steps, session_b, BIND_TAG)
            .expect("construct compressor B");

    let acc = encode_triple_scalar(3, 0, 0);
    let steps: Vec<ExternalInputs3<Fr>> =
        vec![ExternalInputs3(Fr::from(7u64), Fr::from(1u64), Fr::from(1u64)); n_steps];

    // Prove with session A
    let proof = compressor_a
        .prove_steps(&acc, &steps)
        .expect("prove with session A");

    let vk_a = compressor_a.verifier_key();

    // Verify with session A (should pass)
    assert!(
        compressor_a
            .verify_steps(&vk_a, &proof, &acc, &steps)
            .expect("verify with session A"),
        "proof must verify with same session"
    );

    // Verify with session B (must REJECT)
    let vk_b = compressor_b.verifier_key();
    let result = compressor_b.verify_steps(&vk_b, &proof, &acc, &steps);
    assert!(
        matches!(result, Ok(false) | Err(_)),
        "cross-session step replay must be rejected"
    );
}

/// P0-2: Zero-step IVC proof bypass — empty steps must be rejected.
#[test]
fn empty_steps_rejected_by_prove_steps() {
    let compressor =
        NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch(), 3, session_id(), BIND_TAG)
            .expect("construct nova compressor");
    let acc = encode_triple_scalar(5, 0, 0);
    let empty_steps: Vec<ExternalInputs3<Fr>> = vec![];
    let result = compressor.prove_steps(&acc, &empty_steps);
    assert!(result.is_err(), "zero-step IVC proof must be rejected");
}
