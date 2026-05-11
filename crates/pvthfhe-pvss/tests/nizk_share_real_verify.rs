//! Batch A.1 RED: tampered share-commitment proof MUST be rejected.
//!
//! The current `verify_d2_hash_binding` stub returns `Ok(())` unconditionally,
//! so the verifier accepts any proof regardless of the share-commitment
//! binding.  This test constructs a statement whose `share_commitment` was
//! derived from `share_A`, then feeds the prover a **different** `share_B`
//! as the witness.  A sound D2 hash-binding check must reject such a proof.
//! The stub lets it through → RED.

use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::nizk_share::{
    compute_share_commitment, ShareNizkProver, ShareNizkStatement,
    ShareNizkVerifier, ShareNizkWitness,
};
use pvthfhe_types::{EncRandomness, ProtocolBytes, ShareSecret};
use sha2::{Digest, Sha256};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn verifier_rejects_tampered_share_commitment() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    // Two different shares
    let share_a = b"share-AAAA-aaaa-AAAA-aaaa-AAAA-aaaa-AA".to_vec(); // 37 bytes
    let share_b = b"share-BBBB-bbbb-BBBB-bbbb-BBBB-bbbb-BB".to_vec(); // 37 bytes
    assert_ne!(share_a, share_b);

    // Statement carries share_commitment derived from share_a
    let share_commitment_a = compute_share_commitment(&session_id, 0, &share_a);

    let mut random_ct = vec![0u8; 128];
    rng.fill_bytes(&mut random_ct);

    let ciphertext_v = {
        let mut h = Sha256::new();
        h.update(b"ciphertext-v1");
        h.update(&random_ct);
        h.finalize()
    };

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk.clone()),
        ciphertext_u: ProtocolBytes(random_ct),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment_a.to_vec()),
    };

    // The witness uses share_b — a DIFFERENT share than what
    // share_commitment was derived from.
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share_b.clone()),
        encryption_randomness: EncRandomness::new(vec![0xCCu8; 32]),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness)
        .expect("prover must accept self-consistent inputs");

    // A sound verifier MUST reject this proof: the share in the commitment
    // ciphertext is share_b, but share_commitment binds share_a.
    // The current stub returns Ok(()) for everything → RED.
    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);

    assert!(
        result.is_err(),
        "Batch A.1 RED: verifier accepted proof whose share_commitment binds share_a \
         while commitment ciphertext encrypts share_b. \
         D2 hash-binding stub must be replaced. result = {:?}",
        result
    );
}

#[test]
fn verifier_accepts_valid_share_commitment() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(99);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let share = b"share-CCCC-cccc-CCCC-cccc-CCCC-cccc-CC".to_vec();

    let share_commitment = compute_share_commitment(&session_id, 0, &share);

    let mut random_ct = vec![0u8; 128];
    rng.fill_bytes(&mut random_ct);

    let ciphertext_v = {
        let mut h = Sha256::new();
        h.update(b"ciphertext-v1");
        h.update(&random_ct);
        h.finalize()
    };

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        ciphertext_u: ProtocolBytes(random_ct),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    // Witness matches the statement — share_commitment was derived from
    // the same share that the prover encrypts.
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share),
        encryption_randomness: EncRandomness::new(vec![0xDDu8; 32]),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness)
        .expect("prover must accept self-consistent inputs");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);

    assert!(
        result.is_ok(),
        "Batch A.1 RED: valid proof with matching share_commitment should be accepted. \
         result = {:?}",
        result
    );
}
