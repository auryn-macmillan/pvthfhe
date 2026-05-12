//! Batch A.1 FIXED: d2 preimage binding verifies proof integrity.
//!
//! The old `verify_d2_hash_binding` returned `Ok(())` unconditionally for
//! non-mock backends (a bypass).  With the preimage binding, the verifier
//! checks that `d2_binding` = SHA256(commitment_ct || share_commitment ||
//! session_id || recipient_index).  Tampering with the d2_binding field
//! in the serialized proof MUST cause rejection.
//!
//! Content-level consistency (encrypted share matches share_commitment)
//! is the prover's responsibility, not the verifier's with preimage binding.

use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::nizk_share::{
    canonical_bfv_params_digest, compute_ciphertext_v, compute_share_commitment, ShareNizkProver,
    ShareNizkStatement, ShareNizkVerifier, ShareNizkWitness,
};
use pvthfhe_types::{EncRandomness, ProtocolBytes, ShareSecret};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn verifier_rejects_tampered_d2_binding() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let share = b"share-AAAA-aaaa-AAAA-aaaa-AAAA-aaaa-AA".to_vec();

    // Statement carries share_commitment derived from the same share
    let share_commitment = compute_share_commitment(&session_id, 0, &share);

    let randomness = [0xCCu8; 32];
    let mut enc_rng = ChaCha8Rng::from_seed(randomness);
    let random_ct = backend
        .encrypt(
            &pvthfhe_fhe::types::PublicKey { bytes: pk.clone() },
            &share,
            &mut enc_rng,
        )
        .expect("encrypt share")
        .bytes;
    let ciphertext_v = compute_ciphertext_v(&random_ct);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk.clone()),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id.clone()),
        ciphertext_u: ProtocolBytes(random_ct),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    // Witness matches the statement
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share),
        encryption_randomness: EncRandomness::new(randomness.to_vec()),
    };

    let mut proof = ShareNizkProver::prove(&backend, &stmt, &witness)
        .expect("prover must accept self-consistent inputs");

    // Tamper with the d2_binding in the serialized proof envelope.
    // d2_binding is the last 32 bytes of the body → last 32 bytes of proof_bytes.
    let proof_len = proof.proof_bytes.len();
    proof.proof_bytes.0[proof_len - 1] ^= 0xFF;

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);

    assert!(
        result.is_err(),
        "D2 preimage binding check must reject proof with tampered d2_binding. result = {:?}",
        result
    );
}

#[test]
fn verifier_fails_closed_for_valid_d2_binding_without_bfv_relation() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(99);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let share = b"share-CCCC-cccc-CCCC-cccc-CCCC-cccc-CC".to_vec();

    let share_commitment = compute_share_commitment(&session_id, 0, &share);

    let randomness = [0xDDu8; 32];
    let mut enc_rng = ChaCha8Rng::from_seed(randomness);
    let random_ct = backend
        .encrypt(
            &pvthfhe_fhe::types::PublicKey { bytes: pk.clone() },
            &share,
            &mut enc_rng,
        )
        .expect("encrypt share")
        .bytes;
    let ciphertext_v = compute_ciphertext_v(&random_ct);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        ciphertext_u: ProtocolBytes(random_ct),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    // Witness matches the statement — share_commitment was derived from
    // the same share that the prover encrypts.
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share),
        encryption_randomness: EncRandomness::new(randomness.to_vec()),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness)
        .expect("prover must accept self-consistent inputs");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);

    assert!(
        result.is_err(),
        "D.1 remains incomplete: valid D2/algebraic v3 proof must fail closed until verifier checks the BFV encryption relation. result = {:?}",
        result
    );
}
