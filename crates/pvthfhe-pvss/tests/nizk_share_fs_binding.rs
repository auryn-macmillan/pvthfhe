//! Batch A.3 RED: Fiat-Shamir challenge MUST bind the prover's commitment.
//!
//! The FS challenge is currently derived from the statement alone,
//! ignoring the prover's commitment ciphertext.  This means two proofs
//! with different witnesses (hence different commitment_ct) produce
//! the same challenge — the transcript does not bind the witness.
//! A correct FS transform must absorb commitment_ct before deriving
//! the challenge, so that different witnesses produce different challenges.
//!
//! RED: challenge_a == challenge_b (no witness binding)
//! GREEN: challenge_a != challenge_b (witness bound via commitment_ct)

use pvthfhe_fhe::{mock::MockBackend, types::PublicKey, FheBackend};
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
fn challenge_changes_when_witness_changes() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let share_a = b"share-AAAA-aaaa-AAAA-aaaa-AAAA-aaaa-AA".to_vec();
    let share_b = b"share-BBBB-bbbb-BBBB-bbbb-BBBB-bbbb-BB".to_vec();
    let mut enc_seed_a = [0xCAu8; 32];
    let mut enc_seed_b = [0xCBu8; 32];
    enc_seed_a[0] = 1;
    enc_seed_b[0] = 2;
    let mut enc_rng_a = ChaCha8Rng::from_seed(enc_seed_a);
    let ciphertext_u_a = backend
        .encrypt(&PublicKey { bytes: pk.clone() }, &share_a, &mut enc_rng_a)
        .expect("encrypt share A")
        .bytes;
    let ciphertext_v_a = compute_ciphertext_v(&ciphertext_u_a);

    let share_commitment = compute_share_commitment(&session_id, 0, &share_a);

    let stmt_a = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk.clone()),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id.clone()),
        ciphertext_u: ProtocolBytes(ciphertext_u_a),
        ciphertext_v: ProtocolBytes(ciphertext_v_a.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };
    let mut enc_rng_b = ChaCha8Rng::from_seed(enc_seed_b);
    let ciphertext_u_b = backend
        .encrypt(&PublicKey { bytes: pk.clone() }, &share_b, &mut enc_rng_b)
        .expect("encrypt share B")
        .bytes;
    let ciphertext_v_b = compute_ciphertext_v(&ciphertext_u_b);
    let share_commitment_b = compute_share_commitment(&session_id, 0, &share_b);
    let stmt_b = ShareNizkStatement {
        ciphertext_u: ProtocolBytes(ciphertext_u_b),
        ciphertext_v: ProtocolBytes(ciphertext_v_b.to_vec()),
        share_commitment: ProtocolBytes(share_commitment_b.to_vec()),
        ..stmt_a.clone()
    };

    let witness_a = ShareNizkWitness {
        share_bytes: ShareSecret::new(share_a.clone()),
        encryption_randomness: EncRandomness::new(enc_seed_a.to_vec()),
    };
    let witness_b = ShareNizkWitness {
        share_bytes: ShareSecret::new(share_b),
        encryption_randomness: EncRandomness::new(enc_seed_b.to_vec()),
    };

    let proof_a = ShareNizkProver::prove(&backend, &stmt_a, &witness_a, None)
        .expect("prover must succeed for witness A");
    let proof_b = ShareNizkProver::prove(&backend, &stmt_b, &witness_b, None)
        .expect("prover must succeed for witness B");

    let opened_a = proof_a.decode().expect("decode proof A");
    let opened_b = proof_b.decode().expect("decode proof B");

    let challenge_a = opened_a.challenge;
    let challenge_b = opened_b.challenge;

    // RED: challenges are identical because commitment_ct is NOT absorbed
    // GREEN: challenges differ because commitment_ct IS absorbed before challenge derivation
    assert_ne!(
        challenge_a,
        challenge_b,
        "Batch A.3 RED→GREEN: Fiat-Shamir challenge must change when witness changes. \
         challenge_a == challenge_b == {:02x?} — commitment_ct not bound to transcript. \
         Fix: absorb commitment_ct before deriving challenge.",
        &challenge_a[..8]
    );
}

#[test]
fn valid_v3_proof_fails_closed_until_bfv_relation_exists() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let share = b"share-CCCC-cccc-CCCC-cccc-CCCC-cccc-CC".to_vec();
    let enc_seed = [0xDDu8; 32];
    let mut enc_rng = ChaCha8Rng::from_seed(enc_seed);
    let ciphertext_u = backend
        .encrypt(&PublicKey { bytes: pk.clone() }, &share, &mut enc_rng)
        .expect("encrypt share")
        .bytes;
    let ciphertext_v = compute_ciphertext_v(&ciphertext_u);
    let share_commitment = compute_share_commitment(&session_id, 0, &share);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        ciphertext_u: ProtocolBytes(ciphertext_u),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share.clone()),
        encryption_randomness: EncRandomness::new(enc_seed.to_vec()),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness, None).expect("prover must succeed");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);
    assert!(
        result.is_err(),
        "D.1 remains incomplete: v3 proof lacks a verifier-checkable BFV encryption relation. result = {:?}",
        result
    );
}
