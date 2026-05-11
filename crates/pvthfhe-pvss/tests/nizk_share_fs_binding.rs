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
fn challenge_changes_when_witness_changes() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let mut ciphertext_u = vec![0u8; 128];
    rng.fill_bytes(&mut ciphertext_u);

    let ciphertext_v = {
        let mut h = Sha256::new();
        h.update(b"ciphertext-v1");
        h.update(&ciphertext_u);
        h.finalize()
    };

    // Two different shares
    let share_a = b"share-AAAA-aaaa-AAAA-aaaa-AAAA-aaaa-AA".to_vec();
    let share_b = b"share-BBBB-bbbb-BBBB-bbbb-BBBB-bbbb-BB".to_vec();
    assert_ne!(share_a, share_b);

    // Statement uses share_commitment from share_a
    let share_commitment = compute_share_commitment(&session_id, 0, &share_a);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk.clone()),
        ciphertext_u: ProtocolBytes(ciphertext_u.clone()),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let randomness = vec![0xCCu8; 32];

    // Witness A
    let witness_a = ShareNizkWitness {
        share_bytes: ShareSecret::new(share_a.clone()),
        encryption_randomness: EncRandomness::new(randomness.clone()),
    };

    // Witness B — same statement, different share bytes
    let witness_b = ShareNizkWitness {
        share_bytes: ShareSecret::new(share_b.clone()),
        encryption_randomness: EncRandomness::new(randomness),
    };

    let proof_a = ShareNizkProver::prove(&backend, &stmt, &witness_a)
        .expect("prover must succeed for witness A");
    let proof_b = ShareNizkProver::prove(&backend, &stmt, &witness_b)
        .expect("prover must succeed for witness B");

    let opened_a = proof_a.decode().expect("decode proof A");
    let opened_b = proof_b.decode().expect("decode proof B");

    let challenge_a = opened_a.challenge;
    let challenge_b = opened_b.challenge;

    // RED: challenges are identical because commitment_ct is NOT absorbed
    // GREEN: challenges differ because commitment_ct IS absorbed before challenge derivation
    assert_ne!(
        challenge_a, challenge_b,
        "Batch A.3 RED→GREEN: Fiat-Shamir challenge must change when witness changes. \
         challenge_a == challenge_b == {:02x?} — commitment_ct not bound to transcript. \
         Fix: absorb commitment_ct before deriving challenge.",
        &challenge_a[..8]
    );
}

#[test]
fn both_proofs_verify_against_statement() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let mut ciphertext_u = vec![0u8; 128];
    rng.fill_bytes(&mut ciphertext_u);

    let ciphertext_v = {
        let mut h = Sha256::new();
        h.update(b"ciphertext-v1");
        h.update(&ciphertext_u);
        h.finalize()
    };

    let share = b"share-CCCC-cccc-CCCC-cccc-CCCC-cccc-CC".to_vec();
    let share_commitment = compute_share_commitment(&session_id, 0, &share);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        ciphertext_u: ProtocolBytes(ciphertext_u),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share.clone()),
        encryption_randomness: EncRandomness::new(vec![0xDDu8; 32]),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness)
        .expect("prover must succeed");

    // The proof should still verify (the lattice binding must remain consistent
    // after reordering the challenge derivation).
    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);
    assert!(
        result.is_ok(),
        "After FS fix, valid proofs must still verify. result = {:?}",
        result
    );
}
