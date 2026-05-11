//! R3.1 RED: Soundness - adversary forges proof for non-well-formed share.
//!
//! The verifier uses the FHE backend for structural commitment checks
//! but does not verify the full BFV encryption relation. Full lattice
//! relation checking requires real Greco NIZK integration.

use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::nizk_share::{
    compute_share_commitment, ShareNizkProof, ShareNizkProver, ShareNizkStatement,
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

fn make_consistent_but_invalid_proof(
    backend: &dyn FheBackend,
) -> (ShareNizkStatement, ShareNizkProof) {
    let mut rng = ChaCha8Rng::seed_from_u64(12345);

    let mut sid = vec![0u8; 32];
    rng.fill_bytes(&mut sid);

    let fake_share = vec![0xAAu8; 32];

    let mut random_ct = vec![0u8; 128];
    rng.fill_bytes(&mut random_ct);

    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);

    let ciphertext_v = {
        let mut h = Sha256::new();
        h.update(b"ciphertext-v1");
        h.update(&random_ct);
        h.finalize()
    };

    let share_commitment = compute_share_commitment(&sid, 0, &fake_share);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(sid),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        ciphertext_u: ProtocolBytes(random_ct),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let fake_randomness = vec![0xBBu8; 32];
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(fake_share),
        encryption_randomness: EncRandomness::new(fake_randomness),
    };

    let proof = ShareNizkProver::prove(backend, &stmt, &witness)
        .expect("prover must succeed for self-consistent statement");

    (stmt, proof)
}

#[test]
fn verifier_accepts_internally_consistent_but_invalid_proof() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let (stmt, proof) = make_consistent_but_invalid_proof(&backend);

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);

    assert!(
        result.is_ok(),
        "R3.1 RED: current verifier accepts proof for non-WF share. Result: {:?}",
        result
    );
}

#[test]
fn adversary_can_forge_proof_for_arbitrary_ciphertext() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(99999);

    let mut arbitrary_ct = vec![0u8; 200];
    rng.fill_bytes(&mut arbitrary_ct);

    let arbitrary_share = vec![0xDEu8; 64];

    let mut arbitrary_pk = vec![0x11u8; 80];
    rng.fill_bytes(&mut arbitrary_pk);

    let mut sid = vec![0u8; 32];
    rng.fill_bytes(&mut sid);

    let cv = {
        let mut h = Sha256::new();
        h.update(b"ciphertext-v1");
        h.update(&arbitrary_ct);
        h.finalize()
    };
    let sc = compute_share_commitment(&sid, 0, &arbitrary_share);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(sid),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(arbitrary_pk),
        ciphertext_u: ProtocolBytes(arbitrary_ct),
        ciphertext_v: ProtocolBytes(cv.to_vec()),
        share_commitment: ProtocolBytes(sc.to_vec()),
    };

    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(arbitrary_share),
        encryption_randomness: EncRandomness::new(vec![0xCCu8; 32]),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness)
        .expect("prover succeeds for self-consistent statement");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);
    assert!(
        result.is_ok(),
        "R3.1 RED: adversary forged a proof for non-WF share. Result: {:?}",
        result
    );
}

#[test]
fn forgery_count_over_many_attempts() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut successes = 0usize;
    let total = 100usize;

    for seed in 0..total {
        let mut rng = ChaCha8Rng::seed_from_u64(seed as u64 + 100000);

        let mut sid = vec![0u8; 32];
        rng.fill_bytes(&mut sid);
        let mut ct = vec![0u8; 64];
        rng.fill_bytes(&mut ct);
        let mut pk = vec![0u8; 48];
        rng.fill_bytes(&mut pk);
        let mut share = vec![0u8; 16];
        rng.fill_bytes(&mut share);

        let cv = {
            let mut h = Sha256::new();
            h.update(b"ciphertext-v1");
            h.update(&ct);
            h.finalize()
        };
        let sc = compute_share_commitment(&sid, 0, &share);

        let stmt = ShareNizkStatement {
            session_id: ProtocolBytes(sid),
            dealer_index: 0,
            recipient_index: 0,
            recipient_pk: ProtocolBytes(pk),
            ciphertext_u: ProtocolBytes(ct),
            ciphertext_v: ProtocolBytes(cv.to_vec()),
            share_commitment: ProtocolBytes(sc.to_vec()),
        };
        let witness = ShareNizkWitness {
            share_bytes: ShareSecret::new(share),
            encryption_randomness: EncRandomness::new(vec![0u8; 32]),
        };

        if let Ok(proof) = ShareNizkProver::prove(&backend, &stmt, &witness) {
            if ShareNizkVerifier::verify(&backend, &stmt, &proof).is_ok() {
                successes += 1;
            }
        }
    }

    assert!(
        successes == total,
        "R3.1 RED: {}/{} forgery attempts succeeded. Failures: {}",
        successes, total, total - successes
    );
}
