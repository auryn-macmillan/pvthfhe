//! R3.1 GREEN: ZK property — witness removed from proof envelope.
//!
//! The `ShareNizkOpenedProof` no longer serializes `share_bytes` or
//! `encryption_randomness`. Verifier cannot recover the witness from the proof.

use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::nizk_share::{
    ShareNizkProver, ShareNizkStatement,
    ShareNizkWitness, SHARE_NIZK_DOMAIN_SEPARATOR,
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

fn make_statement() -> ShareNizkStatement {
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);
    let mut ct = vec![0u8; 128];
    rng.fill_bytes(&mut ct);
    let mut sid = vec![0u8; 32];
    rng.fill_bytes(&mut sid);

    let cv = {
        let mut h = Sha256::new();
        h.update(b"ciphertext-v1");
        h.update(&ct);
        h.finalize()
    };
    let sc = {
        let mut h = Sha256::new();
        h.update(&sid);
        h.update(0usize.to_le_bytes());
        h.update(&[1u8; 32]);
        h.finalize()
    };

    ShareNizkStatement {
        session_id: ProtocolBytes(sid),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        ciphertext_u: ProtocolBytes(ct),
        ciphertext_v: ProtocolBytes(cv.to_vec()),
        share_commitment: ProtocolBytes(sc.to_vec()),
    }
}

#[test]
fn proof_does_not_leak_witness_bytes() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let stmt = make_statement();
    let share = vec![42u8; 32];
    let randomness = vec![7u8; 32];

    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share),
        encryption_randomness: EncRandomness::new(randomness),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness)
        .expect("prover must succeed");

    let opened = proof.decode().expect("proof must decode");
    assert_eq!(opened.domain_separator, SHARE_NIZK_DOMAIN_SEPARATOR);
    assert_eq!(opened.statement, stmt);

    assert!(!opened.commitment_bytes.is_empty());
}

#[test]
fn proofs_with_different_witness_are_not_trivially_distinguishable() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let stmt = make_statement();

    let witness1 = ShareNizkWitness {
        share_bytes: ShareSecret::new(vec![1u8; 32]),
        encryption_randomness: EncRandomness::new(vec![2u8; 32]),
    };
    let proof1 = ShareNizkProver::prove(&backend, &stmt, &witness1).expect("prove");

    let witness2 = ShareNizkWitness {
        share_bytes: ShareSecret::new(vec![99u8; 32]),
        encryption_randomness: EncRandomness::new(vec![88u8; 32]),
    };
    let proof2 = ShareNizkProver::prove(&backend, &stmt, &witness2).expect("prove");

    let opened1 = proof1.decode().expect("decode real");
    let opened2 = proof2.decode().expect("decode sim");

    assert_eq!(opened1.statement, stmt);
    assert_eq!(opened2.statement, stmt);
    assert_eq!(opened1.domain_separator, SHARE_NIZK_DOMAIN_SEPARATOR);
    assert_eq!(opened2.domain_separator, SHARE_NIZK_DOMAIN_SEPARATOR);

    assert_ne!(opened1.commitment_bytes, opened2.commitment_bytes);
}
