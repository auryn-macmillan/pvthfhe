//! D.1 share relation proof envelope privacy checks.
//!
//! The public proof may carry only non-opening relation bindings. It must not
//! expose plaintext shares or deterministic encryption randomness.

use pvthfhe_fhe::{mock::MockBackend, types::PublicKey, FheBackend};
use pvthfhe_pvss::nizk_share::{
    canonical_bfv_params_digest, compute_ciphertext_v, compute_share_commitment, ShareNizkProver,
    ShareNizkStatement, ShareNizkVerifier, ShareNizkWitness, SHARE_NIZK_DOMAIN_SEPARATOR,
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

fn make_statement(
    backend: &MockBackend,
    share: &[u8],
    randomness: &[u8; 32],
) -> ShareNizkStatement {
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);
    let mut sid = vec![0u8; 32];
    rng.fill_bytes(&mut sid);
    let mut enc_rng = ChaCha8Rng::from_seed(*randomness);
    let ct = backend
        .encrypt(&PublicKey { bytes: pk.clone() }, share, &mut enc_rng)
        .expect("encrypt share")
        .bytes;
    let cv = compute_ciphertext_v(&ct);
    let sc = compute_share_commitment(&sid, 0, share);

    ShareNizkStatement {
        session_id: ProtocolBytes(sid.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(sid),
        ciphertext_u: ProtocolBytes(ct),
        ciphertext_v: ProtocolBytes(cv.to_vec()),
        share_commitment: ProtocolBytes(sc.to_vec()),
    }
}

#[test]
fn proof_keeps_replay_relation_witness_private() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let share = vec![42u8; 32];
    let randomness = [7u8; 32];
    let stmt = make_statement(&backend, &share, &randomness);

    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share.clone()),
        encryption_randomness: EncRandomness::new(randomness.to_vec()),
    };

    let proof = ShareNizkProver::prove(&backend, &stmt, &witness).expect("prover must succeed");

    let opened = proof.decode().expect("proof must decode");
    assert_eq!(opened.domain_separator, SHARE_NIZK_DOMAIN_SEPARATOR);
    assert_eq!(opened.statement, stmt);

    assert!(!opened.commitment_bytes.is_empty());
    assert_ne!(opened.relation_binding, [0u8; 32]);
    assert!(!opened.algebraic_proof.is_empty());
    assert!(
        ShareNizkVerifier::verify(&backend, &stmt, &proof).is_err(),
        "D.1 remains incomplete: v3 proofs must fail closed because they lack a verifier-checkable BFV encryption relation"
    );
}

#[test]
fn proofs_for_different_relation_witnesses_have_different_commitments() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let share = vec![1u8; 32];
    let share2 = vec![99u8; 32];
    let randomness1 = [2u8; 32];
    let randomness2 = [88u8; 32];
    let stmt = make_statement(&backend, &share, &randomness1);
    let mut stmt2 = make_statement(&backend, &share2, &randomness2);
    stmt2.session_id = stmt.session_id.clone();
    stmt2.recipient_pk = stmt.recipient_pk.clone();
    stmt2.dkg_root = stmt.dkg_root.clone();
    let mut enc_rng = ChaCha8Rng::from_seed(randomness2);
    let ct2 = backend
        .encrypt(
            &PublicKey {
                bytes: stmt.recipient_pk.0.clone(),
            },
            &share2,
            &mut enc_rng,
        )
        .expect("encrypt share with second randomness")
        .bytes;
    stmt2.ciphertext_u = ProtocolBytes(ct2.clone());
    stmt2.ciphertext_v = ProtocolBytes(compute_ciphertext_v(&ct2).to_vec());
    stmt2.share_commitment =
        ProtocolBytes(compute_share_commitment(stmt.session_id.as_slice(), 0, &share2).to_vec());

    let witness1 = ShareNizkWitness {
        share_bytes: ShareSecret::new(share.clone()),
        encryption_randomness: EncRandomness::new(randomness1.to_vec()),
    };
    let proof1 = ShareNizkProver::prove(&backend, &stmt, &witness1).expect("prove");

    let witness2 = ShareNizkWitness {
        share_bytes: ShareSecret::new(share2),
        encryption_randomness: EncRandomness::new(randomness2.to_vec()),
    };
    let proof2 = ShareNizkProver::prove(&backend, &stmt2, &witness2).expect("prove");

    let opened1 = proof1.decode().expect("decode real");
    let opened2 = proof2.decode().expect("decode sim");

    assert_eq!(opened1.statement, stmt);
    assert_eq!(opened2.statement, stmt2);
    assert_eq!(opened1.domain_separator, SHARE_NIZK_DOMAIN_SEPARATOR);
    assert_eq!(opened2.domain_separator, SHARE_NIZK_DOMAIN_SEPARATOR);

    assert_ne!(opened1.commitment_bytes, opened2.commitment_bytes);
}
