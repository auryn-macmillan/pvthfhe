//! R3.1 RED: Soundness - adversary forges proof for non-well-formed share.
//!
//! The verifier uses the FHE backend for structural commitment checks
//! but does not verify the full BFV encryption relation. Full lattice
//! relation checking requires real Greco NIZK integration.

use pvthfhe_fhe::{mock::MockBackend, types::PublicKey, FheBackend};
use pvthfhe_nizk::fiat_shamir::Transcript;
use pvthfhe_nizk::sigma::{
    self, SigmaProof, SigmaStatement, SigmaWitness, RLWE_N, RLWE_Q0, RLWE_Q1, RLWE_Q2,
};
use pvthfhe_pvss::nizk_share::{
    canonical_bfv_params_digest, compute_ciphertext_v, compute_share_commitment,
    ShareNizkOpenedProof, ShareNizkProof, ShareNizkProver, ShareNizkStatement, ShareNizkVerifier,
    ShareNizkWitness, SHARE_NIZK_DOMAIN_SEPARATOR,
};
use pvthfhe_types::{EncRandomness, ProtocolBytes, ShareSecret};
use rand_chacha::ChaCha20Rng;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";
const DIGEST_LEN: usize = 32;
const CHALLENGE_LEN: usize = 32;

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

fn aggregate_single_party_pk(backend: &MockBackend, session_id: &[u8; 32]) -> Vec<u8> {
    let mut rng = ChaCha8Rng::seed_from_u64(0xD101);
    let share = backend
        .keygen_share_with_session(session_id, 1, &mut rng)
        .expect("keygen share");
    backend.setup_threshold(1, 1).expect("threshold setup");
    backend
        .aggregate_keygen(&[share])
        .expect("aggregate keygen")
        .bytes
}

#[test]
fn verifier_rejects_ciphertext_share_commitment_mismatch() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let session_id = [0x44u8; 32];
    let recipient_pk = aggregate_single_party_pk(&backend, &session_id);
    let share_a = b"share-AAAA-aaaa-AAAA-aaaa-AAAA-aaaa-AA".to_vec();
    let share_b = b"share-BBBB-bbbb-BBBB-bbbb-BBBB-bbbb-BB".to_vec();
    assert_ne!(share_a, share_b);

    let mut enc_rng = ChaCha8Rng::seed_from_u64(0xD102);
    let ciphertext_u = backend
        .encrypt(
            &PublicKey {
                bytes: recipient_pk.clone(),
            },
            &share_a,
            &mut enc_rng,
        )
        .expect("encrypt share A")
        .bytes;
    let ciphertext_v = compute_ciphertext_v(&ciphertext_u);
    let share_commitment = compute_share_commitment(&session_id, 0, &share_b);
    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.to_vec()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(recipient_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id.to_vec()),
        ciphertext_u: ProtocolBytes(ciphertext_u),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share_b),
        encryption_randomness: EncRandomness::new(vec![0xD1; 32]),
    };

    let result = ShareNizkProver::prove(&backend, &stmt, &witness)
        .and_then(|proof| ShareNizkVerifier::verify(&backend, &stmt, &proof));
    assert!(
        result.is_err(),
        "prover/verifier path must reject ciphertext/share_commitment mismatch through BFV relation check"
    );
}

fn make_consistent_but_invalid_proof(
    backend: &dyn FheBackend,
) -> Result<(), pvthfhe_pvss::PvssError> {
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
        session_id: ProtocolBytes(sid.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(stmt_dkg_root_from_sid(&sid)),
        ciphertext_u: ProtocolBytes(random_ct),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let fake_randomness = vec![0xBBu8; 32];
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(fake_share),
        encryption_randomness: EncRandomness::new(fake_randomness),
    };

    ShareNizkProver::prove(backend, &stmt, &witness).map(|_| ())
}

fn stmt_dkg_root_from_sid(sid: &[u8]) -> Vec<u8> {
    sid.to_vec()
}

#[test]
fn verifier_accepts_internally_consistent_but_invalid_proof() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    // v4: prover no longer rejects at produce-time; verifier rejects at BFV relation boundary.
    // Build a valid proof, then tamper with ciphertext to trigger rejection.
    let mut rng = ChaCha8Rng::seed_from_u64(12345);
    let mut sid = vec![0u8; 32];
    rng.fill_bytes(&mut sid);
    let share = vec![0xAAu8; 32];
    let mut pk = vec![0u8; 64];
    rng.fill_bytes(&mut pk);
    let mut enc_rng = ChaCha8Rng::seed_from_u64(54321);
    let ciphertext_u = backend
        .encrypt(&PublicKey { bytes: pk.clone() }, &share, &mut enc_rng)
        .expect("encrypt share")
        .bytes;
    let ciphertext_v = compute_ciphertext_v(&ciphertext_u);
    let share_commitment = compute_share_commitment(&sid, 0, &share);
    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(sid.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(sid),
        ciphertext_u: ProtocolBytes(ciphertext_u),
        ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };
    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(share),
        encryption_randomness: EncRandomness::new(vec![0xBBu8; 32]),
    };
    let proof =
        ShareNizkProver::prove(&backend, &stmt, &witness).expect("v4 prover produces proof");
    // Tamper ciphertext in proof statement to mismatch
    let mut tampered_stmt = stmt.clone();
    tampered_stmt.ciphertext_u = ProtocolBytes(vec![0xFF; 128]);
    tampered_stmt.ciphertext_v =
        ProtocolBytes(compute_ciphertext_v(tampered_stmt.ciphertext_u.as_slice()).to_vec());
    let result = ShareNizkVerifier::verify(&backend, &tampered_stmt, &proof);
    assert!(
        result.is_err(),
        "D.1 GREEN: verifier must reject proof for non-WF ciphertext through BFV relation check"
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
        session_id: ProtocolBytes(sid.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(arbitrary_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(sid.clone()),
        ciphertext_u: ProtocolBytes(arbitrary_ct),
        ciphertext_v: ProtocolBytes(cv.to_vec()),
        share_commitment: ProtocolBytes(sc.to_vec()),
    };

    let witness = ShareNizkWitness {
        share_bytes: ShareSecret::new(arbitrary_share),
        encryption_randomness: EncRandomness::new(vec![0xCCu8; 32]),
    };

    let result = ShareNizkProver::prove(&backend, &stmt, &witness)
        .and_then(|proof| ShareNizkVerifier::verify(&backend, &stmt, &proof));
    assert!(
        result.is_err(),
        "D.1 GREEN: adversary must not forge a proof for non-WF share. Result: {:?}",
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
            session_id: ProtocolBytes(sid.clone()),
            dealer_index: 0,
            recipient_index: 0,
            recipient_pk: ProtocolBytes(pk),
            bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
            dkg_root: ProtocolBytes(sid.clone()),
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
        successes == 0,
        "D.1 GREEN: {}/{} arbitrary-ciphertext forgery attempts succeeded",
        successes,
        total
    );
}

#[test]
fn verifier_rejects_direct_opened_proof_with_arbitrary_ciphertext() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(0xD101_D1EC7);

    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);
    let mut recipient_pk = vec![0u8; 64];
    rng.fill_bytes(&mut recipient_pk);
    let committed_share = vec![7u8; 48];
    let mut arbitrary_ciphertext = vec![0u8; 192];
    rng.fill_bytes(&mut arbitrary_ciphertext);
    let share_commitment = compute_share_commitment(&session_id, 0, &committed_share);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(recipient_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        ciphertext_u: ProtocolBytes(arbitrary_ciphertext.clone()),
        ciphertext_v: ProtocolBytes(compute_ciphertext_v(&arbitrary_ciphertext).to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let algebraic_proof = forge_algebraic_proof_for_statement(&stmt, &committed_share);
    let relation_binding = test_relation_binding(&stmt, &algebraic_proof);
    let commitment_bytes = ProtocolBytes(b"attacker-chosen-commitment".to_vec());
    let commitment_binding = test_commitment_binding(&stmt, &relation_binding);
    let challenge = test_challenge(&stmt, commitment_bytes.as_slice());

    let opened = ShareNizkOpenedProof {
        statement: stmt.clone(),
        commitment_bytes: commitment_bytes.clone(),
        commitment_seed: [0u8; DIGEST_LEN],
        commitment_binding,
        challenge,
        lattice_binding: test_lattice_binding(
            &stmt,
            commitment_bytes.as_slice(),
            &commitment_binding,
            &challenge,
            &relation_binding,
        ),
        relation_binding,
        algebraic_proof: ProtocolBytes(algebraic_proof),
        d2_binding: test_d2_binding(&stmt, commitment_bytes.as_slice(), &relation_binding),
        bfv_encryption_proof: ProtocolBytes(vec![]),
        domain_separator: SHARE_NIZK_DOMAIN_SEPARATOR.to_owned(),
    };
    let proof = ShareNizkProof::from_opened(&opened).expect("attacker can serialize opened proof");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);
    assert!(
        result.is_err(),
        "D.1 RED: verifier accepted a directly constructed proof for a valid committed share bound only by hashes to arbitrary ciphertext_u: {:?}",
        result
    );
}

#[test]
fn verifier_rejects_direct_opened_proof_encrypting_one_share_but_committing_another() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let session_id = [0xD1u8; 32];
    let recipient_pk = aggregate_single_party_pk(&backend, &session_id);
    let encrypted_share = b"share-AAAA-aaaa-AAAA-aaaa-AAAA-aaaa-AA".to_vec();
    let committed_share = b"share-BBBB-bbbb-BBBB-bbbb-BBBB-bbbb-BB".to_vec();
    assert_ne!(encrypted_share, committed_share);

    let mut enc_rng = ChaCha8Rng::seed_from_u64(0xD1EC7ED);
    let ciphertext_u = backend
        .encrypt(
            &PublicKey {
                bytes: recipient_pk.clone(),
            },
            &encrypted_share,
            &mut enc_rng,
        )
        .expect("encrypt share A")
        .bytes;
    let share_commitment = compute_share_commitment(&session_id, 0, &committed_share);

    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.to_vec()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(recipient_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id.to_vec()),
        ciphertext_u: ProtocolBytes(ciphertext_u.clone()),
        ciphertext_v: ProtocolBytes(compute_ciphertext_v(&ciphertext_u).to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let algebraic_proof = forge_algebraic_proof_for_statement(&stmt, &committed_share);
    let relation_binding = test_relation_binding(&stmt, &algebraic_proof);
    let commitment_bytes = ProtocolBytes(b"attacker-chosen-mismatch-commitment".to_vec());
    let commitment_binding = test_commitment_binding(&stmt, &relation_binding);
    let challenge = test_challenge(&stmt, commitment_bytes.as_slice());
    let opened = ShareNizkOpenedProof {
        statement: stmt.clone(),
        commitment_bytes: commitment_bytes.clone(),
        commitment_seed: [0u8; DIGEST_LEN],
        commitment_binding,
        challenge,
        lattice_binding: test_lattice_binding(
            &stmt,
            commitment_bytes.as_slice(),
            &commitment_binding,
            &challenge,
            &relation_binding,
        ),
        relation_binding,
        algebraic_proof: ProtocolBytes(algebraic_proof),
        d2_binding: test_d2_binding(&stmt, commitment_bytes.as_slice(), &relation_binding),
        bfv_encryption_proof: ProtocolBytes(vec![]),
        domain_separator: SHARE_NIZK_DOMAIN_SEPARATOR.to_owned(),
    };
    let proof =
        ShareNizkProof::from_opened(&opened).expect("attacker can serialize mismatch proof");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);
    assert!(
        result.is_err(),
        "D.1 RED: verifier accepted proof whose ciphertext encrypts one share while share_commitment and algebraic proof bind another: {:?}",
        result
    );
}

fn forge_algebraic_proof_for_statement(stmt: &ShareNizkStatement, share: &[u8]) -> Vec<u8> {
    let s_i = test_share_sigma_witness(share);
    let e_i = vec![0i64; RLWE_N];
    let c_rns = test_share_sigma_c_rns(stmt.session_id.as_slice(), stmt.recipient_index);
    let d_rns = sigma::compute_d_rns(&c_rns, &s_i, &e_i).expect("compute d_rns");
    // D.1: share_commitment now uses Ajtai D2 binding, not sigma D2.
    // The algebraic proof's d_rns is valid for the sigma relation but does
    // not need to match the share_commitment via SHA-256.
    let _ = stmt.share_commitment.as_slice(); // keep statement binding alive
    let sigma_stmt = SigmaStatement {
        c_rns,
        d_rns: d_rns.clone(),
    };
    let sigma_witness = SigmaWitness { s_i, e_i };
    let mut proof_rng = ChaCha20Rng::from_seed([0xA5; 32]);
    let proof = sigma::prove(
        &test_share_sigma_session_binding(stmt),
        u32::try_from(stmt.recipient_index).expect("recipient index fits u32"),
        &sigma_stmt,
        &sigma_witness,
        &test_digest_sigma_d(&d_rns),
        &mut proof_rng,
    )
    .expect("sigma prove");
    test_encode_algebraic_proof(&d_rns, &proof)
}

fn test_share_sigma_witness(share: &[u8]) -> Vec<i64> {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-sigma-witness-digest-v1");
    h.update(
        u64::try_from(share.len())
            .expect("share len fits u64")
            .to_be_bytes(),
    );
    h.update(share);
    let digest = h.finalize();
    let mut out = vec![0i64; RLWE_N];
    for (byte_index, byte) in digest.iter().enumerate() {
        for bit in 0..8usize {
            out[byte_index * 8 + bit] = i64::from((byte >> bit) & 1);
        }
    }
    out
}

fn test_share_sigma_c_rns(session_id: &[u8], recipient_index: usize) -> Vec<u64> {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-sigma-c-rns-v1");
    h.update(session_id);
    h.update(recipient_index.to_be_bytes());
    let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
    let mut out = vec![0u64; RLWE_N * 3];
    for (limb, modulus) in [RLWE_Q0, RLWE_Q1, RLWE_Q2].iter().enumerate() {
        for index in 0..RLWE_N {
            out[limb * RLWE_N + index] = rng.next_u64() % modulus;
        }
    }
    out
}

fn test_digest_sigma_d(d_rns: &[u64]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-sigma-d-commitment-v1");
    for value in d_rns {
        h.update(value.to_le_bytes());
    }
    h.finalize().into()
}

fn test_share_sigma_session_binding(stmt: &ShareNizkStatement) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-sigma-session-v1");
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.recipient_pk.as_slice());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.ciphertext_v.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.finalize().to_vec()
}

fn test_encode_algebraic_proof(d_rns: &[u64], proof: &SigmaProof) -> Vec<u8> {
    let mut out = Vec::new();
    test_encode_u64_vec(&mut out, d_rns);
    test_encode_u64_vec(&mut out, &proof.t_rns);
    test_encode_i64_vec(&mut out, &proof.z_s);
    test_encode_i64_vec(&mut out, &proof.z_e);
    test_encode_i64_vec(&mut out, &proof.ch);
    out
}

fn test_encode_u64_vec(out: &mut Vec<u8>, values: &[u64]) {
    out.extend_from_slice(
        &u32::try_from(values.len())
            .expect("vec len fits u32")
            .to_be_bytes(),
    );
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn test_encode_i64_vec(out: &mut Vec<u8>, values: &[i64]) {
    out.extend_from_slice(
        &u32::try_from(values.len())
            .expect("vec len fits u32")
            .to_be_bytes(),
    );
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn test_relation_binding(stmt: &ShareNizkStatement, algebraic_proof: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-relation-binding-v2");
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.recipient_pk.as_slice());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.ciphertext_v.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.update(algebraic_proof);
    h.finalize().into()
}

fn test_commitment_binding(
    stmt: &ShareNizkStatement,
    relation_binding: &[u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"greco-bfv-commitment-binding-v3");
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.recipient_pk.as_slice());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.update(relation_binding);
    h.finalize().into()
}

fn test_challenge(stmt: &ShareNizkStatement, commitment_ct: &[u8]) -> [u8; CHALLENGE_LEN] {
    let mut transcript = Transcript::new(
        stmt.session_id.as_slice(),
        u32::try_from(stmt.dealer_index).expect("dealer index fits u32"),
    );
    transcript.absorb(b"domain_separator", SHARE_NIZK_DOMAIN_SEPARATOR.as_bytes());
    transcript.absorb(b"session_id", stmt.session_id.as_slice());
    transcript.absorb(b"dealer_index", &stmt.dealer_index.to_be_bytes());
    transcript.absorb(b"recipient_index", &stmt.recipient_index.to_be_bytes());
    transcript.absorb(b"recipient_pk", stmt.recipient_pk.as_slice());
    transcript.absorb(b"bfv_params_digest", stmt.bfv_params_digest.as_slice());
    transcript.absorb(b"dkg_root", stmt.dkg_root.as_slice());
    transcript.absorb(b"ciphertext_u", stmt.ciphertext_u.as_slice());
    transcript.absorb(b"ciphertext_v", stmt.ciphertext_v.as_slice());
    transcript.absorb(b"share_commitment", stmt.share_commitment.as_slice());
    transcript.absorb(b"commitment_ct", commitment_ct);
    let mut challenge = [0u8; CHALLENGE_LEN];
    transcript.challenge_bytes(b"share-encryption-challenge", &mut challenge);
    challenge
}

fn test_lattice_binding(
    stmt: &ShareNizkStatement,
    commitment_ct: &[u8],
    commitment_binding: &[u8; DIGEST_LEN],
    challenge: &[u8; CHALLENGE_LEN],
    relation_binding: &[u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"greco-bfv-binding-v1");
    h.update(challenge);
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.recipient_pk.as_slice());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.ciphertext_v.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.update(commitment_ct);
    h.update(commitment_binding);
    h.update(relation_binding);
    h.finalize().into()
}

fn test_d2_binding(
    stmt: &ShareNizkStatement,
    commitment_ct: &[u8],
    relation_binding: &[u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-d2-binding-v2");
    h.update(commitment_ct);
    h.update(stmt.share_commitment.as_slice());
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.recipient_pk.as_slice());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.ciphertext_v.as_slice());
    h.update(relation_binding);
    h.finalize().into()
}

// ── RED: sigma equation tamper tests ───────────────────────────────────────
//
// These tests construct valid algebraic proofs, then tamper with z_s or d_rns
// in the proof bytes.  The verifier MUST detect the tampering via the
// c*z_s + z_e == t + ch*d_i (mod Q) equation check that was added in
// verify_algebraic_relation().  Before the equation check was added (D.1
// blocker), the verifier accepted proofs with arbitrary z_s/z_e values within
// norm bounds — a critical soundness gap.
//
// Because the verifier checks algebraic_relation (step 6) before the BFV
// encryption proof (step 11), a tampered z_s/d_rns is caught at step 6 even
// when the BFV proof is empty (MockBackend limitation).

fn forge_valid_algebraic_proof(
    stmt: &ShareNizkStatement,
    committed_share: &[u8],
) -> (Vec<u8>, Vec<u64>) {
    let s_i = test_share_sigma_witness(committed_share);
    let e_i = vec![0i64; RLWE_N];
    let c_rns = test_share_sigma_c_rns(stmt.session_id.as_slice(), stmt.recipient_index);
    let d_rns = sigma::compute_d_rns(&c_rns, &s_i, &e_i).expect("compute d_rns");
    let sigma_stmt = SigmaStatement {
        c_rns,
        d_rns: d_rns.clone(),
    };
    let sigma_witness = SigmaWitness { s_i, e_i };
    let mut proof_rng = ChaCha20Rng::from_seed([0xA5; 32]);
    let proof = sigma::prove(
        &test_share_sigma_session_binding(stmt),
        u32::try_from(stmt.recipient_index).expect("recipient index fits u32"),
        &sigma_stmt,
        &sigma_witness,
        &test_digest_sigma_d(&d_rns),
        &mut proof_rng,
    )
    .expect("sigma prove");
    (test_encode_algebraic_proof(&d_rns, &proof), d_rns)
}

fn tamper_z_s_in_algebraic_proof(ap_bytes: &[u8]) -> Vec<u8> {
    // Layout: u32 len + d_rns(u64)*24576 + u32 len + t_rns(u64)*24576 + u32 len + z_s...
    let d_rns_data = RLWE_N * 3 * 8; // 24576 * 8 = 196608
    let t_rns_data = RLWE_N * 3 * 8; // same
    // skip: 4 (d_rns len) + d_rns_data + 4 (t_rns len) + t_rns_data + 4 (z_s len)
    let z_s_offset = 4 + d_rns_data + 4 + t_rns_data + 4;
    assert!(
        ap_bytes.len() > z_s_offset,
        "algebraic_proof too short ({}) for z_s tamper at offset {}",
        ap_bytes.len(),
        z_s_offset
    );
    let mut tampered = ap_bytes.to_vec();
    tampered[z_s_offset] ^= 0x01; // flip low byte of first z_s coefficient
    tampered
}

fn assemble_opened_proof(
    stmt: &ShareNizkStatement,
    algebraic_proof: &[u8],
    bfv_encryption_proof: &[u8],
) -> ShareNizkOpenedProof {
    let relation_binding = test_relation_binding(stmt, algebraic_proof);
    let commitment_bytes =
        ProtocolBytes(b"attacker-commitment-ct-value-32".to_vec());
    let commitment_binding = test_commitment_binding(stmt, &relation_binding);
    let challenge = test_challenge(stmt, commitment_bytes.as_slice());
    let lattice_binding = test_lattice_binding(
        stmt,
        commitment_bytes.as_slice(),
        &commitment_binding,
        &challenge,
        &relation_binding,
    );
    let d2_binding = test_d2_binding(stmt, commitment_bytes.as_slice(), &relation_binding);
    ShareNizkOpenedProof {
        statement: stmt.clone(),
        commitment_bytes,
        commitment_seed: [0u8; DIGEST_LEN],
        commitment_binding,
        challenge,
        lattice_binding,
        relation_binding,
        algebraic_proof: ProtocolBytes(algebraic_proof.to_vec()),
        d2_binding,
        bfv_encryption_proof: ProtocolBytes(bfv_encryption_proof.to_vec()),
        domain_separator: SHARE_NIZK_DOMAIN_SEPARATOR.to_owned(),
    }
}

#[test]
fn verifier_rejects_proof_with_tampered_z_s() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let session_id = vec![0xD1u8; 32];
    let committed_share = vec![0x13u8; 48];

    let share_commitment = compute_share_commitment(&session_id, 0, &committed_share);
    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(vec![0u8; 64]),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        ciphertext_u: ProtocolBytes(vec![0u8; 128]),
        ciphertext_v: ProtocolBytes(compute_ciphertext_v(&vec![0u8; 128]).to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    // Build a valid algebraic proof, then tamper z_s
    let (valid_ap, _d_rns) = forge_valid_algebraic_proof(&stmt, &committed_share);
    let tampered_ap = tamper_z_s_in_algebraic_proof(&valid_ap);
    assert_ne!(
        valid_ap, tampered_ap,
        "tampered algebraic_proof must differ from valid proof"
    );

    let opened =
        assemble_opened_proof(&stmt, &tampered_ap, b"");
    let proof = ShareNizkProof::from_opened(&opened).expect("encode tampered proof");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);
    assert!(
        result.is_err(),
        "RED→GREEN: verifier must reject proof with tampered z_s (equation check). Got: {:?}",
        result
    );
}

#[test]
fn verifier_rejects_proof_with_tampered_d_rns() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let session_id = vec![0xD2u8; 32];
    let committed_share = vec![0x42u8; 48];

    let share_commitment = compute_share_commitment(&session_id, 0, &committed_share);
    let stmt = ShareNizkStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(vec![0u8; 64]),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        ciphertext_u: ProtocolBytes(vec![0u8; 128]),
        ciphertext_v: ProtocolBytes(compute_ciphertext_v(&vec![0u8; 128]).to_vec()),
        share_commitment: ProtocolBytes(share_commitment.to_vec()),
    };

    let (valid_ap, _d_rns) = forge_valid_algebraic_proof(&stmt, &committed_share);
    // Tamper first byte of the first d_rns limb (offset 4: after u32 length prefix)
    let mut tampered_ap = valid_ap.clone();
    assert!(tampered_ap.len() > 4, "algebraic_proof too short for d_rns tamper");
    tampered_ap[4] ^= 0x01;
    assert_ne!(
        valid_ap, tampered_ap,
        "tampered algebraic_proof must differ from valid proof"
    );

    let opened = assemble_opened_proof(&stmt, &tampered_ap, b"");
    let proof = ShareNizkProof::from_opened(&opened).expect("encode tampered proof");

    let result = ShareNizkVerifier::verify(&backend, &stmt, &proof);
    assert!(
        result.is_err(),
        "RED→GREEN: verifier must reject proof with tampered d_rns (equation check). Got: {:?}",
        result
    );
}
