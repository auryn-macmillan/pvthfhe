//! D.2 regression: batched share proofs must bind `sk` and `e_sm` tracks independently.

use pvthfhe_fhe::{mock::MockBackend, types::PublicKey, FheBackend};
use pvthfhe_pvss::nizk_share::{
    canonical_bfv_params_digest, compute_ciphertext_v, compute_share_commitment,
    ShareNizkBatchedStatement, ShareNizkBatchedVerifier, ShareNizkProver, ShareNizkStatement,
    ShareNizkTrackStatement, ShareNizkTrackType, ShareNizkVerifier, ShareNizkWitness,
};
use pvthfhe_pvss::PvssError;
use pvthfhe_types::{EncRandomness, ProtocolBytes, ShareSecret};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481,288230376167047169,288230376161280001]\nvariance = 10\n";

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

fn track_statement(
    backend: &MockBackend,
    session_id: &[u8],
    recipient_pk: &[u8],
    track_type: ShareNizkTrackType,
    slot_index: Option<u16>,
    payload: Vec<u8>,
    randomness: [u8; 32],
) -> (ShareNizkTrackStatement, ShareNizkWitness) {
    let mut enc_rng = ChaCha8Rng::from_seed(randomness);
    let ciphertext_u = backend
        .encrypt(
            &PublicKey {
                bytes: recipient_pk.to_vec(),
            },
            &payload,
            &mut enc_rng,
        )
        .expect("encrypt track payload")
        .bytes;
    let share_commitment = compute_share_commitment(session_id, 0, &payload);
    let ciphertext_v = compute_ciphertext_v(&ciphertext_u);
    (
        ShareNizkTrackStatement {
            track_type,
            slot_index,
            ciphertext_u: ProtocolBytes(ciphertext_u),
            ciphertext_v: ProtocolBytes(ciphertext_v.to_vec()),
            track_commitment: ProtocolBytes(share_commitment.to_vec()),
        },
        ShareNizkWitness {
            share_bytes: ShareSecret::new(payload),
            encryption_randomness: EncRandomness::new(randomness.to_vec()),
        },
    )
}

#[test]
fn batched_track_binding_rejects_esm_ciphertext_tamper_while_sk_is_unchanged() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");

    let mut rng = ChaCha8Rng::seed_from_u64(0xD200);
    let mut session_id = vec![0u8; 32];
    rng.fill_bytes(&mut session_id);
    let mut recipient_pk = vec![0u8; 64];
    rng.fill_bytes(&mut recipient_pk);

    let (sk_track, sk_witness) = track_statement(
        &backend,
        &session_id,
        &recipient_pk,
        ShareNizkTrackType::Sk,
        None,
        b"sk-track-0000000000000000000000000000".to_vec(),
        [0xA1; 32],
    );
    let (esm_track, esm_witness) = track_statement(
        &backend,
        &session_id,
        &recipient_pk,
        ShareNizkTrackType::ESm,
        Some(7),
        b"esm-track-000000000000000000000000000".to_vec(),
        [0xA2; 32],
    );

    let batched_stmt = ShareNizkBatchedStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(recipient_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        sk: sk_track,
        esm_slots: vec![esm_track],
    };

    let proof =
        ShareNizkProver::prove_batched(&backend, &batched_stmt, &sk_witness, &[esm_witness])
            .expect("batched proof");

    let mut tampered_stmt = batched_stmt.clone();
    tampered_stmt.esm_slots[0].ciphertext_u.0[0] ^= 0x55;
    tampered_stmt.esm_slots[0].ciphertext_v = ProtocolBytes(
        compute_ciphertext_v(tampered_stmt.esm_slots[0].ciphertext_u.as_slice()).to_vec(),
    );

    let result = ShareNizkBatchedVerifier::verify(&backend, &tampered_stmt, &proof);
    assert!(
        result.is_err(),
        "D.2: tampering only the e_sm encrypted share must fail even when the sk track is unchanged. result = {:?}",
        result
    );
}

#[test]
fn batched_valid_tracks_fail_closed_until_d1_bfv_relation_exists() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");

    let session_id = vec![0xD2; 32];
    let recipient_pk = vec![0x42; 64];
    let (sk_track, sk_witness) = track_statement(
        &backend,
        &session_id,
        &recipient_pk,
        ShareNizkTrackType::Sk,
        None,
        b"sk-valid-0000000000000000000000000000".to_vec(),
        [0xB1; 32],
    );
    let (esm_track, esm_witness) = track_statement(
        &backend,
        &session_id,
        &recipient_pk,
        ShareNizkTrackType::ESm,
        Some(2),
        b"esm-valid-000000000000000000000000000".to_vec(),
        [0xB2; 32],
    );

    let batched_stmt = ShareNizkBatchedStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(recipient_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        sk: sk_track,
        esm_slots: vec![esm_track],
    };

    let proof =
        ShareNizkProver::prove_batched(&backend, &batched_stmt, &sk_witness, &[esm_witness])
            .expect("batched proof");

    let result = ShareNizkBatchedVerifier::verify(&backend, &batched_stmt, &proof);
    assert!(
        result.is_err(),
        "D.1 containment remains: independently bound D.2 batched proof must still fail closed until BFV relation verification exists. result = {:?}",
        result
    );
}

#[test]
fn batched_schema_projects_legacy_track_statements_with_independent_commitments() {
    let session_id = vec![0x55; 32];
    let recipient_pk = vec![0x66; 64];
    let sk_track = ShareNizkTrackStatement {
        track_type: ShareNizkTrackType::Sk,
        slot_index: None,
        ciphertext_u: ProtocolBytes(vec![1, 2, 3]),
        ciphertext_v: ProtocolBytes(compute_ciphertext_v(&[1, 2, 3]).to_vec()),
        track_commitment: ProtocolBytes([0x11; 32].to_vec()),
    };
    let esm_track = ShareNizkTrackStatement {
        track_type: ShareNizkTrackType::ESm,
        slot_index: Some(9),
        ciphertext_u: ProtocolBytes(vec![4, 5, 6]),
        ciphertext_v: ProtocolBytes(compute_ciphertext_v(&[4, 5, 6]).to_vec()),
        track_commitment: ProtocolBytes([0x22; 32].to_vec()),
    };
    let stmt = ShareNizkBatchedStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 3,
        recipient_index: 4,
        recipient_pk: ProtocolBytes(recipient_pk.clone()),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(vec![0x77; 32]),
        sk: sk_track,
        esm_slots: vec![esm_track],
    };

    let sk_legacy: ShareNizkStatement =
        stmt.legacy_statement_for_track(ShareNizkTrackType::Sk, None);
    let esm_legacy: ShareNizkStatement =
        stmt.legacy_statement_for_track(ShareNizkTrackType::ESm, Some(9));

    assert_ne!(sk_legacy.share_commitment, esm_legacy.share_commitment);
    assert_ne!(sk_legacy.ciphertext_u, esm_legacy.ciphertext_u);
    assert_eq!(sk_legacy.session_id, esm_legacy.session_id);
}

#[test]
fn batched_projection_rejects_cross_track_replay_when_public_material_matches() {
    let session_id = vec![0xD3; 32];
    let recipient_pk = vec![0x44; 64];
    let ciphertext_u = ProtocolBytes(b"same-ciphertext-for-replay-check".to_vec());
    let ciphertext_v = ProtocolBytes(compute_ciphertext_v(ciphertext_u.as_slice()).to_vec());
    let track_commitment = ProtocolBytes([0x33; 32].to_vec());
    let sk_track = ShareNizkTrackStatement {
        track_type: ShareNizkTrackType::Sk,
        slot_index: None,
        ciphertext_u: ciphertext_u.clone(),
        ciphertext_v: ciphertext_v.clone(),
        track_commitment: track_commitment.clone(),
    };
    let esm_track = ShareNizkTrackStatement {
        track_type: ShareNizkTrackType::ESm,
        slot_index: Some(4),
        ciphertext_u,
        ciphertext_v,
        track_commitment,
    };
    let stmt = ShareNizkBatchedStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(recipient_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        sk: sk_track,
        esm_slots: vec![esm_track],
    };

    let sk_legacy = stmt.legacy_statement_for_track(ShareNizkTrackType::Sk, None);
    let esm_legacy = stmt.legacy_statement_for_track(ShareNizkTrackType::ESm, Some(4));

    assert_ne!(
        sk_legacy, esm_legacy,
        "D.3: track identity and e_sm slot must be bound into the projected proof statement so an sk proof cannot replay as e_sm when public ciphertext/commitment bytes match"
    );
}

#[test]
fn batched_rejects_sk_proof_reused_as_esm_track_proof() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");

    let session_id = vec![0xD4; 32];
    let recipient_pk = vec![0x45; 64];
    let payload = b"same-track-payload-000000000000000000".to_vec();
    let randomness = [0xD4; 32];

    let (sk_track, sk_witness) = track_statement(
        &backend,
        &session_id,
        &recipient_pk,
        ShareNizkTrackType::Sk,
        None,
        payload.clone(),
        randomness,
    );
    let (esm_track, esm_witness) = track_statement(
        &backend,
        &session_id,
        &recipient_pk,
        ShareNizkTrackType::ESm,
        Some(5),
        payload,
        randomness,
    );
    let stmt = ShareNizkBatchedStatement {
        session_id: ProtocolBytes(session_id.clone()),
        dealer_index: 0,
        recipient_index: 0,
        recipient_pk: ProtocolBytes(recipient_pk),
        bfv_params_digest: ProtocolBytes(canonical_bfv_params_digest().to_vec()),
        dkg_root: ProtocolBytes(session_id),
        sk: sk_track,
        esm_slots: vec![esm_track],
    };
    let proof = ShareNizkProver::prove_batched(&backend, &stmt, &sk_witness, &[esm_witness])
        .expect("batched prover must succeed");
    let esm_statement = stmt.legacy_statement_for_track(ShareNizkTrackType::ESm, Some(5));

    let result = ShareNizkVerifier::verify(&backend, &esm_statement, &proof);
    assert!(
        result.is_err(),
        "D.3: an sk proof must be rejected when replayed as an e_sm slot proof, got {:?}",
        result
    );
}
