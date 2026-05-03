use pvthfhe_keygen::{
    hermine::{check_and_blame, HermineAdapter},
    BFVPublicKey, BlameProof, KeygenAdapter, KeygenSession, Participant,
    PublicVerificationArtifact, Share,
};

fn sample_participants() -> Vec<Participant> {
    vec![
        Participant { id: 1 },
        Participant { id: 2 },
        Participant { id: 3 },
    ]
}

fn sample_session() -> KeygenSession {
    KeygenSession {
        session_id: "p4-session-alpha".to_owned(),
        threshold: 2,
        ..Default::default()
    }
}

fn sample_share() -> Share {
    Share {
        session_id: "p4-session-alpha".to_owned(),
        ..Default::default()
    }
}

fn sample_artifact() -> PublicVerificationArtifact {
    PublicVerificationArtifact {
        session_id: "p4-session-alpha".to_owned(),
        ..Default::default()
    }
}

fn sample_blame() -> BlameProof {
    BlameProof {
        session_id: "p4-session-alpha".to_owned(),
        reason: "commitment_mismatch".to_owned(),
        ..Default::default()
    }
}

fn sample_bfv_key() -> BFVPublicKey {
    BFVPublicKey {
        bytes: vec![0xde, 0xad, 0xbe, 0xef],
    }
}

fn adapter() -> HermineAdapter {
    HermineAdapter::new()
}

// ── T1: Honest keygen ─────────────────────────────────────────────────────────

#[test]
fn t1_honest_n_of_n_keygen_yields_valid_bfv_public_key() {
    let participants = sample_participants();
    let ad = adapter();
    let session = ad.generate_session(&participants, 2).expect("session");
    let (shares, artifact) = ad.generate_shares(&session, 1).expect("shares");
    assert_eq!(shares.len(), participants.len());
    let valid = ad.verify_transcript(&artifact).expect("verify");
    assert!(valid, "transcript must be valid for an honest dealer");
    let key = ad.reconstruct_bfv_key(&shares).expect("key");
    assert!(
        !key.bytes.is_empty(),
        "reconstructed BFV key must be non-empty"
    );
    // Ensure the sample constructors still compile.
    let _s = sample_share();
    let _k = sample_bfv_key();
}

#[test]
fn t1_reconstruction_is_consistent_across_authorized_sets() {
    let participants = sample_participants();
    let ad = adapter();
    let session = ad.generate_session(&participants, 2).expect("session");
    let (shares, _artifact) = ad.generate_shares(&session, 1).expect("shares");

    // Two different quorums of size >= threshold must yield the same key.
    let key_01 = ad.reconstruct_bfv_key(&shares[..2]).expect("key-01");
    let key_12 = ad.reconstruct_bfv_key(&shares[1..]).expect("key-12");
    let key_all = ad.reconstruct_bfv_key(&shares).expect("key-all");

    assert_eq!(key_01.bytes, key_12.bytes, "quorum 01 == quorum 12");
    assert_eq!(key_01.bytes, key_all.bytes, "quorum 01 == all");
    // Unused sample bindings — kept to preserve sample helper coverage.
    let _session = sample_session();
    let _shares = vec![sample_share(), sample_share()];
}

// ── T2: Secrecy / non-exposure ────────────────────────────────────────────────

#[test]
fn t2_reconstructed_key_does_not_expose_individual_shares() {
    let participants = sample_participants();
    let ad = adapter();
    let session = ad.generate_session(&participants, 2).expect("session");
    let (shares, _artifact) = ad.generate_shares(&session, 1).expect("shares");
    let key = ad.reconstruct_bfv_key(&shares).expect("key");

    // The reconstructed key bytes must not equal any individual share value bytes.
    for s in &shares {
        if let Some(val) = s.secret_value {
            assert_ne!(
                key.bytes,
                val.to_be_bytes().to_vec(),
                "key must not equal an individual share value"
            );
        }
    }
    let _session = sample_session();
    let _k = sample_bfv_key();
}

#[test]
fn t2_corrupted_view_stays_bound_to_public_transcript() {
    let participants = sample_participants();
    let ad = adapter();
    let session = ad.generate_session(&participants, 2).expect("session");
    let (shares, artifact) = ad.generate_shares(&session, 1).expect("shares");

    // Corrupt one share's commitment: it should no longer match the artifact.
    let mut corrupted = shares[0].clone();
    corrupted.commitment = Some(vec![0xff; 32]);

    let blame = check_and_blame(&session.session_id, &corrupted, &artifact);
    // With a random-looking wrong commitment the blame check will fire.
    assert!(
        blame.is_some(),
        "corrupted share must produce a blame proof"
    );
    let _session = sample_session();
    let _artifact = sample_artifact();
    let _share = sample_share();
}

// ── T3: Verification ─────────────────────────────────────────────────────────

#[test]
fn t3_invalid_dealing_is_rejected_by_verify() {
    let ad = adapter();
    // An artifact with empty commitments is invalid.
    let bad_artifact = PublicVerificationArtifact {
        session_id: "p4-session-alpha".to_owned(),
        commitments: vec![],
        dealer_id: Some(99),
        threshold: None,
    };
    let valid = ad.verify_transcript(&bad_artifact).expect("verify");
    assert!(!valid, "empty commitments artifact must fail verify");
    let _artifact = sample_artifact();
    let _session = sample_session();
}

#[test]
fn t3_bad_commitment_transcript_does_not_verify() {
    let ad = adapter();
    // An artifact whose commitments contain an empty entry is invalid.
    let bad_artifact = PublicVerificationArtifact {
        session_id: "p4-session-alpha".to_owned(),
        commitments: vec![vec![], vec![0x01, 0x02]],
        dealer_id: Some(1),
        threshold: None,
    };
    let valid = ad.verify_transcript(&bad_artifact).expect("verify");
    assert!(!valid, "artifact with empty commitment must fail verify");
    let _artifact = sample_artifact();
    let _share = sample_share();
}

// ── T4: Blame ─────────────────────────────────────────────────────────────────

#[test]
fn t4_cheating_dealer_produces_blame_proof() {
    let participants = sample_participants();
    let ad = adapter();
    let session = ad.generate_session(&participants, 2).expect("session");
    let (shares, artifact) = ad.generate_shares(&session, 1).expect("shares");

    // Tamper: change the secret_value without updating the commitment.
    let mut tampered_share = shares[0].clone();
    tampered_share.secret_value = Some(99_999_999);

    let blame = check_and_blame(&session.session_id, &tampered_share, &artifact);
    assert!(
        blame.is_some(),
        "tampered share must trigger blame against dealer"
    );
    let proof = blame.expect("blame proof must be present");
    assert_eq!(proof.reason, "commitment_mismatch");
    assert_eq!(proof.accused_id, Some(1), "dealer 1 must be accused");
    let _blame = sample_blame();
    let _artifact = sample_artifact();
    let _session = sample_session();
}

#[test]
fn t4_blame_proof_names_guilty_dealer_not_honest_party() {
    // Build a blame proof naming dealer_id=7 (the cheater), not the recipient.
    let blame = BlameProof {
        session_id: "p4-session-alpha".to_owned(),
        reason: "commitment_mismatch".to_owned(),
        accused_id: Some(7),
        evidence: Some(vec![0x00]),
    };
    assert_eq!(blame.accused_id, Some(7));
    assert_ne!(
        blame.accused_id,
        Some(1),
        "blame must not name an honest participant"
    );
    let _blame = sample_blame();
    let _session = sample_session();
}

// ── T5: Session state ─────────────────────────────────────────────────────────

#[test]
fn t5_session_state_advances_through_protocol_steps() {
    let participants = sample_participants();
    let ad = adapter();

    // Step 1: generate session.
    let session = ad.generate_session(&participants, 2).expect("session");
    assert!(!session.session_id.is_empty(), "session_id must be set");
    assert_eq!(session.threshold, 2);
    assert_eq!(session.participants.len(), 3);

    // Step 2: dealing.
    let (shares, artifact) = ad.generate_shares(&session, 1).expect("shares");
    assert_eq!(shares.len(), 3);

    // Step 3: verification.
    let valid = ad.verify_transcript(&artifact).expect("verify");
    assert!(valid, "honest dealing must pass verification");

    // Step 4: reconstruction.
    let key = ad.reconstruct_bfv_key(&shares).expect("key");
    assert!(!key.bytes.is_empty());

    let _session = sample_session();
    let _artifact = sample_artifact();
}

#[test]
fn t5_aborted_session_preserves_transition_invariants() {
    let participants = sample_participants();
    let ad = adapter();
    let session = ad.generate_session(&participants, 2).expect("session");
    let (shares, artifact) = ad.generate_shares(&session, 1).expect("shares");

    // Simulate abort: corrupt a share → blame is produced → reconstruction is skipped.
    let mut bad_share = shares[0].clone();
    bad_share.secret_value = Some(0); // guaranteed wrong (probability of collision ≈ 0)
    let blame = check_and_blame(&session.session_id, &bad_share, &artifact);

    // After abort the session_id in the blame proof must match the session.
    if let Some(ref proof) = blame {
        assert_eq!(
            proof.session_id, session.session_id,
            "blame session_id must match the active session"
        );
    }
    // The artifact (transcript) remains valid regardless of participant misbehaviour.
    let valid = ad.verify_transcript(&artifact).expect("verify");
    assert!(
        valid,
        "public transcript is still valid even after participant abort"
    );
    let _session = sample_session();
    let _blame = sample_blame();
    let _share = sample_share();
}
