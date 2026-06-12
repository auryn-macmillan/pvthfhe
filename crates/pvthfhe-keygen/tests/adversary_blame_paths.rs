//! Adversary simulation tests — exercise all 8 blame paths in hermine.rs.
//!
//! MPC-AUDIT-2026-06-12 Gap 5: Verify that the protocol's "abort with public
//! blame" mechanism correctly identifies each type of adversarial behavior.

use pvthfhe_keygen::{
    hermine::HermineAdapter, BlameProof, KeygenAdapter, KeygenError, KeygenSession, Participant,
    PublicVerificationArtifact, Share,
};

fn make_participants(n: u16) -> Vec<Participant> {
    (1..=n).map(|i| Participant { id: i }).collect()
}

fn make_session(adapter: &HermineAdapter, n: u16, t: u16) -> pvthfhe_keygen::KeygenSession {
    let participants = make_participants(n);
    adapter
        .generate_session(&participants, t)
        .expect("valid session parameters")
}

// ── Path 1: Commitment count mismatch ─────────────────────────────────────────

#[test]
fn blame_path_1_commitment_count_mismatch() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (shares, artifact) = adapter
        .generate_shares(&session, 1)
        .expect("share generation");

    // Remove one commitment from artifact → count mismatch
    let mut tampered = artifact.clone();
    tampered.commitments.pop();

    let result = adapter.blame_dealing(&tampered, &shares).expect("blame");
    assert!(result.is_some(), "must produce BlameProof");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "commitment_count_mismatch");
}

// ── Path 2: Replayed share (wrong session_id) ──────────────────────────────────

#[test]
fn blame_path_2_replayed_share() {
    let adapter = HermineAdapter::default();
    let session_a = make_session(&adapter, 5, 3);
    // Use different participant set so session IDs differ
    let participants_b = (6..=10).map(|i| Participant { id: i }).collect::<Vec<_>>();
    let session_b = adapter
        .generate_session(&participants_b, 3)
        .expect("valid session_b");
    let (shares_a, artifact_a) = adapter.generate_shares(&session_a, 1).expect("shares A");
    let (mut shares_b, _artifact_b) = adapter.generate_shares(&session_b, 6).expect("shares B");

    // Inject one share from session B into session A's verification
    shares_b[0].session_id = session_a.session_id.clone(); // mismatch with share content

    let result = adapter
        .blame_dealing(&artifact_a, &shares_b)
        .expect("blame");
    assert!(result.is_some(), "must detect cross-session replay");
    let proof = result.unwrap();
    assert!(
        proof.reason == "replayed_share"
            || proof.reason == "forged_share"
            || proof.reason == "commitment_mismatch",
        "expected cross-session blame evidence, got: {}",
        proof.reason
    );
}

// ── Path 3: Threshold mismatch ────────────────────────────────────────────────

#[test]
fn blame_path_3_threshold_mismatch() {
    let adapter = HermineAdapter::default();
    let session_3 = make_session(&adapter, 5, 3);
    let session_4 = make_session(&adapter, 5, 4); // different threshold
    let (mut shares, artifact) = adapter.generate_shares(&session_3, 1).expect("shares");

    // Inject share with wrong threshold
    let (shares_4, _) = adapter.generate_shares(&session_4, 1).expect("shares_4");
    shares[0].threshold = shares_4[0].threshold;

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(result.is_some(), "must detect threshold mismatch");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "threshold_mismatch");
}

// ── Path 4: Invalid share identity (zero or duplicate participant_id) ──────────

#[test]
fn blame_path_4_invalid_share_identity_zero() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    shares[0].participant_id = Some(0); // zero is invalid

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(result.is_some(), "must detect zero participant_id");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "invalid_share_identity");
}

#[test]
fn blame_path_4_invalid_share_identity_duplicate() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    // Duplicate participant_id: set share[1] to same id as share[0]
    shares[1].participant_id = shares[0].participant_id;

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(result.is_some(), "must detect duplicate participant_id");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "invalid_share_identity");
}

// ── Path 5: Missing secret_value ──────────────────────────────────────────────

#[test]
fn blame_path_5_missing_secret_value() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    shares[0].secret_value = None;

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(result.is_some(), "must detect missing secret_value");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "missing_secret_value");
}

// ── Path 6: Forged share (commitment mismatch) ────────────────────────────────

#[test]
fn blame_path_6_forged_share() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    // Replace commitment with wrong hash
    shares[0].commitment = Some(vec![0xFFu8; 32]);

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(result.is_some(), "must detect forged share");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "forged_share");
}

// ── Path 7: Commitment mismatch (published != expected) ────────────────────────

#[test]
fn blame_path_7_commitment_mismatch() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (shares, mut artifact) = adapter.generate_shares(&session, 1).expect("shares");

    // Tamper with one published commitment — replaces one in the artifact
    artifact.commitments[0] = vec![0xAAu8; 32];

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(result.is_some(), "must detect commitment mismatch");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "commitment_mismatch");
}

// ── Path 8: Invalid public artifact ───────────────────────────────────────────

#[test]
fn blame_path_8_invalid_public_artifact() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (shares, mut artifact) = adapter.generate_shares(&session, 1).expect("shares");

    // Corrupt artifact: empty session_id
    artifact.session_id.clear();

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(result.is_some(), "must detect invalid public artifact");
    let proof = result.unwrap();
    assert_eq!(proof.reason, "invalid_public_artifact");
}

// ── Smoke: honest path produces no blame ──────────────────────────────────────

#[test]
fn honest_dealing_produces_no_blame() {
    let adapter = HermineAdapter::default();
    let session = make_session(&adapter, 5, 3);
    let (shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    let result = adapter.blame_dealing(&artifact, &shares).expect("blame");
    assert!(
        result.is_none(),
        "honest dealing must produce no BlameProof"
    );
}
