//! Adversarial public-verification and blame tests for `pvthfhe-keygen`.

use pvthfhe_keygen::{
    hermine::HermineAdapter, KeygenAdapter, Participant, PublicVerificationArtifact,
};

fn participants(n: u16) -> Vec<Participant> {
    (1..=n).map(|id| Participant { id }).collect()
}

fn adapter() -> Box<dyn KeygenAdapter> {
    Box::new(HermineAdapter::new())
}

#[test]
fn forged_share_blames_forging_participant() {
    let adapter = adapter();
    let session = adapter
        .generate_session(&participants(4), 3)
        .expect("session");
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    shares[1].secret_value = Some(shares[1].secret_value.expect("secret") + 1);

    assert!(
        !adapter.public_verify(&artifact, &shares).expect("verify"),
        "forged share must fail public verification"
    );

    let blame = adapter
        .blame_dealing(&artifact, &shares)
        .expect("blame result")
        .expect("blame proof");
    assert_eq!(blame.accused_id, shares[1].participant_id);
}

#[test]
fn replayed_share_from_other_session_is_rejected() {
    let adapter = adapter();
    let session = adapter
        .generate_session(&participants(4), 3)
        .expect("session");
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    let other_participants = vec![
        Participant { id: 4 },
        Participant { id: 3 },
        Participant { id: 2 },
        Participant { id: 1 },
    ];
    let other_session = adapter
        .generate_session(&other_participants, 3)
        .expect("other session");
    let (other_shares, _) = adapter
        .generate_shares(&other_session, 1)
        .expect("other shares");

    shares[0] = other_shares[0].clone();

    assert!(
        !adapter.public_verify(&artifact, &shares).expect("verify"),
        "replayed share from another session must fail verification"
    );

    let blame = adapter
        .blame_dealing(&artifact, &shares)
        .expect("blame result")
        .expect("blame proof");
    assert_eq!(blame.accused_id, artifact.dealer_id);
}

#[test]
fn malicious_dealer_bad_commitment_blames_dealer() {
    let adapter = adapter();
    let session = adapter
        .generate_session(&participants(4), 3)
        .expect("session");
    let (shares, mut artifact) = adapter.generate_shares(&session, 1).expect("shares");

    artifact.commitments[0][0] ^= 0x55;

    assert!(
        !adapter.public_verify(&artifact, &shares).expect("verify"),
        "bad public commitment must fail verification"
    );

    let blame = adapter
        .blame_dealing(&artifact, &shares)
        .expect("blame result")
        .expect("blame proof");
    assert_eq!(blame.accused_id, artifact.dealer_id);
}

#[test]
fn colluding_below_threshold_cannot_reconstruct() {
    let adapter = adapter();
    let session = adapter
        .generate_session(&participants(5), 3)
        .expect("session");
    let (shares, _) = adapter.generate_shares(&session, 1).expect("shares");

    let err = adapter
        .reconstruct_bfv_key(&shares[..2])
        .expect_err("below-threshold reconstruction must fail");
    assert!(err.message().contains("threshold"));
}

#[test]
fn abort_blame_correct_names_cheating_participant() {
    let adapter = adapter();
    let session = adapter
        .generate_session(&participants(4), 3)
        .expect("session");
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    shares[2].commitment = Some(vec![0xAA; 32]);

    let blame = adapter
        .blame_dealing(&artifact, &shares)
        .expect("blame result")
        .expect("blame proof");
    assert_eq!(blame.accused_id, shares[2].participant_id);
}

#[test]
fn invalid_empty_commitment_artifact_is_rejected() {
    let adapter = adapter();
    let artifact = PublicVerificationArtifact {
        session_id: "p4-session-empty".to_owned(),
        threshold: Some(3),
        commitments: vec![],
        dealer_id: Some(7),
    };

    assert!(
        !adapter.verify_transcript(&artifact).expect("verify"),
        "empty commitment vector must be invalid"
    );

    let blame = adapter
        .blame_dealing(&artifact, &[])
        .expect("blame result")
        .expect("blame proof");
    assert_eq!(blame.accused_id, artifact.dealer_id);
}

#[test]
fn threshold_tampering_blames_cheating_participant() {
    let adapter = adapter();
    let session = adapter
        .generate_session(&participants(4), 3)
        .expect("session");
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    shares[0].threshold = Some(2);

    assert!(
        !adapter.public_verify(&artifact, &shares).expect("verify"),
        "threshold tampering must fail public verification"
    );

    let blame = adapter
        .blame_dealing(&artifact, &shares)
        .expect("blame result")
        .expect("blame proof");
    assert_eq!(blame.accused_id, shares[0].participant_id);
}

#[test]
fn duplicate_participant_id_is_rejected() {
    let adapter = adapter();
    let err = adapter
        .generate_session(
            &[
                Participant { id: 1 },
                Participant { id: 1 },
                Participant { id: 2 },
            ],
            2,
        )
        .expect_err("duplicate participant ids must fail");
    assert!(err.message().contains("duplicate participant id"));
}
