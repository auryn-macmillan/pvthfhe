//! Adversarial PVSS tests: tampered shares and mismatched session IDs.

use pvthfhe_keygen::{hermine::HermineAdapter, KeygenAdapter, Participant};

fn participants(n: u16) -> Vec<Participant> {
    (1..=n).map(|id| Participant { id }).collect()
}

#[test]
fn tampered_share_value_triggers_blame() {
    let adapter = HermineAdapter::new();
    let session = adapter
        .generate_session(&participants(3), 2)
        .expect("session");
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    let original = shares[0].secret_value.expect("secret_value");
    shares[0].secret_value = Some(original.wrapping_add(1));

    let blame = adapter
        .blame_dealing(&artifact, &shares)
        .expect("blame_dealing ok")
        .expect("blame proof present");

    assert_eq!(blame.accused_id, shares[0].participant_id);
}

#[test]
fn mismatched_session_id_triggers_blame() {
    let adapter = HermineAdapter::new();
    let session = adapter
        .generate_session(&participants(3), 2)
        .expect("session");
    let (mut shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    shares[1].session_id = "wrong-session-id".to_owned();

    let blame = adapter
        .blame_dealing(&artifact, &shares)
        .expect("blame_dealing ok")
        .expect("blame proof present");

    assert_eq!(blame.accused_id, artifact.dealer_id);
}
