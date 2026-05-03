//! Honest-run public-verification test for `pvthfhe-keygen`.

use pvthfhe_keygen::{hermine::HermineAdapter, KeygenAdapter, Participant};

fn participants(n: u16) -> Vec<Participant> {
    (1..=n).map(|id| Participant { id }).collect()
}

fn adapter() -> Box<dyn KeygenAdapter> {
    Box::new(HermineAdapter::new())
}

#[test]
fn honest_n_of_n_no_blame() {
    let adapter = adapter();
    let session = adapter
        .generate_session(&participants(4), 3)
        .expect("session");
    let (shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");

    assert!(adapter
        .verify_transcript(&artifact)
        .expect("verify transcript"));
    assert!(adapter
        .public_verify(&artifact, &shares)
        .expect("public verify"));
    assert!(
        adapter
            .blame_dealing(&artifact, &shares)
            .expect("blame result")
            .is_none(),
        "honest execution must not trigger blame"
    );

    let quorum_key = adapter
        .reconstruct_bfv_key(&shares[..session.threshold as usize])
        .expect("quorum key");
    let all_key = adapter.reconstruct_bfv_key(&shares).expect("all key");
    assert_eq!(quorum_key.bytes, all_key.bytes);
}
