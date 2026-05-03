//! Honest-run public-verification test for `pvthfhe-keygen`.

use pvthfhe_keygen::{hermine::HermineAdapter, KeygenAdapter, Participant};

fn participants(n: u16) -> Vec<Participant> {
    (1..=n).map(|id| Participant { id }).collect()
}

fn adapter() -> Box<dyn KeygenAdapter> {
    Box::new(HermineAdapter::new())
}

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => unreachable!("{ctx}: {e:?}"),
    }
}

#[test]
fn honest_n_of_n_no_blame() {
    let adapter = adapter();
    let session = ok(adapter.generate_session(&participants(4), 3), "session");
    let (shares, artifact) = ok(adapter.generate_shares(&session, 1), "shares");

    assert!(ok(
        adapter.verify_transcript(&artifact),
        "verify transcript"
    ));
    assert!(ok(
        adapter.public_verify(&artifact, &shares),
        "public verify"
    ));
    assert!(
        ok(adapter.blame_dealing(&artifact, &shares), "blame result").is_none(),
        "honest execution must not trigger blame"
    );

    let threshold_usize = usize::from(session.threshold);
    let quorum_key = ok(
        adapter.reconstruct_bfv_key(&shares[..threshold_usize]),
        "quorum key",
    );
    let all_key = ok(adapter.reconstruct_bfv_key(&shares), "all key");
    assert_eq!(quorum_key.bytes, all_key.bytes);
}
