#[cfg(not(feature = "hermine"))]
#[test]
fn hermine_not_available_without_feature() {
    // Trivially passes — HermineAdapter tests are cfg-gated.
}

#[cfg(feature = "hermine")]
#[test]
fn hermine_works_with_feature() {
    use pvthfhe_keygen::{hermine::HermineAdapter, KeygenAdapter, Participant};

    let adapter = HermineAdapter::new();
    let session = adapter
        .generate_session(
            &[
                Participant { id: 1 },
                Participant { id: 2 },
                Participant { id: 3 },
            ],
            2,
        )
        .expect("session");
    let (shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");
    assert_eq!(shares.len(), 3);
    assert!(adapter.verify_transcript(&artifact).expect("verify"));
}
