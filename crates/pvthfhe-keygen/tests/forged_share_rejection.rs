#[cfg(feature = "hermine")]
mod hermine_forged_share_tests {
    use pvthfhe_keygen::hermine::HermineAdapter;
    use pvthfhe_keygen::{KeygenAdapter, Participant};

    fn make_adapter() -> HermineAdapter {
        HermineAdapter::new()
    }

    fn participants() -> Vec<Participant> {
        vec![
            Participant { id: 1 },
            Participant { id: 2 },
            Participant { id: 3 },
        ]
    }

    #[test]
    fn forged_share_value_triggers_blame() {
        let adapter = make_adapter();
        let session = adapter.generate_session(&participants(), 2).unwrap();
        let (mut shares, artifact) = adapter.generate_shares(&session, 1).unwrap();

        if let Some(val) = shares[0].secret_value.as_mut() {
            *val = val.wrapping_add(1);
        }

        let blame = adapter.blame_dealing(&artifact, &shares).unwrap();
        assert!(
            blame.is_some(),
            "expected blame proof for tampered share value"
        );
        let proof = blame.unwrap();
        assert!(!proof.reason.is_empty());
    }

    #[test]
    fn forged_commitment_triggers_blame() {
        let adapter = make_adapter();
        let session = adapter.generate_session(&participants(), 2).unwrap();
        let (mut shares, artifact) = adapter.generate_shares(&session, 1).unwrap();

        if let Some(ref mut c) = shares[0].commitment {
            if !c.is_empty() {
                c[0] ^= 0xFF;
            }
        }

        let blame = adapter.blame_dealing(&artifact, &shares).unwrap();
        assert!(blame.is_some(), "expected blame for corrupted commitment");
        let proof = blame.unwrap();
        assert!(!proof.reason.is_empty());
    }

    #[test]
    fn mismatched_session_id_triggers_blame() {
        let adapter = make_adapter();
        let session = adapter.generate_session(&participants(), 2).unwrap();
        let (mut shares, artifact) = adapter.generate_shares(&session, 1).unwrap();

        shares[0].session_id = "fake-session-id".to_string();

        let blame = adapter.blame_dealing(&artifact, &shares).unwrap();
        assert!(
            blame.is_some(),
            "expected blame for replayed/wrong session_id share"
        );
        let proof = blame.unwrap();
        assert!(!proof.reason.is_empty());
    }

    #[test]
    fn honest_shares_produce_no_blame() {
        let adapter = make_adapter();
        let session = adapter.generate_session(&participants(), 2).unwrap();
        let (shares, artifact) = adapter.generate_shares(&session, 1).unwrap();

        let blame = adapter.blame_dealing(&artifact, &shares).unwrap();
        assert!(blame.is_none(), "honest shares should not trigger blame");
    }

    #[test]
    fn missing_share_triggers_blame() {
        let adapter = make_adapter();
        let session = adapter.generate_session(&participants(), 2).unwrap();
        let (mut shares, artifact) = adapter.generate_shares(&session, 1).unwrap();

        shares.pop();

        let blame = adapter.blame_dealing(&artifact, &shares).unwrap();
        assert!(
            blame.is_some(),
            "expected blame when share count mismatches artifact"
        );
    }
}

#[cfg(not(feature = "hermine"))]
#[test]
fn hermine_forged_share_tests_skipped_without_feature() {
    // HermineAdapter forged share tests require the `hermine` feature flag.
    // This test passes trivially when hermine is not enabled.
}
