//! Adversarial public-verification and blame tests for `pvthfhe-keygen`.

#[cfg(feature = "hermine")]
mod hermine_adversarial_tests {
    use pvthfhe_keygen::{
        hermine::HermineAdapter, KeygenAdapter, Participant, PublicVerificationArtifact,
    };

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

    fn err<T: std::fmt::Debug, E>(r: Result<T, E>, ctx: &str) -> E {
        match r {
            Err(e) => e,
            Ok(v) => unreachable!("{ctx}: expected Err, got Ok({v:?})"),
        }
    }

    fn some<T>(o: Option<T>, ctx: &str) -> T {
        match o {
            Some(v) => v,
            None => unreachable!("{ctx}: got None"),
        }
    }

    #[test]
    fn forged_share_blames_forging_participant() {
        let adapter = adapter();
        let session = ok(adapter.generate_session(&participants(4), 3), "session");
        let (mut shares, artifact) = ok(adapter.generate_shares(&session, 1), "shares");

        shares[1].secret_value = Some(some(shares[1].secret_value, "secret") + 1);

        assert!(
            !ok(adapter.public_verify(&artifact, &shares), "verify"),
            "forged share must fail public verification"
        );

        let blame_opt = ok(adapter.blame_dealing(&artifact, &shares), "blame result");
        let blame = some(blame_opt, "blame proof");
        assert_eq!(blame.accused_id, shares[1].participant_id);
    }

    #[test]
    fn replayed_share_from_other_session_is_rejected() {
        let adapter = adapter();
        let session = ok(adapter.generate_session(&participants(4), 3), "session");
        let (mut shares, artifact) = ok(adapter.generate_shares(&session, 1), "shares");

        let other_participants = vec![
            Participant { id: 4 },
            Participant { id: 3 },
            Participant { id: 2 },
            Participant { id: 1 },
        ];
        let other_session = ok(
            adapter.generate_session(&other_participants, 3),
            "other session",
        );
        let (other_shares, _) = ok(adapter.generate_shares(&other_session, 1), "other shares");

        shares[0] = other_shares[0].clone();

        assert!(
            !ok(adapter.public_verify(&artifact, &shares), "verify"),
            "replayed share from another session must fail verification"
        );

        let blame_opt = ok(adapter.blame_dealing(&artifact, &shares), "blame result");
        let blame = some(blame_opt, "blame proof");
        assert_eq!(blame.accused_id, artifact.dealer_id);
    }

    #[test]
    fn malicious_dealer_bad_commitment_blames_dealer() {
        let adapter = adapter();
        let session = ok(adapter.generate_session(&participants(4), 3), "session");
        let (shares, mut artifact) = ok(adapter.generate_shares(&session, 1), "shares");

        artifact.commitments[0][0] ^= 0x55;

        assert!(
            !ok(adapter.public_verify(&artifact, &shares), "verify"),
            "bad public commitment must fail verification"
        );

        let blame_opt = ok(adapter.blame_dealing(&artifact, &shares), "blame result");
        let blame = some(blame_opt, "blame proof");
        assert_eq!(blame.accused_id, artifact.dealer_id);
    }

    #[test]
    fn colluding_below_threshold_cannot_reconstruct() {
        let adapter = adapter();
        let session = ok(adapter.generate_session(&participants(5), 3), "session");
        let (shares, _) = ok(adapter.generate_shares(&session, 1), "shares");

        let e = err(
            adapter.reconstruct_bfv_key(&shares[..2]),
            "below-threshold reconstruction must fail",
        );
        assert!(e.message().contains("threshold"));
    }

    #[test]
    fn abort_blame_correct_names_cheating_participant() {
        let adapter = adapter();
        let session = ok(adapter.generate_session(&participants(4), 3), "session");
        let (mut shares, artifact) = ok(adapter.generate_shares(&session, 1), "shares");

        shares[2].commitment = Some(vec![0xAA; 32]);

        let blame_opt = ok(adapter.blame_dealing(&artifact, &shares), "blame result");
        let blame = some(blame_opt, "blame proof");
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
            !ok(adapter.verify_transcript(&artifact), "verify"),
            "empty commitment vector must be invalid"
        );

        let blame_opt = ok(adapter.blame_dealing(&artifact, &[]), "blame result");
        let blame = some(blame_opt, "blame proof");
        assert_eq!(blame.accused_id, artifact.dealer_id);
    }

    #[test]
    fn threshold_tampering_blames_cheating_participant() {
        let adapter = adapter();
        let session = ok(adapter.generate_session(&participants(4), 3), "session");
        let (mut shares, artifact) = ok(adapter.generate_shares(&session, 1), "shares");

        shares[0].threshold = Some(2);

        assert!(
            !ok(adapter.public_verify(&artifact, &shares), "verify"),
            "threshold tampering must fail public verification"
        );

        let blame_opt = ok(adapter.blame_dealing(&artifact, &shares), "blame result");
        let blame = some(blame_opt, "blame proof");
        assert_eq!(blame.accused_id, shares[0].participant_id);
    }

    #[test]
    fn duplicate_participant_id_is_rejected() {
        let adapter = adapter();
        let e = err(
            adapter.generate_session(
                &[
                    Participant { id: 1 },
                    Participant { id: 1 },
                    Participant { id: 2 },
                ],
                2,
            ),
            "duplicate participant ids must fail",
        );
        assert!(e.message().contains("duplicate participant id"));
    }
}

#[cfg(not(feature = "hermine"))]
#[test]
fn hermine_adversarial_tests_skipped_without_feature() {
    // HermineAdapter adversarial tests require the `hermine` feature flag.
    // This test passes trivially when hermine is not enabled.
}
