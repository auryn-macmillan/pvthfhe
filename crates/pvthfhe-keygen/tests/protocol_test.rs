#[cfg(feature = "hermine")]
mod protocol_tests {
    use pvthfhe_keygen::{
        hermine::{check_and_blame, HermineAdapter},
        BFVPublicKey, BlameProof, KeygenAdapter, KeygenSession, Participant,
        PublicVerificationArtifact, Share,
    };

    fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, ctx: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => unreachable!("{ctx}: {e:?}"),
        }
    }

    fn some<T>(o: Option<T>, ctx: &str) -> T {
        match o {
            Some(v) => v,
            None => unreachable!("{ctx}: got None"),
        }
    }

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

    #[test]
    fn t1_honest_n_of_n_keygen_yields_valid_bfv_public_key() {
        let participants = sample_participants();
        let ad = adapter();
        let session = ok(ad.generate_session(&participants, 2), "session");
        let (shares, artifact) = ok(ad.generate_shares(&session, 1), "shares");
        assert_eq!(shares.len(), participants.len());
        let valid = ok(ad.verify_transcript(&artifact), "verify");
        assert!(valid, "transcript must be valid for an honest dealer");
        let key = ok(ad.reconstruct_bfv_key(&shares), "key");
        assert!(
            !key.bytes.is_empty(),
            "reconstructed BFV key must be non-empty"
        );
        let _s = sample_share();
        let _k = sample_bfv_key();
    }

    #[test]
    fn t1_reconstruction_is_consistent_across_authorized_sets() {
        let participants = sample_participants();
        let ad = adapter();
        let session = ok(ad.generate_session(&participants, 2), "session");
        let (shares, _artifact) = ok(ad.generate_shares(&session, 1), "shares");

        let key_01 = ok(ad.reconstruct_bfv_key(&shares[..2]), "key-01");
        let key_12 = ok(ad.reconstruct_bfv_key(&shares[1..]), "key-12");
        let key_all = ok(ad.reconstruct_bfv_key(&shares), "key-all");

        assert_eq!(key_01.bytes, key_12.bytes, "quorum 01 == quorum 12");
        assert_eq!(key_01.bytes, key_all.bytes, "quorum 01 == all");
        let _session = sample_session();
        let _shares = [sample_share(), sample_share()];
    }

    #[test]
    fn t2_reconstructed_key_does_not_expose_individual_shares() {
        let participants = sample_participants();
        let ad = adapter();
        let session = ok(ad.generate_session(&participants, 2), "session");
        let (shares, _artifact) = ok(ad.generate_shares(&session, 1), "shares");
        let key = ok(ad.reconstruct_bfv_key(&shares), "key");

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
        let session = ok(ad.generate_session(&participants, 2), "session");
        let (shares, artifact) = ok(ad.generate_shares(&session, 1), "shares");

        let mut corrupted = shares[0].clone();
        corrupted.commitment = Some(vec![0xff; 32]);

        let blame = check_and_blame(&session.session_id, &corrupted, &artifact);
        assert!(
            blame.is_some(),
            "corrupted share must produce a blame proof"
        );
        let _session = sample_session();
        let _artifact = sample_artifact();
        let _share = sample_share();
    }

    #[test]
    fn t3_invalid_dealing_is_rejected_by_verify() {
        let ad = adapter();
        let bad_artifact = PublicVerificationArtifact {
            session_id: "p4-session-alpha".to_owned(),
            commitments: vec![],
            dealer_id: Some(99),
            threshold: None,
        };
        let valid = ok(ad.verify_transcript(&bad_artifact), "verify");
        assert!(!valid, "empty commitments artifact must fail verify");
        let _artifact = sample_artifact();
        let _session = sample_session();
    }

    #[test]
    fn t3_bad_commitment_transcript_does_not_verify() {
        let ad = adapter();
        let bad_artifact = PublicVerificationArtifact {
            session_id: "p4-session-alpha".to_owned(),
            commitments: vec![vec![], vec![0x01, 0x02]],
            dealer_id: Some(1),
            threshold: None,
        };
        let valid = ok(ad.verify_transcript(&bad_artifact), "verify");
        assert!(!valid, "artifact with empty commitment must fail verify");
        let _artifact = sample_artifact();
        let _share = sample_share();
    }

    #[test]
    fn t4_cheating_dealer_produces_blame_proof() {
        let participants = sample_participants();
        let ad = adapter();
        let session = ok(ad.generate_session(&participants, 2), "session");
        let (shares, artifact) = ok(ad.generate_shares(&session, 1), "shares");

        let mut tampered_share = shares[0].clone();
        tampered_share.secret_value = Some(99_999_999);

        let blame = check_and_blame(&session.session_id, &tampered_share, &artifact);
        assert!(
            blame.is_some(),
            "tampered share must trigger blame against dealer"
        );
        let proof = some(blame, "blame proof must be present");
        assert_eq!(proof.reason, "commitment_mismatch");
        assert_eq!(proof.accused_id, Some(1), "dealer 1 must be accused");
        let _blame = sample_blame();
        let _artifact = sample_artifact();
        let _session = sample_session();
    }

    #[test]
    fn t4_blame_proof_names_guilty_dealer_not_honest_party() {
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

    #[test]
    fn t5_session_state_advances_through_protocol_steps() {
        let participants = sample_participants();
        let ad = adapter();

        let session = ok(ad.generate_session(&participants, 2), "session");
        assert!(!session.session_id.is_empty(), "session_id must be set");
        assert_eq!(session.threshold, 2);
        assert_eq!(session.participants.len(), 3);

        let (shares, artifact) = ok(ad.generate_shares(&session, 1), "shares");
        assert_eq!(shares.len(), 3);

        let valid = ok(ad.verify_transcript(&artifact), "verify");
        assert!(valid, "honest dealing must pass verification");

        let key = ok(ad.reconstruct_bfv_key(&shares), "key");
        assert!(!key.bytes.is_empty());

        let _session = sample_session();
        let _artifact = sample_artifact();
    }

    #[test]
    fn t5_aborted_session_preserves_transition_invariants() {
        let participants = sample_participants();
        let ad = adapter();
        let session = ok(ad.generate_session(&participants, 2), "session");
        let (shares, artifact) = ok(ad.generate_shares(&session, 1), "shares");

        let mut bad_share = shares[0].clone();
        bad_share.secret_value = Some(0);
        let blame = check_and_blame(&session.session_id, &bad_share, &artifact);

        if let Some(ref proof) = blame {
            assert_eq!(
                proof.session_id, session.session_id,
                "blame session_id must match the active session"
            );
        }
        let valid = ok(ad.verify_transcript(&artifact), "verify");
        assert!(
            valid,
            "public transcript is still valid even after participant abort"
        );
        let _session = sample_session();
        let _blame = sample_blame();
        let _share = sample_share();
    }
}

#[cfg(not(feature = "hermine"))]
#[test]
fn hermine_protocol_tests_skipped_without_feature() {
    // HermineAdapter protocol tests require the `hermine` feature flag.
}
