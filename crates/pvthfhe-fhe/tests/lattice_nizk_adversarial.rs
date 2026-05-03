//! Adversarial rejection tests for the lattice NIZK adapter.

#![cfg(feature = "real-nizk")]
#![allow(clippy::panic)]

mod lattice_nizk_adversarial {
    use pvthfhe_fhe::real_nizk::{
        LatticeNizk, NizkError, NizkProof, NizkStatement, NizkWitness, RealNizkAdapter,
    };
    use pvthfhe_keygen::Share;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sha2::{Digest, Sha256};

    fn sample_statement_and_witness(secret_value: u64) -> (NizkStatement, NizkWitness) {
        let share = Share {
            session_id: "session-red-001".to_owned(),
            threshold: Some(2),
            participant_id: Some(7),
            secret_value: Some(secret_value),
            commitment: None,
        };
        let participant_id = share
            .participant_id
            .unwrap_or_else(|| unreachable!("participant id must be set"));
        let commitment = pvss_commitment(&share.session_id, participant_id, secret_value);
        let statement = NizkStatement {
            ciphertext_bytes: vec![0x10, 0x20, 0x30, 0x40],
            decrypt_share_bytes: vec![0x44, 0x55, 0x66, 0x77],
            pvss_commitment: commitment,
            params: (65_537, 1_024, 17),
            session_id: share.session_id.clone(),
            participant_id,
        };
        let witness = NizkWitness {
            secret_share: secret_value,
            error: vec![1, -1, 0, 2],
            randomness: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        (statement, witness)
    }

    fn pvss_commitment(session_id: &str, participant_id: u16, secret_value: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(participant_id.to_le_bytes());
        hasher.update(secret_value.to_be_bytes());
        hasher.finalize().into()
    }

    fn prove_ok(statement: &NizkStatement, witness: &NizkWitness, rng: &mut StdRng) -> NizkProof {
        match RealNizkAdapter::prove(statement, witness, rng) {
            Ok(p) => p,
            Err(e) => unreachable!("prove should not error: {e:?}"),
        }
    }

    #[test]
    fn test_malformed_proof_bytes_rejected() {
        let (statement, _) = sample_statement_and_witness(41);
        let proof = NizkProof {
            backend_id: "slap".to_owned(),
            proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        assert!(RealNizkAdapter::verify(&statement, &proof).is_err());
    }

    #[test]
    fn test_replay_across_sessions_rejected() {
        let (mut statement, witness) = sample_statement_and_witness(41);
        statement.session_id = "sess-A".to_owned();
        statement.pvss_commitment =
            pvss_commitment(&statement.session_id, statement.participant_id, 41);
        let mut rng = StdRng::seed_from_u64(17);
        let proof = prove_ok(&statement, &witness, &mut rng);

        let mut replay_statement = statement.clone();
        replay_statement.session_id = "sess-B".to_owned();
        replay_statement.pvss_commitment = pvss_commitment(
            &replay_statement.session_id,
            replay_statement.participant_id,
            41,
        );

        assert!(RealNizkAdapter::verify(&replay_statement, &proof).is_err());
    }

    #[test]
    fn test_participant_id_substitution_rejected() {
        let (mut statement, witness) = sample_statement_and_witness(41);
        statement.participant_id = 1;
        statement.pvss_commitment =
            pvss_commitment(&statement.session_id, statement.participant_id, 41);
        let mut rng = StdRng::seed_from_u64(18);
        let proof = prove_ok(&statement, &witness, &mut rng);

        let mut substituted_statement = statement.clone();
        substituted_statement.participant_id = 2;
        substituted_statement.pvss_commitment = pvss_commitment(
            &substituted_statement.session_id,
            substituted_statement.participant_id,
            99,
        );

        assert!(RealNizkAdapter::verify(&substituted_statement, &proof).is_err());
    }

    #[test]
    fn test_wrong_q_parameter_rejected() {
        let (statement, witness) = sample_statement_and_witness(41);
        let mut rng = StdRng::seed_from_u64(19);
        let proof = prove_ok(&statement, &witness, &mut rng);

        let mut wrong_q_statement = statement.clone();
        wrong_q_statement.params.0 = 65_539;

        assert!(RealNizkAdapter::verify(&wrong_q_statement, &proof).is_err());
    }

    #[test]
    fn test_fs_challenge_tamper_rejected() {
        let (statement, witness) = sample_statement_and_witness(41);
        let mut rng = StdRng::seed_from_u64(20);
        let proof = prove_ok(&statement, &witness, &mut rng);

        let mut tampered_bytes = proof.proof_bytes.clone();
        tampered_bytes[6] ^= 0x01;
        let tampered = NizkProof {
            backend_id: proof.backend_id.clone(),
            proof_bytes: tampered_bytes,
        };

        assert!(matches!(
            RealNizkAdapter::verify(&statement, &tampered),
            Err(NizkError::VerificationFailed(_))
        ));
    }

    #[test]
    fn test_truncated_proof_bytes_rejected() {
        let (statement, witness) = sample_statement_and_witness(41);
        let mut rng = StdRng::seed_from_u64(21);
        let proof = prove_ok(&statement, &witness, &mut rng);

        let truncated = NizkProof {
            backend_id: proof.backend_id.clone(),
            proof_bytes: proof.proof_bytes[..4].to_vec(),
        };

        assert!(RealNizkAdapter::verify(&statement, &truncated).is_err());
    }

    #[test]
    fn test_batch_with_one_bad_proof_rejected() {
        let cases = [11_u64, 22, 33]
            .into_iter()
            .map(sample_statement_and_witness)
            .collect::<Vec<_>>();
        let statements = cases
            .iter()
            .map(|(statement, _)| statement.clone())
            .collect::<Vec<_>>();
        let mut rng = StdRng::seed_from_u64(22);
        let mut proofs: Vec<NizkProof> = cases
            .iter()
            .map(|(statement, witness)| {
                match RealNizkAdapter::prove(statement, witness, &mut rng) {
                    Ok(p) => p,
                    Err(e) => unreachable!("prove should not error: {e:?}"),
                }
            })
            .collect();
        proofs[2].proof_bytes[6] ^= 0x01;

        assert!(RealNizkAdapter::batch_verify(&statements, &proofs).is_err());
    }

    #[test]
    fn test_empty_proof_bytes_rejected() {
        let (statement, _) = sample_statement_and_witness(41);
        let proof = NizkProof {
            backend_id: "slap".to_owned(),
            proof_bytes: vec![],
        };

        assert!(RealNizkAdapter::verify(&statement, &proof).is_err());
    }

    #[test]
    fn test_nizk_accepts_wrong_witness_fails() {
        let (statement, _) = sample_statement_and_witness(100);
        let wrong_witness = NizkWitness {
            secret_share: 999,
            error: vec![0, 0, 0, 0],
            randomness: vec![0x11, 0x22, 0x33, 0x44],
        };
        let mut rng = StdRng::seed_from_u64(42);
        let proof = prove_ok(&statement, &wrong_witness, &mut rng);
        assert!(
            RealNizkAdapter::verify(&statement, &proof).is_err(),
            "verifier must reject proof for mismatched witness"
        );
    }

    #[test]
    fn test_nizk_two_proofs_same_stmt_differ() {
        let (statement, witness) = sample_statement_and_witness(42);
        let mut rng1 = StdRng::seed_from_u64(100);
        let mut rng2 = StdRng::seed_from_u64(200);
        let proof1 = prove_ok(&statement, &witness, &mut rng1);
        let proof2 = prove_ok(&statement, &witness, &mut rng2);
        assert_ne!(
            proof1.proof_bytes, proof2.proof_bytes,
            "two proofs with different RNG seeds must differ (randomization)"
        );
    }

    #[test]
    fn test_nizk_wrong_commitment_fails_verify() {
        let (mut statement, witness) = sample_statement_and_witness(77);
        let mut rng = StdRng::seed_from_u64(50);
        let proof = prove_ok(&statement, &witness, &mut rng);
        statement.pvss_commitment[0] ^= 0xFF;
        assert!(
            RealNizkAdapter::verify(&statement, &proof).is_err(),
            "verifier must reject proof when commitment is tampered"
        );
    }
}
