//! Integration tests: lattice_nizk.
#![cfg(feature = "real-nizk")]

mod lattice_nizk {
    use pvthfhe_fhe::real_nizk::{LatticeNizk, NizkStatement, NizkWitness, RealNizkAdapter};
    use pvthfhe_keygen::Share;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sha2::{Digest, Sha256};

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

    fn sample_statement_and_witness(secret_value: u64) -> (NizkStatement, NizkWitness) {
        let share = Share {
            session_id: "session-red-001".to_owned(),
            threshold: Some(2),
            participant_id: Some(7),
            secret_value: Some(secret_value),
            commitment: None,
        };
        let participant_id = some(share.participant_id, "participant id");
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

    #[test]
    fn test_honest_prove_verify() {
        let (statement, witness) = sample_statement_and_witness(41);
        let mut rng = StdRng::seed_from_u64(7);

        let proof = ok(
            RealNizkAdapter::prove(&statement, &witness, &mut rng),
            "real lattice NIZK prover should exist in GREEN phase",
        );

        ok(
            RealNizkAdapter::verify(&statement, &proof),
            "honest prover/verifier flow should accept in GREEN phase",
        );
    }

    #[test]
    fn test_tampered_share_rejected() {
        let (statement, mut witness) = sample_statement_and_witness(41);
        witness.secret_share = 99;
        let mut rng = StdRng::seed_from_u64(8);

        let proof = ok(
            RealNizkAdapter::prove(&statement, &witness, &mut rng),
            "tampered witness should still compile in RED phase",
        );

        assert!(
            RealNizkAdapter::verify(&statement, &proof).is_err(),
            "tampered secret_value must be rejected"
        );
    }

    #[test]
    fn test_wrong_pvss_commitment_rejected() {
        let (mut statement, witness) = sample_statement_and_witness(41);
        statement.pvss_commitment = [0x55; 32];
        let mut rng = StdRng::seed_from_u64(9);

        let proof = ok(
            RealNizkAdapter::prove(&statement, &witness, &mut rng),
            "wrong commitment case should compile in RED phase",
        );

        assert!(
            RealNizkAdapter::verify(&statement, &proof).is_err(),
            "wrong PVSS commitment hash must be rejected"
        );
    }

    #[test]
    fn test_batch_verify_correctness() {
        let cases = [11_u64, 22, 33]
            .into_iter()
            .map(sample_statement_and_witness)
            .collect::<Vec<_>>();
        let statements = cases
            .iter()
            .map(|(statement, _)| statement.clone())
            .collect::<Vec<_>>();
        let mut rng = StdRng::seed_from_u64(10);
        let proofs = ok(
            cases
                .iter()
                .map(|(statement, witness)| RealNizkAdapter::prove(statement, witness, &mut rng))
                .collect::<Result<Vec<_>, _>>(),
            "batch prove path should exist in GREEN phase",
        );

        ok(
            RealNizkAdapter::batch_verify(&statements, &proofs),
            "batch of honest proofs should verify in GREEN phase",
        );
    }

    #[test]
    fn test_proof_is_deterministic() {
        let (statement, witness) = sample_statement_and_witness(52);
        let mut rng_one = StdRng::seed_from_u64(11);
        let mut rng_two = StdRng::seed_from_u64(11);

        let proof_one = ok(
            RealNizkAdapter::prove(&statement, &witness, &mut rng_one),
            "first proof generation should exist in GREEN phase",
        );
        let proof_two = ok(
            RealNizkAdapter::prove(&statement, &witness, &mut rng_two),
            "second proof generation should exist in GREEN phase",
        );

        assert_eq!(
            proof_one.as_bytes(),
            proof_two.as_bytes(),
            "same inputs should yield identical deterministic proof bytes"
        );
    }

    #[test]
    fn test_verify_rejects_mismatched_participant_binding() {
        let (mut statement, witness) = sample_statement_and_witness(63);
        statement.participant_id = 8;
        let mut rng = StdRng::seed_from_u64(12);

        let proof = ok(
            RealNizkAdapter::prove(&statement, &witness, &mut rng),
            "participant-binding case should compile in RED phase",
        );

        assert!(
            RealNizkAdapter::verify(&statement, &proof).is_err(),
            "proof must be scoped to the original participant binding"
        );
    }
}
