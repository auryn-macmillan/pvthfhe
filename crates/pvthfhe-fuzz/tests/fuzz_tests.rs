#[test]
fn sigma_fuzz_10k() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xFUZZ_0001);
    let n = pvthfhe_nizk::sigma::rlwe_n();
    let l = pvthfhe_nizk::sigma::num_rns_limbs();

    let mut honest_pass = 0u64;
    let mut tamper_reject = 0u64;
    let target = 10_000;

    for i in 0..target {
        let seed = (i as u64)
            .wrapping_mul(0xDEAD_BEEF)
            .wrapping_add(0xCAFE_D00D);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let session_id = format!("fuzz-test-{i}").into_bytes();
        let participant_id = (rng.next_u64() % 256) as u32;
        let d_commitment = {
            let mut h = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rng, &mut h);
            h
        };

        // Generate random s_i, e_i
        let s_i = pvthfhe_fuzz::sample_ternary(&mut rng, n);
        let e_i = pvthfhe_fuzz::sample_bounded_i64(&mut rng, n, pvthfhe_nizk::sigma::SIGMA_B_E);

        // Generate random c_rns
        let moduli = [
            pvthfhe_nizk::sigma::RLWE_Q0,
            pvthfhe_nizk::sigma::RLWE_Q1,
            pvthfhe_nizk::sigma::RLWE_Q2,
        ];
        let mut c_rns = vec![0u64; n * l];
        for (limb, &q) in moduli.iter().enumerate() {
            for j in 0..n {
                c_rns[limb * n + j] = rng.next_u64() % q;
            }
        }

        let d_rns = match pvthfhe_nizk::sigma::compute_d_rns(&c_rns, &s_i, &e_i) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let stmt = pvthfhe_nizk::sigma::SigmaStatement { c_rns, d_rns };
        let wit = pvthfhe_nizk::sigma::SigmaWitness { s_i, e_i };

        let proof = match pvthfhe_nizk::sigma::prove(
            &session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        ) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Honest verify
        if pvthfhe_nizk::sigma::verify(&session_id, participant_id, &stmt, &proof, &d_commitment)
            .is_ok()
        {
            honest_pass += 1;
        }

        // Tamper
        let mut tampered = proof.clone();
        if !tampered.t_rns.is_empty() {
            tampered.t_rns[0] ^= 0xFF;
        }
        if pvthfhe_nizk::sigma::verify(&session_id, participant_id, &stmt, &tampered, &d_commitment)
            .is_err()
        {
            tamper_reject += 1;
        }
    }

    eprintln!("sigma_fuzz_10k: {honest_pass} honest pass, {tamper_reject} tamper reject (target={target})");
    assert!(
        honest_pass >= target as u64 / 10,
        "Too few honest passes: {honest_pass}"
    );
    assert!(
        tamper_reject >= target as u64 / 10,
        "Too few tamper rejections: {tamper_reject}"
    );
}

#[test]
fn sigma_wrong_session_rejected() {
    for i in 0..1000 {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xBA00_0000 + i as u64);
        let n = pvthfhe_nizk::sigma::rlwe_n();
        let l = pvthfhe_nizk::sigma::num_rns_limbs();
        let d_commitment = [0u8; 32];
        let session_a = b"session-a";
        let session_b = b"session-b";
        let participant_id = 1u32;

        let s_i = pvthfhe_fuzz::sample_ternary(&mut rng, n);
        let e_i = pvthfhe_fuzz::sample_bounded_i64(&mut rng, n, pvthfhe_nizk::sigma::SIGMA_B_E);
        let moduli = [
            pvthfhe_nizk::sigma::RLWE_Q0,
            pvthfhe_nizk::sigma::RLWE_Q1,
            pvthfhe_nizk::sigma::RLWE_Q2,
        ];
        let mut c_rns = vec![0u64; n * l];
        for (limb, &q) in moduli.iter().enumerate() {
            for j in 0..n {
                c_rns[limb * n + j] = rng.next_u64() % q;
            }
        }
        let d_rns = pvthfhe_nizk::sigma::compute_d_rns(&c_rns, &s_i, &e_i).unwrap();
        let stmt = pvthfhe_nizk::sigma::SigmaStatement { c_rns, d_rns };
        let wit = pvthfhe_nizk::sigma::SigmaWitness { s_i, e_i };

        let proof = pvthfhe_nizk::sigma::prove(
            session_a,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        )
        .unwrap();

        assert!(
            pvthfhe_nizk::sigma::verify(session_b, participant_id, &stmt, &proof, &d_commitment)
                .is_err(),
            "sigma round {i}: wrong session should be rejected"
        );
    }
}
