use pvthfhe_nizk::sigma::{
    compute_d_rns, prove_multi, rlwe_n, verify_multi, SigmaStatement, SigmaWitness,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn party_id_substitution_rejected() {
    let n = rlwe_n();
    let l = pvthfhe_nizk::sigma::num_rns_limbs();
    let rns_len = n * l;
    let moduli = [
        pvthfhe_nizk::sigma::RLWE_Q0,
        pvthfhe_nizk::sigma::RLWE_Q1,
        pvthfhe_nizk::sigma::RLWE_Q2,
    ];
    let num_rounds = 8;

    let mut rejected = 0usize;
    let num_trials = 200;

    for trial in 0..num_trials {
        let mut rng = ChaCha20Rng::seed_from_u64(0x50010000 + trial as u64);
        let session_id = format!("pid-sub-session-{trial}").into_bytes();
        let real_party_id = (rng.next_u64() % 256) as u32;
        let fake_party_id = real_party_id.wrapping_add(1) % 256;
        let d_commitment = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };

        let mut c_rns = vec![0u64; rns_len];
        for (limb, &q) in moduli.iter().enumerate() {
            for j in 0..n {
                c_rns[limb * n + j] = rng.next_u64() % q;
            }
        }

        let s_i = {
            let mut s = vec![0i64; n];
            for x in s.iter_mut() {
                *x = match rng.next_u64() % 3 {
                    0 => -1,
                    1 => 0,
                    _ => 1,
                };
            }
            s
        };
        let e_i = {
            let mut e = vec![0i64; n];
            for x in e.iter_mut() {
                *x = (rng.next_u64() % 33) as i64 - 16;
            }
            e
        };

        let d_rns = compute_d_rns(&c_rns, &s_i, &e_i).expect("compute_d_rns");
        let stmt = SigmaStatement { c_rns, d_rns };
        let wit = SigmaWitness { s_i, e_i };

        let proof = prove_multi(
            &session_id,
            real_party_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
            num_rounds,
        )
        .expect("honest proof from real party");

        if verify_multi(&session_id, fake_party_id, &stmt, &proof, &d_commitment).is_err() {
            rejected += 1;
        }
    }

    let reject_rate = rejected as f64 / num_trials as f64;
    assert!(
        reject_rate > 0.90,
        "party ID substitution: reject rate {:.1}% too low (expected >90%)",
        reject_rate * 100.0
    );
}

#[test]
fn multi_round_party_id_substitution_rejected() {
    let n = rlwe_n();
    let l = pvthfhe_nizk::sigma::num_rns_limbs();
    let rns_len = n * l;
    let moduli = [
        pvthfhe_nizk::sigma::RLWE_Q0,
        pvthfhe_nizk::sigma::RLWE_Q1,
        pvthfhe_nizk::sigma::RLWE_Q2,
    ];
    let num_rounds = 8;

    let mut rejected = 0usize;
    let num_trials = 200;

    for trial in 0..num_trials {
        let mut rng = ChaCha20Rng::seed_from_u64(0x50020000 + trial as u64);
        let session_id = format!("pid-sub-multi-{trial}").into_bytes();
        let real_party_id = (rng.next_u64() % 256) as u32;
        let fake_party_id = real_party_id.wrapping_add(1) % 256;
        let d_commitment = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };

        let mut c_rns = vec![0u64; rns_len];
        for (limb, &q) in moduli.iter().enumerate() {
            for j in 0..n {
                c_rns[limb * n + j] = rng.next_u64() % q;
            }
        }

        let s_i = {
            let mut s = vec![0i64; n];
            for x in s.iter_mut() {
                *x = match rng.next_u64() % 3 {
                    0 => -1,
                    1 => 0,
                    _ => 1,
                };
            }
            s
        };
        let e_i = {
            let mut e = vec![0i64; n];
            for x in e.iter_mut() {
                *x = (rng.next_u64() % 33) as i64 - 16;
            }
            e
        };

        let d_rns = compute_d_rns(&c_rns, &s_i, &e_i).expect("compute_d_rns");
        let stmt = SigmaStatement { c_rns, d_rns };
        let wit = SigmaWitness { s_i, e_i };

        let multi_proof = prove_multi(
            &session_id,
            real_party_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
            num_rounds,
        )
        .expect("multi prove from real party");

        if verify_multi(
            &session_id,
            fake_party_id,
            &stmt,
            &multi_proof,
            &d_commitment,
        )
        .is_err()
        {
            rejected += 1;
        }
    }

    let reject_rate = rejected as f64 / num_trials as f64;
    assert!(
        reject_rate > 0.90,
        "multi-round party ID substitution: reject rate {:.1}% too low (expected >90%)",
        reject_rate * 100.0
    );
}
