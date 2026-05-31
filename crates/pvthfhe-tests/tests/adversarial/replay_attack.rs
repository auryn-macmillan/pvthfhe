use pvthfhe_nizk::sigma::{
    compute_d_rns, prove_multi, rlwe_n, verify_multi, SigmaStatement, SigmaWitness,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn replay_attack_different_session_rejected() {
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
        let mut rng = ChaCha20Rng::seed_from_u64(0x40010000 + trial as u64);
        let session_a = format!("replay-session-A-{trial}").into_bytes();
        let session_b = format!("replay-session-B-{trial}").into_bytes();
        let participant_id = 1u32;
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

        let mut rng_a = ChaCha20Rng::seed_from_u64(0x40010000 + trial as u64 + 1000);
        let proof = prove_multi(
            &session_a,
            participant_id,
            &stmt,
            &wit,
            &mut rng_a,
            &d_commitment,
            num_rounds,
        )
        .expect("honest proof in session A");

        if verify_multi(&session_b, participant_id, &stmt, &proof, &d_commitment).is_err() {
            rejected += 1;
        }
    }

    let reject_rate = rejected as f64 / num_trials as f64;
    assert!(
        reject_rate > 0.90,
        "replay attack: reject rate {:.1}% too low (expected >90%)",
        reject_rate * 100.0
    );
}

#[test]
fn replay_attack_same_session_different_participant_rejected() {
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
        let mut rng = ChaCha20Rng::seed_from_u64(0x40020000 + trial as u64);
        let session_id = format!("replay-session-{trial}").into_bytes();
        let pid_a = 1u32;
        let pid_b = 2u32;
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
            pid_a,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
            num_rounds,
        )
        .expect("honest proof for party A");

        if verify_multi(&session_id, pid_b, &stmt, &proof, &d_commitment).is_err() {
            rejected += 1;
        }
    }

    let reject_rate = rejected as f64 / num_trials as f64;
    assert!(
        reject_rate > 0.90,
        "pid replay: reject rate {:.1}% too low (expected >90%)",
        reject_rate * 100.0
    );
}
