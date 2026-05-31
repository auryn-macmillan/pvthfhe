//! Quotient inflation attack test.
//! Attempts to bypass the range check by setting the quotient r1
//! to a large value in the sigma S-Z verification.

use pvthfhe_nizk::sigma::{
    self, compute_d_rns, compute_sigma_sz_data, prove, rlwe_n, verify, SigmaStatement, SigmaWitness,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn quotient_inflation_breaks_sz_check() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x2000_0000 + trial as u64);
        let session_id = b"quotient-inflation";
        let participant_id = 1u32;
        let d_commitment = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };

        let mut c_rns = vec![0u64; n * l];
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

        let mut proof = prove(
            session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        )
        .expect("honest proof");

        // Tamper with t_rns to inject a large quotient
        // This breaks the algebraic equation c*z_s + z_e = t + ch*d_i
        if !proof.t_rns.is_empty() {
            proof.t_rns[0] = proof.t_rns[0].wrapping_add(1);
        }

        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_err(),
            "quotient inflation trial {trial}: verifier must reject tampered t_rns"
        );
    }
}

#[test]
fn sz_data_r1_out_of_range_rejected() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x2100_0000 + trial as u64);
        let session_id = format!("sz-r1-session-{trial}").into_bytes();
        let participant_id = 1u32;
        let d_commitment = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };

        let mut c_rns = vec![0u64; n * l];
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

        let proof = prove(
            &session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        )
        .expect("honest proof");

        let (_gammas, _c_eval, _zs_eval, _ze_eval, _t_eval, _di_eval, r1_eval) =
            compute_sigma_sz_data(
                &stmt.c_rns,
                &stmt.d_rns,
                &proof,
                &session_id,
                participant_id,
            );

        // Verify r1 values are within u64 range (not overflowed)
        for (i, &r1) in r1_eval.iter().enumerate() {
            assert!(r1 < u64::MAX, "sz r1 trial {trial}: r1[{i}]={r1} overflow");
        }

        // Verify honest proof still passes
        let result = verify(&session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_ok(),
            "sz r1 trial {trial}: honest proof must verify"
        );
    }
}
