//! Sigma forgery attack test.
//! Attempts to produce a sigma proof with a wrong witness (z_s, z_e)
//! that satisfies the algebraic equations but doesn't match the honest witness.
//! The verifier checks bound constraints on z_s and z_e which should catch this.

use pvthfhe_nizk::sigma::{
    self, compute_d_rns, prove, rlwe_n, verify, SigmaStatement, SigmaWitness, B_Z_E, B_Z_S,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn forged_sigma_response_out_of_bounds() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x80000100 + trial as u64);
        let session_id = b"forgery-session";
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

        // Adversary sets z_s coefficients beyond the verifier bound B_Z_S
        let tampered_zs = proof.z_s.iter().map(|&v| v + B_Z_S + 1).collect::<Vec<_>>();
        proof.z_s = tampered_zs;

        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_err(),
            "forgery trial {trial}: verifier must reject z_s outside norm bound"
        );
    }
}

#[test]
fn forged_sigma_response_ze_out_of_bounds() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x80000200 + trial as u64);
        let session_id = b"forgery-ze-session";
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

        proof.z_e = proof.z_e.iter().map(|&v| v + B_Z_E + 1).collect();

        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_err(),
            "forgery ze trial {trial}: verifier must reject z_e outside norm bound"
        );
    }
}

#[test]
fn forged_challenge_value_rejected() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x80000300 + trial as u64);
        let session_id = b"forgery-ch-session";
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

        // Set challenge to an invalid value (not -1, 0, or 1)
        proof.ch = 2;

        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_err(),
            "forgery ch trial {trial}: verifier must reject invalid challenge value"
        );
    }
}
