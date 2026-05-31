//! Length mismatch attack test.
//! Attempts to provide wrong numbers of commitments/shares,
//! which must be rejected.

use pvthfhe_nizk::sigma::{
    self, compute_d_rns, prove, rlwe_n, verify, SigmaStatement, SigmaWitness,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn wrong_z_s_length_rejected() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let rns_len = n * l;
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x30010000 + trial as u64);
        let session_id = b"len-mismatch-session";
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

        let mut proof = prove(
            session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        )
        .expect("honest proof");

        // Corrupt z_s length
        proof.z_s = vec![0i64; n + 1];

        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_err(),
            "length mismatch {trial}: verifier must reject z_s with wrong length"
        );
    }
}

#[test]
fn wrong_z_e_length_rejected() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let rns_len = n * l;
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x30020000 + trial as u64);
        let session_id = b"len-mismatch-ze";
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

        let mut proof = prove(
            session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        )
        .expect("honest proof");

        proof.z_e = vec![0i64; n - 1];

        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_err(),
            "length mismatch {trial}: verifier must reject z_e with wrong length"
        );
    }
}

#[test]
fn wrong_t_rns_length_rejected() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let rns_len = n * l;
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x30030000 + trial as u64);
        let session_id = b"len-mismatch-t";
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

        let mut proof = prove(
            session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        )
        .expect("honest proof");

        proof.t_rns = vec![0u64; rns_len - 3];

        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment);
        assert!(
            result.is_err(),
            "length mismatch {trial}: verifier must reject t_rns with wrong length"
        );
    }
}
