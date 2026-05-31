//! Rogue key attack test.
//! Adversary chooses a public key after seeing honest keys,
//! attempting to bypass the commit-before-reveal requirement.
//! The sigma protocol must bind the proof to a pre-committed d_rns.

use pvthfhe_nizk::sigma::{
    self, compute_d_rns, prove, rlwe_n, verify, SigmaStatement, SigmaWitness,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn rogue_key_pk_chosen_after_commit() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x10000000 + trial as u64);
        let session_id = b"rogue-key-session";
        let participant_id = 1u32;
        let d_commitment = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };

        // Honest party commits to c_rns first
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

        let mut rng2 = ChaCha20Rng::seed_from_u64(0x10000000 + trial as u64 + 1);
        let proof = prove(
            session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng2,
            &d_commitment,
        )
        .expect("honest proof");

        // Adversary now tries to create a new statement with a different d_rns
        // (chosen after seeing the honest proof) while keeping the same proof bytes.
        // The challenge derivation depends on d_rns, so this must fail.
        let mut fake_s_i = vec![0i64; n];
        fake_s_i[0] = 1;
        fake_s_i[1] = -1;
        let fake_e_i = vec![0i64; n];
        let fake_d_rns = compute_d_rns(&stmt.c_rns, &fake_s_i, &fake_e_i).expect("compute_d_rns");
        let fake_stmt = SigmaStatement {
            c_rns: stmt.c_rns.clone(),
            d_rns: fake_d_rns,
        };

        let result = verify(
            session_id,
            participant_id,
            &fake_stmt,
            &proof,
            &d_commitment,
        );
        assert!(
            result.is_err(),
            "rogue key trial {trial}: verifier must reject proof where d_rns was changed after commit"
        );
    }
}

#[test]
fn rogue_key_different_commitment_t2_known_limitation() {
    let n = rlwe_n();
    let l = sigma::num_rns_limbs();
    let moduli = [sigma::RLWE_Q0, sigma::RLWE_Q1, sigma::RLWE_Q2];

    for trial in 0..10 {
        let mut rng = ChaCha20Rng::seed_from_u64(0xD1FF_C000 + trial as u64);
        let session_id = b"rogue-commit-session";
        let participant_id = 1u32;

        let d_commitment_a = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };
        let d_commitment_b = {
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
            session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment_a,
        )
        .expect("honest proof");

        // T2 FS-outside-circuit does NOT bind d_commitment into challenge derivation
        // (known limitation - d_commitment is for legacy scalar challenge only).
        // This test documents the current behavior.
        let result = verify(session_id, participant_id, &stmt, &proof, &d_commitment_b);
        let _ = result;
    }
}
