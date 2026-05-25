//! N4 sigma-protocol completeness and soundness tests.
//! 1000 honest instances must accept; 100+ cheating instances must reject.
//! Deterministic via `ChaCha20Rng::seed_from_u64(0x4e_34)`.

use pvthfhe_nizk::sigma::{
    compute_d_rns, prove, rlwe_n, verify, SigmaStatement, SigmaWitness, RLWE_Q0, RLWE_Q1, RLWE_Q2,
    SIGMA_B_E,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn sample_uniform_rq(rng: &mut ChaCha20Rng) -> Vec<u64> {
    let moduli = [RLWE_Q0, RLWE_Q1, RLWE_Q2];
    let mut out = vec![0u64; rlwe_n() * moduli.len()];
    for (limb, &q) in moduli.iter().enumerate() {
        // Rejection sampling avoids modular bias: discard values >= floor(2^64/q)*q.
        let threshold = u64::MAX - (u64::MAX % q);
        for j in 0..rlwe_n() {
            loop {
                let v = rng.next_u64();
                if v < threshold {
                    out[limb * rlwe_n() + j] = v % q;
                    break;
                }
            }
        }
    }
    out
}

fn sample_ternary(rng: &mut ChaCha20Rng) -> Vec<i64> {
    let mut s = vec![0i64; rlwe_n()];
    for x in s.iter_mut() {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        *x = match b[0] % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
    }
    s
}

fn sample_error(rng: &mut ChaCha20Rng) -> Result<Vec<i64>, String> {
    const RANGE: u64 = 33; // 2 * SIGMA_B_E + 1 = 33
    const THRESHOLD: u64 = u64::MAX - (u64::MAX % RANGE);
    let mut e = vec![0i64; rlwe_n()];
    for x in e.iter_mut() {
        loop {
            let v = rng.next_u64();
            if v < THRESHOLD {
                *x = i64::try_from(v % RANGE).map_err(|err| err.to_string())? - SIGMA_B_E;
                break;
            }
        }
    }
    Ok(e)
}

#[test]
fn honest_instances_all_accept() -> Result<(), String> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4e_34);

    for trial in 0..1000usize {
        let c_rns = sample_uniform_rq(&mut rng);
        let s_i = sample_ternary(&mut rng);
        let e_i = sample_error(&mut rng)?;
        let d_rns = compute_d_rns(&c_rns, &s_i, &e_i)
            .map_err(|err| format!("trial {trial}: compute_d_rns: {err}"))?;

        let stmt = SigmaStatement {
            c_rns: c_rns.clone(),
            d_rns: d_rns.clone(),
        };
        let wit = SigmaWitness { s_i, e_i };

        let proof = prove(b"test-session-n4", 0, &stmt, &wit, &mut rng)
            .map_err(|err| format!("trial {trial}: prove: {err}"))?;
        verify(b"test-session-n4", 0, &stmt, &proof)
            .map_err(|err| format!("trial {trial}: honest verify rejected: {err}"))?;
    }
    Ok(())
}

#[test]
fn cheating_instances_all_reject() -> Result<(), String> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4e_34_ff_00);

    for trial in 0..34usize {
        // --- Tamper 1: flip a key coefficient (breaks c*s_fake + e != d) ---
        {
            let c_rns = sample_uniform_rq(&mut rng);
            let mut s_i = sample_ternary(&mut rng);
            let e_i = sample_error(&mut rng)?;
            let d_rns = compute_d_rns(&c_rns, &s_i, &e_i)
                .map_err(|err| format!("flip-key trial {trial}: {err}"))?;
            s_i[0] += 2;
            let stmt = SigmaStatement { c_rns, d_rns };
            let wit = SigmaWitness { s_i, e_i };
            let proof = prove(b"test-session-n4", 0, &stmt, &wit, &mut rng)
                .map_err(|err| format!("flip-key prove trial {trial}: {err}"))?;
            assert!(
                verify(b"test-session-n4", 0, &stmt, &proof).is_err(),
                "flip-key trial {trial}: should have been rejected"
            );
        }

        // --- Tamper 2: change an error coefficient (breaks c*s + e_fake != d) ---
        {
            let c_rns = sample_uniform_rq(&mut rng);
            let s_i = sample_ternary(&mut rng);
            let mut e_i = sample_error(&mut rng)?;
            let d_rns = compute_d_rns(&c_rns, &s_i, &e_i)
                .map_err(|err| format!("change-err trial {trial}: {err}"))?;
            e_i[0] = SIGMA_B_E + 17;
            let stmt = SigmaStatement { c_rns, d_rns };
            let wit = SigmaWitness { s_i, e_i };
            let proof = prove(b"test-session-n4", 0, &stmt, &wit, &mut rng)
                .map_err(|err| format!("change-err prove trial {trial}: {err}"))?;
            assert!(
                verify(b"test-session-n4", 0, &stmt, &proof).is_err(),
                "change-err trial {trial}: should have been rejected"
            );
        }

        // --- Tamper 3: corrupt d_i in the statement (honest witness, wrong d) ---
        {
            let c_rns = sample_uniform_rq(&mut rng);
            let s_i = sample_ternary(&mut rng);
            let e_i = sample_error(&mut rng)?;
            let d_rns = compute_d_rns(&c_rns, &s_i, &e_i)
                .map_err(|err| format!("tamper-stmt trial {trial}: {err}"))?;
            let mut d_tampered = d_rns.clone();
            d_tampered[0] = (d_tampered[0] + 1) % RLWE_Q0;

            let stmt_honest = SigmaStatement {
                c_rns: c_rns.clone(),
                d_rns,
            };
            let stmt_tampered = SigmaStatement {
                c_rns,
                d_rns: d_tampered,
            };
            let wit = SigmaWitness { s_i, e_i };
            let proof = prove(b"test-session-n4", 0, &stmt_honest, &wit, &mut rng)
                .map_err(|err| format!("tamper-stmt prove trial {trial}: {err}"))?;
            assert!(
                verify(b"test-session-n4", 0, &stmt_tampered, &proof).is_err(),
                "tamper-stmt trial {trial}: should have been rejected"
            );
        }
    }
    Ok(())
}
