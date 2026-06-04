//! Sigma protocol fuzzer.
//!
//! Fuzzes `sigma::prove` and `sigma::verify` with random statements/witnesses.
//! Verifies:
//! 1. Honest prover roundtrip passes (prove + verify = Ok)
//! 2. Tampered proofs are rejected
//! 3. Challenge-dependent behavior across sessions

// Fuzz harness: expect() on setup is an acceptable failure signal.
#![allow(clippy::expect_used)]

use pvthfhe_fuzz::{sample_bounded_i64, sample_ternary, FUZZ_ITERATIONS};
use pvthfhe_nizk::sigma::{
    compute_d_rns, num_rns_limbs, prove, rlwe_n, verify, RLWE_Q0, RLWE_Q1, RLWE_Q2, SIGMA_B_E,
    SIGMA_REPETITIONS,
};
use pvthfhe_nizk::sigma::{SigmaStatement, SigmaWitness};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn generate_random_statement_witness(rng: &mut dyn RngCore) -> (SigmaStatement, SigmaWitness) {
    let n = rlwe_n();
    let l = num_rns_limbs();
    let moduli = [RLWE_Q0, RLWE_Q1, RLWE_Q2];

    // Generate random c_rns
    let mut c_rns = vec![0u64; n * l];
    for (limb, &q) in moduli.iter().enumerate() {
        for j in 0..n {
            c_rns[limb * n + j] = rng.next_u64() % q;
        }
    }

    // Generate random s_i (ternary) and e_i (bounded by SIGMA_B_E)
    let s_i = sample_ternary(rng, n);
    let e_i = sample_bounded_i64(rng, n, SIGMA_B_E);

    // Compute d_rns = c * s_i + e_i
    let d_rns = compute_d_rns(&c_rns, &s_i, &e_i).expect("compute_d_rns should succeed");

    (SigmaStatement { c_rns, d_rns }, SigmaWitness { s_i, e_i })
}

fn main() {
    println!("=== Sigma Fuzzer ===");
    println!("Iterations: {FUZZ_ITERATIONS}");
    println!(
        "N: {}, RNS limbs: {}, SIGMA_REPETITIONS: {}",
        rlwe_n(),
        num_rns_limbs(),
        SIGMA_REPETITIONS
    );

    let mut honest_pass = 0u64;
    let mut honest_fail = 0u64;
    let mut tamper_reject = 0u64;
    let mut tamper_accept = 0u64;
    let mut multi_pass = 0u64;
    let mut multi_fail = 0u64;

    for i in 0..FUZZ_ITERATIONS {
        // Use deterministic seed from iteration for reproducibility
        let seed = (i as u64)
            .wrapping_mul(0xDEAD_BEEF)
            .wrapping_add(0xCAFE_D00D);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let session_id = format!("fuzz-session-{i}").into_bytes();
        let participant_id = (rng.next_u64() % 256) as u32;
        let d_commitment = {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };

        let (stmt, wit) = generate_random_statement_witness(&mut rng);

        // 1. Single-round prove
        let proof = match prove(
            &session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{i}] prove error: {e:?}");
                honest_fail += 1;
                continue;
            }
        };

        // 2. Honest verifier
        match verify(&session_id, participant_id, &stmt, &proof, &d_commitment) {
            Ok(()) => honest_pass += 1,
            Err(e) => {
                eprintln!("[{i}] honest verify error: {e:?}");
                honest_fail += 1;
            }
        }

        // 3. Tampered proof (flip a t_rns byte)
        {
            let mut tampered = proof.clone();
            if !tampered.t_rns.is_empty() {
                tampered.t_rns[0] ^= 0xFF;
            }
            match verify(&session_id, participant_id, &stmt, &tampered, &d_commitment) {
                Err(_) => tamper_reject += 1,
                Ok(()) => {
                    eprintln!("[{i}] WARNING: tampered proof accepted!");
                    tamper_accept += 1;
                }
            }
        }

        // 4. Wrong session_id
        {
            let wrong_session = b"wrong-session-fuzz";
            match verify(wrong_session, participant_id, &stmt, &proof, &d_commitment) {
                Err(_) => {} // expected
                Ok(()) => eprintln!("[{i}] WARNING: wrong session accepted!"),
            }
        }

        // 5. Wrong participant_id
        {
            let wrong_pid = participant_id.wrapping_add(1);
            match verify(&session_id, wrong_pid, &stmt, &proof, &d_commitment) {
                Err(_) => {} // expected
                Ok(()) => eprintln!("[{i}] WARNING: wrong participant accepted!"),
            }
        }

        // 6. Multi-round prove/verify (use fewer rounds for speed)
        let num_rounds = 4; // test with 4 rounds for speed
        let multi_proof = match pvthfhe_nizk::sigma::prove_multi(
            &session_id,
            participant_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
            num_rounds,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{i}] multi prove error: {e:?}");
                multi_fail += 1;
                continue;
            }
        };

        match pvthfhe_nizk::sigma::verify_multi(
            &session_id,
            participant_id,
            &stmt,
            &multi_proof,
            &d_commitment,
        ) {
            Ok(()) => multi_pass += 1,
            Err(e) => {
                eprintln!("[{i}] multi verify error: {e:?}");
                multi_fail += 1;
            }
        }

        if i > 0 && i % 1000 == 0 {
            println!("[{i}/{FUZZ_ITERATIONS}]...");
        }
    }

    println!();
    println!("=== Results ===");
    println!("Honest roundtrip: {honest_pass} pass, {honest_fail} fail");
    println!("Tamper rejection: {tamper_reject} reject, {tamper_accept} accept");
    println!("Multi-round: {multi_pass} pass, {multi_fail} fail");

    if honest_fail > 0 || tamper_accept > 0 || multi_fail > 0 {
        eprintln!("FUZZ FAILED");
        std::process::exit(1);
    }
    println!("FUZZ PASSED");
}
