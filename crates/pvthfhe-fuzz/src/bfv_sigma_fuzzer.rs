use fhe_math::rq::Context;
use pvthfhe_fuzz::{sample_bounded_i64, FUZZ_ITERATIONS};
use pvthfhe_nizk::bfv_sigma::{
    self, bfv_delta_rns, BfvSigmaStatement, BfvSigmaWitness, BFV_SIGMA_B_E, B_M, B_U, B_Y,
};
use pvthfhe_nizk::sigma::{int_poly_to_rns, num_rns_limbs, poly_mul_rq, rlwe_n, rns_add};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::sync::{Arc, OnceLock};

fn get_ctx() -> &'static Arc<Context> {
    static CTX: OnceLock<Arc<Context>> = OnceLock::new();
    CTX.get_or_init(|| {
        let moduli = [
            288_230_376_173_076_481u64,
            288_230_376_167_047_169u64,
            288_230_376_161_280_001u64,
        ];
        Arc::new(Context::new(&moduli, 8192).expect("RLWE context creation"))
    })
}

fn generate_random_bfv_statement_witness(
    rng: &mut dyn RngCore,
) -> (BfvSigmaStatement, BfvSigmaWitness) {
    let n = rlwe_n();
    let l = num_rns_limbs();
    let ctx = get_ctx();
    let moduli = [
        288_230_376_173_076_481u64,
        288_230_376_167_047_169u64,
        288_230_376_161_280_001u64,
    ];

    let mut pk0_rns = vec![0u64; n * l];
    let mut pk1_rns = vec![0u64; n * l];
    for (limb, &q) in moduli.iter().enumerate() {
        for j in 0..n {
            pk0_rns[limb * n + j] = rng.next_u64() % q;
            pk1_rns[limb * n + j] = rng.next_u64() % q;
        }
    }

    let t_plain: u64 = 65536;
    let delta_limbs = bfv_delta_rns(t_plain).expect("bfv_delta_rns");

    let u = sample_bounded_i64(rng, n, B_U.min(B_Y / (n as i64) - 1).max(1));
    let e0 = sample_bounded_i64(rng, n, BFV_SIGMA_B_E.min(B_Y / (n as i64) - 1).max(1));
    let e1 = sample_bounded_i64(rng, n, BFV_SIGMA_B_E.min(B_Y / (n as i64) - 1).max(1));
    let m = sample_bounded_i64(rng, n, B_M);

    let u_rns = int_poly_to_rns(&u, ctx).expect("u rns");
    let e0_rns = int_poly_to_rns(&e0, ctx).expect("e0 rns");
    let e1_rns = int_poly_to_rns(&e1, ctx).expect("e1 rns");

    let pk0_u_rns = poly_mul_rq(&pk0_rns, &u_rns, ctx).expect("pk0*u");
    let pk1_u_rns = poly_mul_rq(&pk1_rns, &u_rns, ctx).expect("pk1*u");
    let delta_m_rns =
        pvthfhe_nizk::bfv_sigma::scale_plaintext_to_rns(&m, &delta_limbs).expect("delta*m");

    let ct0_rns = rns_add(
        &rns_add(&pk0_u_rns, &e0_rns, ctx).expect("pk0u+e0"),
        &delta_m_rns,
        ctx,
    )
    .expect("ct0");
    let ct1_rns = rns_add(&pk1_u_rns, &e1_rns, ctx).expect("ct1");

    (
        BfvSigmaStatement {
            pk0_rns,
            pk1_rns,
            ct0_rns,
            ct1_rns,
            delta_limbs,
            t_plain,
        },
        BfvSigmaWitness { u, e0, e1, m },
    )
}

fn main() {
    println!("=== BFV Sigma Fuzzer ===");
    println!("Iterations: {FUZZ_ITERATIONS}");

    let mut honest_pass = 0u64;
    let mut honest_fail = 0u64;
    let mut tamper_reject = 0u64;

    for i in 0..FUZZ_ITERATIONS {
        let seed = (i as u64)
            .wrapping_mul(0xBEEF_CAFE)
            .wrapping_add(0xBF00_BF00);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let session_id = format!("bfv-fuzz-{i}").into_bytes();
        let participant_id = (rng.next_u64() % 256) as u32;
        let binding_data = {
            let mut h = vec![0u8; 32];
            rng.fill_bytes(&mut h);
            h
        };

        let (stmt, wit) = generate_random_bfv_statement_witness(&mut rng);

        let proof = match bfv_sigma::prove(
            &session_id,
            participant_id,
            &stmt,
            &wit,
            &binding_data,
            &mut rng,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{i}] prove error: {e:?}");
                honest_fail += 1;
                continue;
            }
        };

        match bfv_sigma::verify(&session_id, participant_id, &stmt, &proof, &binding_data) {
            Ok(()) => honest_pass += 1,
            Err(e) => {
                eprintln!("[{i}] honest verify error: {e:?}");
                honest_fail += 1;
            }
        }

        {
            let mut tampered = proof.clone();
            if !tampered.t0_rns.is_empty() {
                tampered.t0_rns[0] ^= 0xFF;
            }
            if bfv_sigma::verify(&session_id, participant_id, &stmt, &tampered, &binding_data)
                .is_err()
            {
                tamper_reject += 1;
            } else {
                eprintln!("[{i}] WARNING: tampered BFV proof accepted!");
            }
        }

        {
            let wrong_session = b"wrong-bfv-session";
            assert!(
                bfv_sigma::verify(wrong_session, participant_id, &stmt, &proof, &binding_data)
                    .is_err(),
                "[{i}] wrong session should be rejected"
            );
        }

        if i > 0 && i % 1000 == 0 {
            println!("[{i}/{FUZZ_ITERATIONS}]...");
        }
    }

    println!();
    println!("=== Results ===");
    println!("Honest roundtrip: {honest_pass} pass, {honest_fail} fail");
    println!("Tamper rejection: {tamper_reject} reject");

    if honest_fail > 0 {
        eprintln!("FUZZ FAILED");
        std::process::exit(1);
    }
    println!("FUZZ PASSED");
}
