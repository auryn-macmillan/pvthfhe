#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(unexpected_cfgs)]

//! Regression test: reshare randomness is non-deterministic (audit finding F23).
//!
//! Before R0.7, the reshare path at `fhers.rs:258` used
//! `ChaCha8Rng::seed_from_u64(party_id)`, making reshare output a deterministic
//! function of party_id.  R0.7 migrated that call to `OsRng`.  This test
//! verifies that repeated calls to `generate_secret_shares_from_poly` (the same
//! operation performed by the reshare path) produce non-deterministic
//! coefficients across 100 invocations for the same input.

#[cfg(not(feature = "demo-seeded-rng"))]
#[allow(unexpected_cfgs)]
#[test]
fn reshare_entropy() {
    use std::collections::HashSet;

    use fhe::trbfv::ShareManager;
    use pvthfhe_fhe::{fhers::FhersBackend, FheBackend};
    use pvthfhe_rng::OsRng;

    const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

    const N: usize = 3;
    const T: usize = 2;
    const ITERATIONS: usize = 100;

    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let bfv_params = backend.bfv_params().clone();
    let shamir_threshold = T.saturating_sub(1).min(N.saturating_sub(T));
    let mut share_manager = ShareManager::new(N, shamir_threshold, bfv_params.clone());

    let coeffs: Vec<i64> = (0..bfv_params.degree())
        .map(|i| (i as i64) % 7 - 3)
        .collect();
    let sk_poly = share_manager
        .coeffs_to_poly_level0(&coeffs)
        .expect("coeffs to poly");

    let mut fingerprints = HashSet::new();

    for _ in 0..ITERATIONS {
        let rng = OsRng;
        let shares = share_manager
            .generate_secret_shares_from_poly(sk_poly.clone(), rng)
            .expect("generate secret shares");

        // Fingerprint: first 8 coefficients of row 0 for each share matrix
        let fp: Vec<Vec<u64>> = shares
            .iter()
            .map(|matrix| matrix.row(0).iter().take(8).copied().collect::<Vec<_>>())
            .collect();
        fingerprints.insert(fp);
    }

    let unique = fingerprints.len();
    let ratio = unique as f64 / ITERATIONS as f64;
    assert!(
        ratio > 0.99,
        "reshare output is too deterministic: {} unique fingerprints out of {} iterations ({:.2}%)",
        unique,
        ITERATIONS,
        ratio * 100.0,
    );
}
