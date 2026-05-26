//! R3.6 RED: demo_nizk must require --insecure-seed flag.
//!
//! This test asserts that `build_demo_nizk_inputs` refuses to use a seeded
//! RNG without an explicit insecure-seed tripwire bypass. When `seed` is
//! `None`, the function should use `OsRng` (secure, production path).
//! When `seed` is `Some(...)` without the `demo-seeded-rng` feature flag,
//! the function must return an error.

use pvthfhe_aggregator::keygen::types::Round1Message;
use pvthfhe_cli::demo_nizk::build_demo_nizk_inputs;
use pvthfhe_fhe::PublicKey;

fn test_message() -> Round1Message {
    Round1Message {
        party_id: 7,
        pk_i: PublicKey {
            bytes: vec![1, 2, 3, 4],
        },
        pk_i_hash: [9; 32],
        commitment_nonce: [0u8; 32],
        commitment: [8; 32],
        poly_commit: [7; 32],
        encrypted_shares: Default::default(),
        nizk: vec![],
    }
}

fn rlwe_n() -> usize {
    pvthfhe_nizk::sigma::rlwe_n()
}

#[test]
fn demo_nizk_with_none_seed_uses_osrng_and_succeeds() {
    let message = test_message();
    let secret_key_bytes = vec![0u8; rlwe_n() * 8];

    let result = build_demo_nizk_inputs("session-1", &message, None, &secret_key_bytes);
    assert!(
        result.is_ok(),
        "demo_nizk with seed=None should succeed (uses OsRng)"
    );
}

#[test]
fn demo_nizk_with_some_seed_refuses_without_insecure_flag() {
    let message = test_message();
    let secret_key_bytes = vec![0u8; rlwe_n() * 8];

    let result = build_demo_nizk_inputs("session-1", &message, Some(42), &secret_key_bytes);
    assert!(
        result.is_err(),
        "demo_nizk with seed=Some(42) must fail without --insecure-seed flag / demo-seeded-rng feature"
    );
}
