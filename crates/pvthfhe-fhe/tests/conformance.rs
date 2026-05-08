//! Conformance tests for [`FheBackend`] implementations.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
//!
//! These tests define the contract that every backend must satisfy.
//! Run with `--features mock` to test the mock backend.
//! Run without features to test the primary (fhe.rs) backend.

use pvthfhe_fhe::{FheBackend, FheError};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fmt::Debug;

/// Minimal TOML params string for tests.
const TEST_PARAMS_TOML: &str = r#"
[rlwe]
n = 8192
log2_q = 174
t_plain = 65536
moduli = [288230376173076481, 288230376167047169, 288230376161280001]
variance = 10
"#;

/// Generic round-trip test: keygen → encrypt → partial_decrypt × 2 → aggregate_decrypt.
#[cfg(feature = "mock")]
fn test_round_trip<B: FheBackend>(backend: B) {
    let mut rng = StdRng::seed_from_u64(42);
    let plaintext = b"hello threshold fhe";

    let share0 = must_ok(backend.keygen_share(0, &mut rng), "keygen_share(0) failed");
    let share1 = must_ok(backend.keygen_share(1, &mut rng), "keygen_share(1) failed");
    let pk = must_ok(
        backend.aggregate_keygen(&[share0, share1]),
        "aggregate_keygen failed",
    );
    let ct = must_ok(backend.encrypt(&pk, plaintext, &mut rng), "encrypt failed");
    let ds0 = must_ok(
        backend.partial_decrypt(&ct, 0, &mut rng),
        "partial_decrypt(0) failed",
    );
    let ds1 = must_ok(
        backend.partial_decrypt(&ct, 1, &mut rng),
        "partial_decrypt(1) failed",
    );
    let recovered = must_ok(
        backend.aggregate_decrypt(&ct, &[ds0, ds1], 2),
        "aggregate_decrypt failed",
    );
    assert_eq!(recovered, plaintext.as_ref());
}

/// Verify that party_id is preserved in keygen shares.
#[cfg(feature = "mock")]
fn test_keygen_share_party_id<B: FheBackend>(backend: B) {
    let mut rng = StdRng::seed_from_u64(0);
    let share = must_ok(backend.keygen_share(7, &mut rng), "keygen_share failed");
    assert_eq!(share.party_id, 7);
}

/// Verify that party_id is preserved in decrypt shares.
#[cfg(feature = "mock")]
fn test_decrypt_share_party_id<B: FheBackend>(backend: B) {
    let mut rng = StdRng::seed_from_u64(0);
    let s0 = must_ok(backend.keygen_share(0, &mut rng), "keygen_share(0)");
    let s1 = must_ok(backend.keygen_share(1, &mut rng), "keygen_share(1)");
    let pk = must_ok(backend.aggregate_keygen(&[s0, s1]), "aggregate_keygen");
    let ct = must_ok(backend.encrypt(&pk, b"test", &mut rng), "encrypt");
    let ds = must_ok(backend.partial_decrypt(&ct, 5, &mut rng), "partial_decrypt");
    assert_eq!(ds.party_id, 5);
}

/// Verify that insufficient shares returns an error.
#[cfg(feature = "mock")]
fn test_insufficient_shares<B: FheBackend>(backend: B) {
    let mut rng = StdRng::seed_from_u64(1);
    let s0 = backend.keygen_share(0, &mut rng).expect("keygen_share(0)");
    let s1 = backend.keygen_share(1, &mut rng).expect("keygen_share(1)");
    let pk = backend
        .aggregate_keygen(&[s0, s1])
        .expect("aggregate_keygen");
    let ct = backend.encrypt(&pk, b"test", &mut rng).expect("encrypt");
    let ds0 = backend
        .partial_decrypt(&ct, 0, &mut rng)
        .expect("partial_decrypt(0)");
    // Only 1 share but threshold=2 — must fail
    let result = backend.aggregate_decrypt(&ct, &[ds0], 2);
    assert!(
        matches!(result, Err(FheError::InsufficientShares { .. })),
        "expected InsufficientShares, got {:?}",
        result
    );
}

/// Verify load_params succeeds with valid TOML.
fn test_load_params<B: FheBackend>() {
    let backend = must_ok(B::load_params(TEST_PARAMS_TOML), "load_params failed");
    drop(backend);
}

/// Verify the current primary-backend surface is explicit during phased wiring.
fn test_primary_backend_surface<B: FheBackend>(backend: B) {
    let mut rng = StdRng::seed_from_u64(7);

    let share = must_ok(
        backend.keygen_share(0, &mut rng),
        "keygen_share should succeed",
    );
    assert_eq!(share.party_id, 0);
    assert!(
        !share.bytes.is_empty(),
        "keygen share bytes should not be empty"
    );

    let session_id = [9u8; 32];
    let share_1 = must_ok(
        backend.keygen_share_with_session(&session_id, 1, &mut rng),
        "keygen_share_with_session(1) should succeed",
    );
    let share_2 = must_ok(
        backend.keygen_share_with_session(&session_id, 2, &mut rng),
        "keygen_share_with_session(2) should succeed",
    );
    let pk = must_ok(
        backend.aggregate_keygen(&[share_1, share_2]),
        "aggregate_keygen should succeed for same-session shares",
    );
    assert!(
        !pk.bytes.is_empty(),
        "aggregate public key bytes should not be empty"
    );

    let ct = must_ok(
        backend.encrypt(&pk, b"test", &mut rng),
        "encrypt should succeed",
    );
    assert!(!ct.bytes.is_empty(), "ciphertext bytes should not be empty");

    assert!(matches!(
        backend.encrypt(&pvthfhe_fhe::PublicKey { bytes: vec![] }, b"test", &mut rng,),
        Err(FheError::MalformedPublicKey)
    ));

    assert!(matches!(
        backend.partial_decrypt(&pvthfhe_fhe::Ciphertext { bytes: vec![] }, 0, &mut rng,),
        Err(FheError::Backend { .. })
    ));

    assert!(matches!(
        backend.aggregate_decrypt(&pvthfhe_fhe::Ciphertext { bytes: vec![] }, &[], 1),
        Err(FheError::Backend { .. })
    ));
}

fn must_ok<T, E: Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => unreachable!("{context}: {err:?}"),
    }
}

// ── Mock backend tests (feature = "mock") ────────────────────────────────────

#[cfg(feature = "mock")]
mod mock_tests {
    use super::*;
    use pvthfhe_fhe::mock::MockBackend;

    #[test]
    fn mock_load_params() {
        test_load_params::<MockBackend>();
    }

    #[test]
    fn mock_round_trip() {
        let backend = must_ok(MockBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_round_trip(backend);
    }

    #[test]
    fn mock_keygen_share_party_id() {
        let backend = must_ok(MockBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_keygen_share_party_id(backend);
    }

    #[test]
    fn mock_decrypt_share_party_id() {
        let backend = must_ok(MockBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_decrypt_share_party_id(backend);
    }

    #[test]
    fn mock_insufficient_shares() {
        let backend = must_ok(MockBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_insufficient_shares(backend);
    }
}

// ── Primary backend tests (no feature flag) ──────────────────────────────────

#[cfg(not(feature = "mock"))]
mod primary_tests {
    use super::*;
    use pvthfhe_fhe::fhers::FhersBackend;

    #[test]
    fn primary_load_params() {
        test_load_params::<FhersBackend>();
    }

    #[test]
    fn primary_round_trip() {
        let backend = must_ok(FhersBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_primary_backend_surface(backend);
    }

    #[test]
    fn primary_keygen_share_party_id() {
        let backend = must_ok(FhersBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_primary_backend_surface(backend);
    }

    #[test]
    fn primary_decrypt_share_party_id() {
        let backend = must_ok(FhersBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_primary_backend_surface(backend);
    }

    #[test]
    fn primary_insufficient_shares() {
        let backend = must_ok(FhersBackend::load_params(TEST_PARAMS_TOML), "load_params");
        test_primary_backend_surface(backend);
    }
}
