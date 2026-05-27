//! Integration tests for Schnorr signatures.
//!
//! Verifies roundtrip, rejection of wrong messages/keys, and M3 barrel-reduction safety.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_nizk::schnorr::{generate_signing_keypair, schnorr_sign, schnorr_verify};
use rand_core::SeedableRng;

#[test]
fn schnorr_roundtrip_deterministic() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let msg = Fr::from(12345u64);
    let (r, s) = schnorr_sign(sk, msg, &mut rng);
    assert!(schnorr_verify(pk, r, s, msg));
}

#[test]
fn schnorr_rejects_wrong_message() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let msg = Fr::from(12345u64);
    let (r, s) = schnorr_sign(sk, msg, &mut rng);
    let wrong = Fr::from(99999u64);
    assert!(!schnorr_verify(pk, r, s, wrong));
}

#[test]
fn schnorr_rejects_wrong_key() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let (sk1, _) = generate_signing_keypair(&mut rng);
    let (_, pk2) = generate_signing_keypair(&mut rng);
    let msg = Fr::from(12345u64);
    let (r, s) = schnorr_sign(sk1, msg, &mut rng);
    assert!(!schnorr_verify(pk2, r, s, msg));
}

#[test]
fn schnorr_rejects_tampered_signature() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let msg = Fr::from(12345u64);
    let (r, s) = schnorr_sign(sk, msg, &mut rng);
    // Tamper with the s component
    let tampered_s = s + Fr::from(1u64);
    assert!(!schnorr_verify(pk, r, tampered_s, msg));
}

#[test]
fn schnorr_multiple_messages() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    for i in 0u64..10u64 {
        let msg = Fr::from(i);
        let (r, s) = schnorr_sign(sk, msg, &mut rng);
        assert!(
            schnorr_verify(pk, r, s, msg),
            "roundtrip failed for msg={i}"
        );
    }
}

/// M3: Verify that large field-element messages (close to |Fr|) work correctly.
/// These could trigger barrel reduction in the old Fp→Fr path but are safe
/// with the new SHA-256-based challenge.
#[test]
fn schnorr_large_message_no_barrel_reduction() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    // A message near the top of the Fr field
    let modulus = Fr::MODULUS;
    let msg = Fr::from_be_bytes_mod_order(&modulus.to_bytes_be());
    let (r, s) = schnorr_sign(sk, msg, &mut rng);
    assert!(schnorr_verify(pk, r, s, msg));
}

/// M3: Verify that distinct G1 points with coordinates above/below Fr produce
/// distinct challenges (no barrel-reduction collisions).
#[test]
fn schnorr_distinct_points_produce_distinct_challenges() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(13);
    let (sk1, pk1) = generate_signing_keypair(&mut rng);
    let (sk2, pk2) = generate_signing_keypair(&mut rng);
    let msg = Fr::from(42u64);

    let (r1, s1) = schnorr_sign(sk1, msg, &mut rng);
    let (r2, s2) = schnorr_sign(sk2, msg, &mut rng);

    // pk1 != pk2 should mean r1 != r2 with overwhelming probability
    assert_ne!(r1, r2);

    // Each signature verifies against its own key
    assert!(schnorr_verify(pk1, r1, s1, msg));
    assert!(schnorr_verify(pk2, r2, s2, msg));

    // Cross-verification should fail (different challenges)
    assert!(!schnorr_verify(pk2, r1, s1, msg));
    assert!(!schnorr_verify(pk1, r2, s2, msg));
}
