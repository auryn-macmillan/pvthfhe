//! Integration tests for Schnorr Proof-of-Possession (PoP).
//!
//! PoP proves knowledge of sk where pk = sk·G.
//! Protocol: commit to nonce R=r·G, challenge e = SHA256(tag || pk || R),
//! response s = r + e·sk. Verify: s·G == R + e·pk.

use ark_bn254::Fr;
use pvthfhe_nizk::schnorr::{generate_signing_keypair, schnorr_pop_prove, schnorr_pop_verify};
use rand_core::SeedableRng;

#[test]
fn test_pop_valid_key_accepts() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(99);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let proof = schnorr_pop_prove(sk, pk, &mut rng);
    assert!(schnorr_pop_verify(pk, &proof));
}

#[test]
fn test_pop_unknown_key_rejects() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(99);
    let (sk, pk1) = generate_signing_keypair(&mut rng);
    let (_, pk2) = generate_signing_keypair(&mut rng);
    let proof = schnorr_pop_prove(sk, pk1, &mut rng);
    assert!(!schnorr_pop_verify(pk2, &proof));
}

#[test]
fn test_pop_forged_rejects() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(99);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let mut proof = schnorr_pop_prove(sk, pk, &mut rng);
    // Tamper with the s component
    proof.s += Fr::from(1u64);
    assert!(!schnorr_pop_verify(pk, &proof));
}

#[test]
fn test_pop_distinct_keys_distinct_proofs() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let (sk1, pk1) = generate_signing_keypair(&mut rng);
    let (sk2, pk2) = generate_signing_keypair(&mut rng);

    let proof1 = schnorr_pop_prove(sk1, pk1, &mut rng);
    let proof2 = schnorr_pop_prove(sk2, pk2, &mut rng);

    // Each proof verifies against its own key
    assert!(schnorr_pop_verify(pk1, &proof1));
    assert!(schnorr_pop_verify(pk2, &proof2));

    // Cross-verification should fail
    assert!(!schnorr_pop_verify(pk2, &proof1));
    assert!(!schnorr_pop_verify(pk1, &proof2));
}

#[test]
fn test_pop_rejects_infinity_point() {
    // A proof with the point-at-infinity as R should be rejected.
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(99);
    let (sk, pk) = generate_signing_keypair(&mut rng);
    let mut proof = schnorr_pop_prove(sk, pk, &mut rng);
    // Set r_point to the identity (point at infinity)
    proof.r = ark_bn254::G1Affine::identity();
    assert!(!schnorr_pop_verify(pk, &proof));
}
