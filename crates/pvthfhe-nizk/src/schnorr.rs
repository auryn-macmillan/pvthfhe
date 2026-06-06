//! Schnorr signatures over BN254 G1 curve.
//!
//! Standard Schnorr protocol via Fiat-Shamir with SHA-256 over raw G1
//! coordinate bytes (avoids Fp→Fr barrel reduction — see M3).
//!
//! ## Protocol
//! 1. Prover: R = r·G (random r), e = SHA256(R.bytes, PK.bytes, msg), s = r + e·sk
//! 2. Verifier: s·G == R + e·PK

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use rand_core::RngCore;

/// Generate a signing keypair. Returns (secret_key, public_key).
pub fn generate_signing_keypair(rng: &mut impl RngCore) -> (Fr, G1Affine) {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    // M3: from_le_bytes_mod_order performs barrel reduction on ~16% of random
    // 64-byte values. Bias is ~2^-254 per key — negligible for this prototype.
    // Production hardening: rejection-sample until bytes < |Fr|.
    let sk = Fr::from_le_bytes_mod_order(&buf);
    let pk = (G1Projective::generator() * sk).into_affine();
    (sk, pk)
}

/// Sign a message hash using Schnorr over BN254 G1.
pub fn schnorr_sign(sk: Fr, message: Fr, rng: &mut impl RngCore) -> (G1Affine, Fr) {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    // M3: from_le_bytes_mod_order performs barrel reduction on ~16% of random
    // 64-byte values. Bias is ~2^-254 per nonce — negligible for this prototype.
    // Production hardening: rejection-sample until bytes < |Fr|.
    let r = Fr::from_le_bytes_mod_order(&buf);
    let r_point = (G1Projective::generator() * r).into_affine();
    let pk_point = (G1Projective::generator() * sk).into_affine();
    let challenge = hash_to_challenge(&r_point, &pk_point, message);
    let s = r + challenge * sk;
    (r_point, s)
}

/// Verify a Schnorr signature: s·G == R + e·PK where e = SHA-256(R.bytes, PK.bytes, msg).
pub fn schnorr_verify(pk: G1Affine, sig_r: G1Affine, sig_s: Fr, message: Fr) -> bool {
    if !pk.is_on_curve() || !sig_r.is_on_curve() {
        return false;
    }
    let challenge = hash_to_challenge(&sig_r, &pk, message);
    let left = G1Projective::generator() * sig_s;
    let right = sig_r.into_group() + pk.into_group() * challenge;
    left.into_affine() == right.into_affine()
}

/// Serialize a G1 affine coordinate to bytes (NOT to Fr — avoids barrel reduction).
fn affine_to_bytes(p: &G1Affine, is_x: bool) -> [u8; 32] {
    let raw = if is_x {
        match p.x() {
            Some(c) => c,
            None => return [0u8; 32],
        }
    } else {
        match p.y() {
            Some(c) => c,
            None => return [0u8; 32],
        }
    };
    let mut buf = [0u8; 32];
    let bytes = raw.into_bigint().to_bytes_le();
    buf[..bytes.len()].copy_from_slice(&bytes);
    buf
}

/// Fiat-Shamir challenge: SHA256(domain, R.x, R.y, PK.x, PK.y, msg).
/// Uses raw G1 coordinate bytes to avoid Fp→Fr barrel reduction (M3).
fn hash_to_challenge(r: &G1Affine, pk: &G1Affine, message: Fr) -> Fr {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pvthfhe_domain_tags::Tag::SchnorrChallenge.as_bytes());
    h.update(affine_to_bytes(r, true));
    h.update(affine_to_bytes(r, false));
    h.update(affine_to_bytes(pk, true));
    h.update(affine_to_bytes(pk, false));
    // Convert message Fr to bytes for hashing
    let msg_bytes = message.into_bigint().to_bytes_le();
    h.update(&msg_bytes);
    Fr::from_be_bytes_mod_order(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    #[test]
    fn roundtrip() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let (sk, pk) = generate_signing_keypair(&mut rng);
        let msg = Fr::from(42u64);
        let (r, s) = schnorr_sign(sk, msg, &mut rng);
        assert!(schnorr_verify(pk, r, s, msg));
    }

    #[test]
    fn rejects_wrong_msg() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let (sk, pk) = generate_signing_keypair(&mut rng);
        let msg = Fr::from(42u64);
        let (r, s) = schnorr_sign(sk, msg, &mut rng);
        let wrong = Fr::from(99u64);
        assert!(!schnorr_verify(pk, r, s, wrong));
    }

    #[test]
    fn rejects_wrong_key() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let (sk1, _) = generate_signing_keypair(&mut rng);
        let (_, pk2) = generate_signing_keypair(&mut rng);
        let msg = Fr::from(42u64);
        let (r, s) = schnorr_sign(sk1, msg, &mut rng);
        assert!(!schnorr_verify(pk2, r, s, msg));
    }
}
