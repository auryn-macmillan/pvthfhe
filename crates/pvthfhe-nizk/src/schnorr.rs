//! Schnorr signatures over BN254 G1 curve.
//!
//! Standard Schnorr protocol via Fiat-Shamir with Poseidon sponge hashing.
//! Compatible with Noir in-circuit verification at ~3K constraints/sig.
//!
//! ## Protocol
//! 1. Prover: R = r·G (random r), e = Poseidon(R, PK, msg), s = r + e·sk
//! 2. Verifier: s·G == R + e·PK

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use rand_core::RngCore;

/// Generate a signing keypair. Returns (secret_key, public_key).
pub fn generate_signing_keypair(rng: &mut impl RngCore) -> (Fr, G1Affine) {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    let sk = Fr::from_le_bytes_mod_order(&buf);
    let pk = (G1Projective::generator() * sk).into_affine();
    (sk, pk)
}

/// Sign a message hash using Schnorr over BN254 G1.
pub fn schnorr_sign(sk: Fr, message: Fr, rng: &mut impl RngCore) -> (G1Affine, Fr) {
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    let r = Fr::from_le_bytes_mod_order(&buf);
    let r_point = (G1Projective::generator() * r).into_affine();
    let pk_point = (G1Projective::generator() * sk).into_affine();
    let challenge = hash_to_challenge(&r_point, &pk_point, message);
    let s = r + challenge * sk;
    (r_point, s)
}

/// Verify a Schnorr signature: s·G == R + e·PK where e = Poseidon(R, PK, msg).
pub fn schnorr_verify(pk: G1Affine, sig_r: G1Affine, sig_s: Fr, message: Fr) -> bool {
    let challenge = hash_to_challenge(&sig_r, &pk, message);
    let left = G1Projective::generator() * sig_s;
    let right = sig_r.into_group() + pk.into_group() * challenge;
    left.into_affine() == right.into_affine()
}

/// Serialize a G1 affine coordinate to Fr.
fn affine_to_fr(p: &G1Affine, is_x: bool) -> Fr {
    let raw = if is_x { p.x().unwrap() } else { p.y().unwrap() };
    Fr::from_le_bytes_mod_order(&raw.into_bigint().to_bytes_le())
}

/// Fiat-Shamir challenge: Poseidon(domain, R.x, R.y, PK.x, PK.y, msg).
fn hash_to_challenge(r: &G1Affine, pk: &G1Affine, message: Fr) -> Fr {
    let inputs = vec![
        Fr::from(0x7363686e6f7272u64),
        affine_to_fr(r, true),
        affine_to_fr(r, false),
        affine_to_fr(pk, true),
        affine_to_fr(pk, false),
        message,
    ];
    let mut hasher =
        Poseidon::<Fr>::new_circom(inputs.len()).expect("Poseidon arity within Circom range");
    hasher.hash(&inputs).expect("Poseidon hash must succeed")
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
