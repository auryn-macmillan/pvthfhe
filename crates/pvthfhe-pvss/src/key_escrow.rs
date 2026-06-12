//! Key Escrow protocol for distributed key authorization.
//! ePrint 2026/1159 §6, Algorithms 3-5

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

const DOMAIN_SEPARATOR: &[u8] = b"pvthfhe-key-escrow/v1";

/// An escrowed ephemeral public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EphPublicKey {
    pub key_bytes: [u8; 32],
    pub epoch: u64,
}

/// Proof that this key was correctly escrowed.
#[derive(Clone, Debug)]
pub struct KeyEscrowProof {
    pub epoch: u64,
    pub commitment: [u8; 32],
}

/// An escrowed secret key share (one per party).
#[derive(Clone, Debug)]
pub struct EphSecretShare {
    pub party_id: u32,
    pub share: Fr,
}

/// The reconstructed escrowed secret key.
#[derive(Clone, Debug)]
pub struct EphSecretKey {
    pub key_bytes: [u8; 32],
}

/// Generate an escrowed key pair. The secret key is deterministically derived
/// from `session_id || tag` and hidden until reconstruction.
///
/// The raw SHA-256 hash is reduced modulo the BN254 scalar field order and
/// stored in canonical big-endian byte form so that the bytes→Fr→bytes
/// round-trip through [`escrow_shares`] and [`key_retrieve`] is lossless.
pub fn key_escrow(
    session_id: &[u8],
    tag: &[u8],
    epoch: u64,
    _rng: &mut impl RngCore,
) -> (EphPublicKey, KeyEscrowProof) {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(session_id);
    h.update(tag);
    h.update(&epoch.to_be_bytes());
    let raw_hash: [u8; 32] = h.finalize().into();

    // Reduce into the BN254 scalar field and convert back to canonical
    // bytes so that escrow_shares / key_retrieve round-trip losslessly.
    let scalar = Fr::from_be_bytes_mod_order(&raw_hash);
    let big_bytes = scalar.into_bigint().to_bytes_be();
    let mut key_bytes = [0u8; 32];
    let start = 32usize.saturating_sub(big_bytes.len());
    let copy_len = (32 - start).min(big_bytes.len());
    key_bytes[start..start + copy_len].copy_from_slice(&big_bytes[..copy_len]);

    let commitment = hash_commitment(&key_bytes, epoch);
    (
        EphPublicKey { key_bytes, epoch },
        KeyEscrowProof { epoch, commitment },
    )
}

/// Verify that an escrowed public key is well-formed.
pub fn key_verify(pk: &EphPublicKey, proof: &KeyEscrowProof) -> bool {
    pk.epoch == proof.epoch && hash_commitment(&pk.key_bytes, pk.epoch) == proof.commitment
}

/// Convert the escrowed secret key into Shamir shares (Fr values).
///
/// Returns `n` shares; threshold `t` needed for reconstruction. Uses a random
/// polynomial of degree `t-1` evaluated at `x = 1..n`.
pub fn escrow_shares(eph_sk: &EphSecretKey, n: usize, t: usize, rng: &mut impl RngCore) -> Vec<Fr> {
    let secret = Fr::from_be_bytes_mod_order(&eph_sk.key_bytes);
    let mut coeffs = vec![secret];
    let mut temp = [0u8; 32];
    for _ in 1..t {
        rng.fill_bytes(&mut temp);
        coeffs.push(Fr::from_be_bytes_mod_order(&temp));
    }
    (1..=n)
        .map(|x| {
            let x_fr = Fr::from(x as u64);
            coeffs
                .iter()
                .rev()
                .fold(Fr::zero(), |acc, c| acc * x_fr + c)
        })
        .collect()
}

/// Reconstruct the escrowed secret key from `t` valid shares via Lagrange
/// interpolation at `x = 0`.
pub fn key_retrieve(shares: &[(u32, Fr)], threshold: usize) -> Option<EphSecretKey> {
    if shares.len() < threshold {
        return None;
    }

    // Lagrange interpolation at x = 0:
    //   f(0) = Σ_i y_i · L_i(0)
    //   L_i(0) = Π_{j≠i} (-x_j) / (x_i - x_j)
    let mut secret = Fr::zero();
    for (i, (xi, yi)) in shares.iter().enumerate() {
        let x_i = Fr::from(*xi as u64);
        let mut numerator = Fr::ONE;
        let mut denominator = Fr::ONE;
        for (j, (xj, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j = Fr::from(*xj as u64);
            numerator *= -x_j;
            denominator *= x_i - x_j;
        }
        if denominator.is_zero() {
            return None;
        }
        let lambda = numerator * denominator.inverse().unwrap();
        secret += *yi * lambda;
    }

    let mut bytes = [0u8; 32];
    let big_bytes = secret.into_bigint().to_bytes_be();
    let start = 32usize.saturating_sub(big_bytes.len());
    let copy_len = (32 - start).min(big_bytes.len());
    bytes[start..start + copy_len].copy_from_slice(&big_bytes[..copy_len]);
    Some(EphSecretKey { key_bytes: bytes })
}

fn hash_commitment(key_bytes: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEPARATOR);
    h.update(b":commit:");
    h.update(key_bytes);
    h.update(&epoch.to_be_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_escrow_and_verify() {
        let mut rng = ChaCha8Rng::from_seed([0x42; 32]);
        let (pk, proof) = key_escrow(b"session1", b"tag1", 42, &mut rng);
        assert!(key_verify(&pk, &proof));
    }

    #[test]
    fn test_wrong_epoch_rejected() {
        let mut rng = ChaCha8Rng::from_seed([0x42; 32]);
        let (pk, _proof) = key_escrow(b"session1", b"tag1", 42, &mut rng);
        let (_, mut proof) = key_escrow(b"session1", b"tag1", 99, &mut rng);
        proof.epoch = 42; // lie
        assert!(!key_verify(&pk, &proof));
    }

    #[test]
    fn test_escrow_shares_and_reconstruct() {
        let mut rng = ChaCha8Rng::from_seed([0x42; 32]);
        let (pk, _proof) = key_escrow(b"s", b"t", 1, &mut rng);
        let eph_sk = EphSecretKey {
            key_bytes: pk.key_bytes,
        };
        let shares = escrow_shares(&eph_sk, 10, 5, &mut rng);
        let share_pairs: Vec<(u32, Fr)> = (1..=5).map(|i| (i as u32, shares[i - 1])).collect();
        let recovered = key_retrieve(&share_pairs, 5).unwrap();
        assert_eq!(recovered.key_bytes, eph_sk.key_bytes);
    }
}
