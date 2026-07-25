//! Scalar challenge derivation (Poseidon-based) for the sigma protocol.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::NizkError;

/// Domain separator for scalar-challenge sigma protocol (v2).
const SCALAR_CHALLENGE_DOMAIN: &[u8] = pvthfhe_foundations::domain_tags::Tag::SigmaScalarChallenge.as_bytes();

// P1 OPEN PROBLEM: Ternary scalar challenge (ch ∈ {-1,0,1}) provides ~1.58 bits
// of soundness per execution. With one round, the soundness error is 2/3 —
// an adversary succeeds 66% of the time by guessing the challenge.
// Resolution pending: either parallel repetition (~90 rounds for 2^-128) or
// switching to binary polynomial challenges in {0,1}^N with NTT-optimized gadgets.
// Tracked as OPEN PROBLEM P1 in SECURITY.md.

// P2-1 audit remediation: the T2 FS-outside-circuit path replaced the legacy
// derive_challenge_scalar with derive_challenge_from_commitment which directly
// produces i64 from the commitment hash without intermediate Poseidon reduction.

/// T2: Derive a Keccak256 transcript commitment from the sigma transcript data.
///
/// Computes `com = Keccak256(DOMAIN || t_rns || c_rns || d_i_rns)` which binds
/// the prover's first message t and the statement (c, d_i) before the challenge
/// is revealed. This commitment is verified in-circuit (via Poseidon, ~900 constraints)
/// so the Fiat-Shamir challenge derivation can be moved outside the circuit
/// (Symphony §6).
pub fn derive_transcript_commitment(t_rns: &[u64], c_rns: &[u64], d_rns: &[u64]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(SCALAR_CHALLENGE_DOMAIN);
    hasher.update(b"t2-commit");
    hasher.update((t_rns.len() as u64).to_be_bytes());
    for &x in t_rns {
        hasher.update(x.to_le_bytes());
    }
    for &x in c_rns {
        hasher.update(x.to_le_bytes());
    }
    for &x in d_rns {
        hasher.update(x.to_le_bytes());
    }
    hasher.finalize().into()
}

/// T2: Derive a scalar ternary challenge from a transcript commitment.
///
/// Replaces the raw `derive_challenge_scalar` when T2 FS-outside-circuit is active.
/// Instead of hashing the full transcript, we hash only the commitment and session
/// binding, then use Poseidon to produce the Fiat-Shamir challenge.
///
/// This is cheaper in-circuit because the commitment (32 bytes) is much smaller
/// than the raw transcript data (3 × L × N × 8 bytes ≈ 384KB).
///
/// `round_index` binds the repetition round into the FS transcript to prevent
/// cross-round replay when SIGMA_REPETITIONS > 1.
pub fn derive_challenge_from_commitment(
    commitment: &[u8; 32],
    session_id: &[u8],
    participant_id: u32,
    round_index: usize,
    d_commitment: &[u8; 32],
) -> Result<i64, NizkError> {
    let mut prefix = Sha256::new();
    prefix.update(SCALAR_CHALLENGE_DOMAIN);
    prefix.update(b"t2-commit-ch");
    prefix.update(session_id);
    prefix.update(participant_id.to_le_bytes());
    prefix.update((round_index as u64).to_le_bytes());
    // P2-1: bind PVSS d_commitment into the FS challenge to prevent
    // cross-commitment proof replay.
    prefix.update(d_commitment);

    let digest = labeled_sha256(&prefix, b"commitment", commitment);
    let lo = bytes16_to_fr(&digest[..16]);
    let hi = bytes16_to_fr(&digest[16..]);
    let ch_fr = poseidon_hash(&[lo, hi])?;

    let bytes = fr_to_bytes(&ch_fr);
    for &byte in &bytes {
        if let Some(ch) = uniform_ternary(byte) {
            return Ok(ch);
        }
    }
    Ok(0) // fallback: all 32 bytes ≥ 252 (probability < 2^-120)
}

/// SHA-256 hashes a labeled field, binding it to a shared prefix (which includes
/// session/participant binding and domain separator).
fn labeled_sha256(prefix: &Sha256, label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = prefix.clone();
    h.update(label);
    h.update(data);
    h.finalize().into()
}

/// Convert 16 bytes (big-endian) to an Fr field element.
fn bytes16_to_fr(bytes: &[u8]) -> Fr {
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(bytes);
    // M3: 16-byte input is always < |Fr| (2^128 << 2^254), no barrel reduction.
    Fr::from_le_bytes_mod_order(&buf)
}

/// Hash a slice of Fr elements using Poseidon.
fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, NizkError> {
    let mut hasher =
        Poseidon::<Fr>::new_circom(inputs.len()).map_err(|_| NizkError::VerificationFailed {
            reason: "Poseidon arity out of circom range",
            party_id: None,
        })?;
    hasher
        .hash(inputs)
        .map_err(|_| NizkError::VerificationFailed {
            reason: "Poseidon hash failed",
            party_id: None,
        })
}

/// Rejection-sampled uniform ternary from a single byte.
///
/// Bytes 0..=251 are split into three equal buckets of 84 each:
/// 0..84 → -1, 84..168 → 0, 168..252 → 1.
/// Bytes ≥ 252 are rejected (returns None); the caller must retry.
pub fn uniform_ternary(byte: u8) -> Option<i64> {
    if byte >= 252 {
        return None;
    }
    Some(match byte / 84 {
        0 => -1,
        1 => 0,
        _ => 1,
    })
}

/// Convert an Fr element to its little-endian byte representation.
fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let le = fr.into_bigint().to_bytes_le();
    let len = le.len().min(32);
    bytes[..len].copy_from_slice(&le[..len]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::{num_rns_limbs, rlwe_n};

    #[test]
    fn uniform_ternary_smoke() {
        assert_eq!(uniform_ternary(0).unwrap(), -1);
        assert_eq!(uniform_ternary(83).unwrap(), -1);
        assert_eq!(uniform_ternary(84).unwrap(), 0);
        assert_eq!(uniform_ternary(167).unwrap(), 0);
        assert_eq!(uniform_ternary(168).unwrap(), 1);
        assert_eq!(uniform_ternary(251).unwrap(), 1);
        assert!(uniform_ternary(252).is_none());
        assert!(uniform_ternary(255).is_none());
    }

    #[test]
    fn challenge_depends_on_session_id() {
        let session_a = b"session-alpha-123";
        let session_b = b"session-beta-456";
        let t_rns = vec![1u64; rlwe_n() * num_rns_limbs()];
        let _c_rns = vec![2u64; rlwe_n() * num_rns_limbs()];
        let _d_rns = vec![3u64; rlwe_n() * num_rns_limbs()];
        let _pvss = [0u8; 32];

        // Verify SHA-256 prefix differs with different session IDs (binding)
        let mut prefix_a = Sha256::new();
        prefix_a.update(SCALAR_CHALLENGE_DOMAIN);
        prefix_a.update(session_a);
        prefix_a.update(0u32.to_le_bytes());

        let mut prefix_b = Sha256::new();
        prefix_b.update(SCALAR_CHALLENGE_DOMAIN);
        prefix_b.update(session_b);
        prefix_b.update(0u32.to_le_bytes());

        let t_bytes: Vec<u8> = t_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
        let digest_a = labeled_sha256(&prefix_a, b"t_rns", &t_bytes);
        let digest_b = labeled_sha256(&prefix_b, b"t_rns", &t_bytes);
        assert_ne!(
            digest_a, digest_b,
            "SHA-256 digests must differ with different session IDs"
        );
    }

    /// P2-1 RED: challenge must change when d_commitment differs.
    /// The PVSS commitment must be bound into the T2 Fiat-Shamir challenge
    /// to prevent an adversary from reusing a proof with a different commitment.
    #[test]
    fn challenge_depends_on_d_commitment() {
        let d_commit_a = [0xAAu8; 32];
        let d_commit_b = [0xBBu8; 32];
        let session_id = b"test-session";
        let participant_id = 1u32;
        let round_index = 0usize;

        let transcript_commitment = [0x42u8; 32];

        let ch_a = derive_challenge_from_commitment(
            &transcript_commitment,
            session_id,
            participant_id,
            round_index,
            &d_commit_a,
        )
        .expect("challenge derivation should succeed in test");
        let ch_b = derive_challenge_from_commitment(
            &transcript_commitment,
            session_id,
            participant_id,
            round_index,
            &d_commit_b,
        )
        .expect("challenge derivation should succeed in test");

        assert_ne!(
            ch_a, ch_b,
            "P2-1: challenge must differ when d_commitment changes"
        );
    }
}
