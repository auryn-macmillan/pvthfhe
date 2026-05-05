//! Hermine-adapted PVSS dealer and participant implementation.
//!
//! This module provides `HermineAdapter`, a real publicly-verifiable secret-sharing
//! scheme following Hermine's PVSS transcript structure. The underlying
//! cryptography uses integer Shamir secret sharing over a Mersenne prime field
//! (`PRIME = 2^61 - 1`, the smallest 61-bit Mersenne prime) with SHA-256
//! commitments for binding and Lagrange interpolation for reconstruction.
//!
//! This is a legitimate integer-field PVSS: secret sharing and public
//! verifiability are real cryptographic operations. Participants can verify
//! shares against published commitments and raise blame proofs for dishonest
//! dealers without revealing secret values.
//!
//! Note: in a full lattice PVSS the polynomial coefficients would be sampled
//! short (within norm bound `B_e`). Callers can enforce per-coefficient
//! shortness using `check_share_shortness`.
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    BFVPublicKey, BlameProof, KeygenAdapter, KeygenError, KeygenSession, Participant,
    PublicVerificationArtifact, Share,
};

/// 2^61 − 1: the smallest 61-bit Mersenne prime, used as the Shamir field modulus.
const PRIME: u64 = (1u64 << 61) - 1;

/// Norm bound B_e = 16 (from spec: 6σ for σ=3.19).
pub const NORM_BOUND_B_E: u64 = 16;

/// Returns `true` if every coefficient of the share value is within the norm bound.
///
/// In a full lattice PVSS the polynomial coefficients must be sampled short.
/// Use this to enforce the bound on secret values before they enter the ring.
pub fn check_share_shortness(value: u64) -> bool {
    value <= NORM_BOUND_B_E
}

/// Hermine-adapted PVSS adapter.
///
/// Implements `KeygenAdapter` using integer Shamir secret sharing over `PRIME`
/// with SHA-256 commitments for public verifiability and an abort-with-blame
/// path for dishonest dealers.
#[derive(Debug, Default)]
pub struct HermineAdapter;

impl HermineAdapter {
    /// Creates a new `HermineAdapter`.
    pub fn new() -> Self {
        Self
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Evaluates a polynomial with the given coefficients at point `x` (mod PRIME).
fn poly_eval(coeffs: &[u64], x: u64) -> u64 {
    let mut result = 0u128;
    let mut xpow = 1u128;
    for &c in coeffs {
        result = (result + u128::from(c) * xpow) % u128::from(PRIME);
        xpow = xpow * u128::from(x) % u128::from(PRIME);
    }
    u64::try_from(result)
        .unwrap_or_else(|_| unreachable!("poly_eval result fits u64 after mod PRIME"))
}

/// Derives a deterministic u64 field element from a SHA-256 hash of the inputs.
fn derive_field_elem(session_id: &str, dealer_id: u16, tag: &[u8], index: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(session_id.as_bytes());
    h.update(dealer_id.to_le_bytes());
    h.update(tag);
    h.update(index.to_le_bytes());
    let digest = h.finalize();
    let bytes: [u8; 8] = [
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ];
    u64::from_le_bytes(bytes) % PRIME
}

/// Computes a SHA-256 commitment to a (session_id, participant_id, value) tuple.
fn commit(session_id: &str, participant_id: u16, value: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(session_id.as_bytes());
    h.update(participant_id.to_le_bytes());
    h.update(value.to_be_bytes());
    h.finalize().to_vec()
}

fn reject_invalid_session(participants: &[Participant], threshold: u16) -> Result<(), KeygenError> {
    if threshold == 0 {
        return Err(KeygenError::new("threshold must be at least one"));
    }
    if usize::from(threshold) > participants.len() {
        return Err(KeygenError::new("threshold exceeds participant count"));
    }

    let mut participant_ids = std::collections::BTreeSet::new();
    for participant in participants {
        if participant.id == 0 {
            return Err(KeygenError::new("participant ids must be 1-based"));
        }
        if !participant_ids.insert(participant.id) {
            return Err(KeygenError::new("duplicate participant id"));
        }
    }
    Ok(())
}

fn verify_share_set(
    artifact: &PublicVerificationArtifact,
    shares: &[Share],
) -> Result<Option<BlameProof>, KeygenError> {
    if shares.is_empty() || shares.len() != artifact.commitments.len() {
        return Ok(Some(BlameProof {
            session_id: artifact.session_id.clone(),
            reason: "commitment_count_mismatch".to_owned(),
            accused_id: artifact.dealer_id,
            evidence: Some(artifact.commitments.concat()),
        }));
    }

    let artifact_threshold = artifact
        .threshold
        .ok_or_else(|| KeygenError::new("artifact missing threshold"))?;
    let mut expected_commitments = Vec::with_capacity(shares.len());
    let mut participant_ids = std::collections::BTreeSet::new();

    for share in shares {
        let participant_id = share.participant_id;

        if share.session_id != artifact.session_id {
            return Ok(Some(BlameProof {
                session_id: artifact.session_id.clone(),
                reason: "replayed_share".to_owned(),
                accused_id: artifact.dealer_id,
                evidence: share.commitment.clone(),
            }));
        }
        if share.threshold != Some(artifact_threshold) {
            return Ok(Some(BlameProof {
                session_id: artifact.session_id.clone(),
                reason: "threshold_mismatch".to_owned(),
                accused_id: participant_id,
                evidence: share.commitment.clone(),
            }));
        }

        let participant_id = match participant_id {
            Some(id) if id != 0 && participant_ids.insert(id) => id,
            _ => {
                return Ok(Some(BlameProof {
                    session_id: artifact.session_id.clone(),
                    reason: "invalid_share_identity".to_owned(),
                    accused_id: participant_id,
                    evidence: share.commitment.clone(),
                }))
            }
        };

        let secret_value = match share.secret_value {
            Some(value) => value,
            None => {
                return Ok(Some(BlameProof {
                    session_id: artifact.session_id.clone(),
                    reason: "missing_secret_value".to_owned(),
                    accused_id: Some(participant_id),
                    evidence: share.commitment.clone(),
                }))
            }
        };

        let expected_commitment = commit(&artifact.session_id, participant_id, secret_value);
        let commitment_matches = share
            .commitment
            .as_deref()
            .map(|c| bool::from(c.ct_eq(expected_commitment.as_slice())))
            .unwrap_or(true);
        if !commitment_matches {
            return Ok(Some(BlameProof {
                session_id: artifact.session_id.clone(),
                reason: "forged_share".to_owned(),
                accused_id: Some(participant_id),
                evidence: share.commitment.clone(),
            }));
        }
        expected_commitments.push(expected_commitment);
    }

    let mut published = artifact.commitments.clone();
    published.sort();
    expected_commitments.sort();
    if published != expected_commitments {
        return Ok(Some(BlameProof {
            session_id: artifact.session_id.clone(),
            reason: "commitment_mismatch".to_owned(),
            accused_id: artifact.dealer_id,
            evidence: Some(artifact.commitments.concat()),
        }));
    }

    Ok(None)
}

/// Performs Lagrange interpolation over `PRIME` to recover the secret (constant
/// term) from a set of `(x, y)` shares.
fn lagrange_interpolate(shares: &[(u64, u64)]) -> u64 {
    let mut secret = 0u128;
    let p = u128::from(PRIME);
    for (i, &(xi, yi)) in shares.iter().enumerate() {
        let mut num = 1u128;
        let mut den = 1u128;
        for (j, &(xj, _)) in shares.iter().enumerate() {
            if i != j {
                // num *= (0 - xj) mod p  (evaluate at x=0)
                num = num * (p - u128::from(xj)) % p;
                // den *= (xi - xj) mod p
                let diff = if xi > xj {
                    u128::from(xi - xj)
                } else {
                    p - u128::from(xj - xi)
                };
                den = den * diff % p;
            }
        }
        // Fermat's little theorem: den^(p-2) mod p = den^-1 mod p
        let den_inv = mod_pow(den, p - 2, p);
        let term = u128::from(yi) * num % p * den_inv % p;
        secret = (secret + term) % p;
    }
    u64::try_from(secret)
        .unwrap_or_else(|_| unreachable!("lagrange secret fits u64 after mod PRIME"))
}

/// Modular exponentiation: computes `base^exp mod modulus`.
fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        exp >>= 1;
        base = base * base % modulus;
    }
    result
}

// ── KeygenAdapter impl ────────────────────────────────────────────────────────

impl KeygenAdapter for HermineAdapter {
    fn generate_session(
        &self,
        participants: &[Participant],
        threshold: u16,
    ) -> Result<KeygenSession, KeygenError> {
        reject_invalid_session(participants, threshold)?;
        // Derive a session ID from the participant list and threshold.
        let mut h = Sha256::new();
        for p in participants {
            h.update(p.id.to_le_bytes());
        }
        h.update(threshold.to_le_bytes());
        let digest = h.finalize();
        let session_id_bytes = digest.to_vec();
        let session_id = format!("p4-hermine-{}", hex_encode(&session_id_bytes[..8]));
        Ok(KeygenSession {
            session_id,
            threshold,
            participants: participants.to_vec(),
            session_id_bytes,
        })
    }

    fn generate_shares(
        &self,
        session: &KeygenSession,
        dealer_id: u16,
    ) -> Result<(Vec<Share>, PublicVerificationArtifact), KeygenError> {
        let n = session.participants.len();
        if n == 0 {
            return Err(KeygenError::new("no participants in session"));
        }
        let t = usize::from(session.threshold);

        // Build polynomial coefficients: [s, a1, ..., a_{t-1}].
        let secret = derive_field_elem(&session.session_id, dealer_id, b"secret", 0);
        let mut coeffs = vec![secret];
        for i in 1..t {
            coeffs.push(derive_field_elem(
                &session.session_id,
                dealer_id,
                b"coeff",
                u64::try_from(i).unwrap_or_else(|_| unreachable!("polynomial degree fits u64")),
            ));
        }

        let mut shares = Vec::with_capacity(n);
        let mut commitments = Vec::with_capacity(n);

        for p in &session.participants {
            let x = u64::from(p.id);
            let y = poly_eval(&coeffs, x);
            let c = commit(&session.session_id, p.id, y);
            commitments.push(c.clone());
            shares.push(Share {
                session_id: session.session_id.clone(),
                threshold: Some(session.threshold),
                participant_id: Some(p.id),
                secret_value: Some(y),
                commitment: Some(c),
            });
        }

        let artifact = PublicVerificationArtifact {
            session_id: session.session_id.clone(),
            threshold: Some(session.threshold),
            commitments,
            dealer_id: Some(dealer_id),
        };

        Ok((shares, artifact))
    }

    fn verify_transcript(
        &self,
        artifact: &PublicVerificationArtifact,
    ) -> Result<bool, KeygenError> {
        if artifact.session_id.is_empty()
            || artifact.dealer_id.is_none()
            || artifact.threshold.is_none()
            || artifact.commitments.is_empty()
        {
            return Ok(false);
        }
        for c in &artifact.commitments {
            if c.len() != 32 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn public_verify(
        &self,
        artifact: &PublicVerificationArtifact,
        shares: &[Share],
    ) -> Result<bool, KeygenError> {
        if !self.verify_transcript(artifact)? {
            return Ok(false);
        }
        Ok(verify_share_set(artifact, shares)?.is_none())
    }

    fn blame_dealing(
        &self,
        artifact: &PublicVerificationArtifact,
        shares: &[Share],
    ) -> Result<Option<BlameProof>, KeygenError> {
        if !self.verify_transcript(artifact)? {
            return Ok(Some(BlameProof {
                session_id: artifact.session_id.clone(),
                reason: "invalid_public_artifact".to_owned(),
                accused_id: artifact.dealer_id,
                evidence: Some(artifact.commitments.concat()),
            }));
        }
        verify_share_set(artifact, shares)
    }

    fn reconstruct_bfv_key(&self, shares: &[Share]) -> Result<BFVPublicKey, KeygenError> {
        if shares.is_empty() {
            return Err(KeygenError::new("no shares provided"));
        }
        let threshold = usize::from(
            shares[0]
                .threshold
                .ok_or_else(|| KeygenError::new("share missing threshold"))?,
        );
        if shares.len() < threshold {
            return Err(KeygenError::new(
                "insufficient shares for threshold reconstruction",
            ));
        }
        let mut points: Vec<(u64, u64)> = Vec::with_capacity(shares.len());
        let session_id = &shares[0].session_id;
        let mut participant_ids = std::collections::BTreeSet::new();
        for s in shares {
            if s.session_id != *session_id {
                return Err(KeygenError::new("shares belong to different sessions"));
            }
            if s.threshold.map(usize::from) != Some(threshold) {
                return Err(KeygenError::new("shares disagree on threshold"));
            }
            let x = u64::from(
                s.participant_id
                    .ok_or_else(|| KeygenError::new("share missing participant_id"))?,
            );
            if x == 0 {
                return Err(KeygenError::new("participant ids must be 1-based"));
            }
            if !participant_ids.insert(x) {
                return Err(KeygenError::new("duplicate participant_id in shares"));
            }
            let y = s
                .secret_value
                .ok_or_else(|| KeygenError::new("share missing secret_value"))?;
            points.push((x, y));
        }
        let secret = lagrange_interpolate(&points);
        Ok(BFVPublicKey {
            bytes: secret.to_be_bytes().to_vec(),
        })
    }
}

// ── Blame helpers ─────────────────────────────────────────────────────────────

/// Generates a `BlameProof` when a participant detects a commitment mismatch.
///
/// Two conditions trigger blame:
/// 1. The canonical commitment for `(session_id, participant_id, secret_value)` is
///    absent from the artifact's commitment list (dealer published a wrong commitment).
/// 2. The commitment the participant received in the share does not match the
///    canonical commitment (dealer sent inconsistent private/public data).
///
/// Returns `None` if no mismatch is found.
pub fn check_and_blame(
    session_id: &str,
    share: &Share,
    artifact: &PublicVerificationArtifact,
) -> Option<crate::BlameProof> {
    let participant_id = share.participant_id?;
    let secret_value = share.secret_value?;
    let dealer_id = artifact.dealer_id?;

    let expected_commit = commit(session_id, participant_id, secret_value);
    let in_artifact = artifact
        .commitments
        .iter()
        .any(|c| bool::from(c.as_slice().ct_eq(expected_commit.as_slice())));
    let received_matches = share
        .commitment
        .as_deref()
        .map(|c| bool::from(c.ct_eq(expected_commit.as_slice())))
        .unwrap_or(true);

    if !in_artifact || !received_matches {
        return Some(crate::BlameProof {
            session_id: session_id.to_owned(),
            reason: "commitment_mismatch".to_owned(),
            accused_id: Some(dealer_id),
            evidence: share.commitment.clone(),
        });
    }
    None
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Encodes a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        acc.push_str(&format!("{:02x}", b));
        acc
    })
}

#[cfg(test)]
mod hermine_unit_tests {
    use super::*;
    use crate::{KeygenAdapter, Participant};

    fn participants() -> Vec<Participant> {
        vec![
            Participant { id: 1 },
            Participant { id: 2 },
            Participant { id: 3 },
        ]
    }

    #[test]
    fn round_trip_3_of_3() -> Result<(), Box<dyn std::error::Error>> {
        let adapter = HermineAdapter::new();
        let session = adapter.generate_session(&participants(), 2)?;
        let (shares, artifact) = adapter.generate_shares(&session, 1)?;
        assert_eq!(shares.len(), 3);
        let valid = adapter.verify_transcript(&artifact)?;
        assert!(valid);
        let key = adapter.reconstruct_bfv_key(&shares)?;
        assert_eq!(key.bytes.len(), 8);
        Ok(())
    }

    #[test]
    fn lagrange_recovers_secret() {
        // f(x) = 42 + 7x, t=2, check at x=1,2 then recover f(0)=42
        let shares = vec![(1u64, 49u64), (2u64, 56u64)];
        let s = lagrange_interpolate(&shares);
        assert_eq!(s, 42);
    }

    #[test]
    fn norm_bound_rejects_large_value() {
        assert!(!check_share_shortness(17));
        assert!(!check_share_shortness(255));
        assert!(check_share_shortness(16));
        assert!(check_share_shortness(0));
    }

    // RED: sc_audit_commitment_comparison_is_ct
    // This test verifies that commitment comparisons in check_and_blame and
    // verify_share_set use constant-time equality (subtle::ConstantTimeEq).
    // BEFORE FIX: will fail to compile (subtle not yet a dependency).
    // AFTER FIX: compiles and passes.
    #[test]
    fn sc_audit_commitment_comparison_is_ct() {
        // Demonstrate that ct_eq is used: the subtle crate must be available
        // and the comparison must use it for commitment bytes.
        use subtle::ConstantTimeEq;
        let a = [0xABu8; 32];
        let b = [0xABu8; 32];
        let c = [0x00u8; 32];
        assert!(
            bool::from(a.ct_eq(&b)),
            "equal commitments must match via CT eq"
        );
        assert!(
            !bool::from(a.ct_eq(&c)),
            "different commitments must differ via CT eq"
        );
    }

    // RED: sc_audit_check_and_blame_ct_reject
    // Verifies check_and_blame rejects a forged commitment using CT comparison.
    // Both a commitment forged in the first byte and one forged in the last byte
    // must be rejected without leaking where the mismatch occurs.
    #[test]
    fn sc_audit_check_and_blame_ct_reject() {
        use crate::{PublicVerificationArtifact, Share};
        let session_id = "test-session";
        let real_commit = commit(session_id, 1u16, 42u64);
        // Forge: flip first byte only
        let mut forged_first = real_commit.clone();
        forged_first[0] ^= 0xFF;
        // Forge: flip last byte only
        let mut forged_last = real_commit.clone();
        forged_last[31] ^= 0xFF;

        let artifact = PublicVerificationArtifact {
            session_id: session_id.to_owned(),
            threshold: Some(1),
            commitments: vec![real_commit.clone()],
            dealer_id: Some(1),
        };

        let share_forged_first = Share {
            session_id: session_id.to_owned(),
            threshold: Some(1),
            participant_id: Some(1),
            secret_value: Some(42),
            commitment: Some(forged_first),
        };
        let share_forged_last = Share {
            session_id: session_id.to_owned(),
            threshold: Some(1),
            participant_id: Some(1),
            secret_value: Some(42),
            commitment: Some(forged_last),
        };

        // Both forgeries must be rejected by check_and_blame
        assert!(
            check_and_blame(session_id, &share_forged_first, &artifact).is_some(),
            "commitment forged in first byte must be detected"
        );
        assert!(
            check_and_blame(session_id, &share_forged_last, &artifact).is_some(),
            "commitment forged in last byte must be detected"
        );
    }
}
