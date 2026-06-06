//! D2 hash-bridge: binds the P4 SHA-256 commitment to NIZK statements.
//!
//! # Security
//! ⚠️ The D2 variant binds C_i = SHA256(domain || session_id_len_be || session_id || i_be || s_i_be)
//! as a separate hash assertion outside the algebraic Cyclo proof. See SECURITY.md §P1.
//!
//! H2 fix: consistent big-endian encoding with domain separation and
//! length-prefixed session_id to prevent endianness-injection attacks.

use sha2::{Digest, Sha256};

/// Domain separator for the D2 hash-bridge commitment.
const D2_DOMAIN: &[u8] = b"pvthfhe-d2-hash-bridge/v1";

/// Compute the P4 commitment C_i for a participant.
///
/// Byte layout:
///   domain (28 B) || session_id_len as u32 BE (4 B) || session_id UTF-8
///   || participant_id as u16 BE (2 B) || secret_share as u64 BE (8 B).
pub fn commit(session_id: &str, participant_id: u16, secret_share: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(D2_DOMAIN);
    hasher.update(&(session_id.len() as u32).to_be_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(participant_id.to_be_bytes());
    hasher.update(secret_share.to_be_bytes());
    hasher.finalize().into()
}

/// Verify a claimed commitment matches the D2-recomputed hash.
///
/// Returns `true` if and only if `commitment` equals
/// `commit(session_id, participant_id, secret_share)`.
pub fn verify(
    commitment: &[u8; 32],
    session_id: &str,
    participant_id: u16,
    secret_share: u64,
) -> bool {
    let expected = commit(session_id, participant_id, secret_share);
    *commitment == expected
}
