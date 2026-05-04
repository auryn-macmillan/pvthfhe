//! D2 hash-bridge: binds the P4 SHA-256 commitment to NIZK statements.
//!
//! # Security
//! ⚠️ The D2 variant binds C_i = SHA256(session_id || i_le || s_i_be) as a
//! separate hash assertion outside the algebraic Cyclo proof. See SECURITY.md §P1.

use sha2::{Digest, Sha256};

/// Compute the P4 commitment C_i for a participant.
///
/// Byte layout: session_id UTF-8 bytes || participant_id as 2 LE bytes || secret_share as 8 BE bytes.
///
/// This matches the layout confirmed in `pvthfhe-fhe/src/real_nizk.rs`
/// (`commitment_hash`), which is the ground-truth implementation.
/// The spec §3.1 description `SHA256(session_id_bytes || i_le || s_i_be)` is
/// consistent with the codebase — **no deviation detected**.
pub fn commit(session_id: &str, participant_id: u16, secret_share: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(participant_id.to_le_bytes());
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
