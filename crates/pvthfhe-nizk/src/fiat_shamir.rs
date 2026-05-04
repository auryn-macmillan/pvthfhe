//! Fiat-Shamir transcript with locked domain separator for PVTHFHE.
//!
//! # Determinism guarantee
//!
//! Given identical `session_id`, `participant_id`, and the same sequence of
//! [`Transcript::absorb`] calls (same labels and data in the same order),
//! [`Transcript::challenge_bytes`] always returns the same bytes regardless of
//! platform, time, or execution environment.  No external randomness is
//! consumed; all state is derived deterministically from the SHA-256 hash of
//! the absorbed data.
//!
//! # Wire format
//!
//! Each [`Transcript::absorb`] call appends to the running hash state:
//! ```text
//! u64_be(label.len()) ‖ label ‖ u64_be(data.len()) ‖ data
//! ```
//!
//! [`Transcript::challenge_bytes`] finalises the state and, for outputs
//! longer than 32 bytes, extends by hashing `u64_be(counter) ‖ state_hash`
//! for counter = 0, 1, 2, …

use sha2::{Digest, Sha256};

/// Domain separator prefix as specified in §3.6 of `design/spec-real-p2p3.md`.
pub const DOMAIN_SEP_PREFIX: &str = "pvthfhe/cyclo-ajtai-d2/v1/";

/// Fiat-Shamir transcript built on SHA-256.
///
/// Initialise with [`Transcript::new`] (which binds the session and participant
/// identity via a locked domain separator), then call [`Transcript::absorb`]
/// for each prover message, and finally call [`Transcript::challenge_bytes`]
/// to obtain verifier challenges.
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    /// Creates a new transcript locked to the given session and participant.
    ///
    /// The domain separator fed into the hash is (ASCII, no null terminator):
    /// ```text
    /// "pvthfhe/cyclo-ajtai-d2/v1/" ‖ session_id ‖ "/" ‖ participant_id_decimal
    /// ```
    pub fn new(session_id: &[u8], participant_id: u32) -> Self {
        let mut hasher = Sha256::new();
        let domain = format!(
            "{}{}/{}",
            DOMAIN_SEP_PREFIX,
            String::from_utf8_lossy(session_id),
            participant_id
        );
        hasher.update(domain.as_bytes());
        Self { hasher }
    }

    /// Absorbs a labeled piece of data into the transcript.
    ///
    /// Wire format: `u64_be(label.len()) ‖ label ‖ u64_be(data.len()) ‖ data`.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
        self.hasher.update(
            u64::try_from(label.len())
                .map_or(u64::MAX, |v| v)
                .to_be_bytes(),
        );
        self.hasher.update(label);
        self.hasher.update(
            u64::try_from(data.len())
                .map_or(u64::MAX, |v| v)
                .to_be_bytes(),
        );
        self.hasher.update(data);
    }

    /// Squeezes `out.len()` challenge bytes from the transcript.
    ///
    /// For outputs ≤ 32 bytes the hash is finalised directly.  For longer
    /// outputs, counter-mode extension is used:
    /// `SHA256(u64_be(i) ‖ state_hash)` for `i = 0, 1, 2, …`
    ///
    /// This call finalises the transcript; subsequent [`absorb`](Self::absorb)
    /// or [`challenge_bytes`](Self::challenge_bytes) calls reflect the
    /// finalised state.
    pub fn challenge_bytes(&mut self, label: &[u8], out: &mut [u8]) {
        self.hasher.update(
            u64::try_from(label.len())
                .map_or(u64::MAX, |v| v)
                .to_be_bytes(),
        );
        self.hasher.update(label);
        let state: [u8; 32] = self.hasher.clone().finalize().into();
        let mut written = 0usize;
        let mut counter: u64 = 0;
        while written < out.len() {
            let mut h = Sha256::new();
            h.update(counter.to_be_bytes());
            h.update(state);
            let block: [u8; 32] = h.finalize().into();
            let take = (out.len() - written).min(32);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter += 1;
        }
    }
}
