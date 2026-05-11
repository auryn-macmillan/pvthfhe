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
            hex::encode(session_id),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separator_is_injective_for_byte_sequences() {
        // Two different byte sequences that collide under String::from_utf8_lossy
        // (both produce "\u{FFFD}") must produce different domain separators
        // when hex-encoded.
        let session_a: &[u8] = &[0xFE];
        let session_b: &[u8] = &[0xFF];

        // Verify they collide under lossy UTF-8 (pre-fix behavior)
        assert_eq!(
            String::from_utf8_lossy(session_a),
            String::from_utf8_lossy(session_b),
            "test vectors must collide under lossy UTF-8"
        );

        // With hex encoding, the transcripts must diverge
        let mut transcript_a = Transcript::new(session_a, 1);
        let mut transcript_b = Transcript::new(session_b, 1);

        transcript_a.absorb(b"label", b"data");
        transcript_b.absorb(b"label", b"data");

        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        transcript_a.challenge_bytes(b"ch", &mut out_a);
        transcript_b.challenge_bytes(b"ch", &mut out_b);

        assert_ne!(out_a, out_b, "hex-encoded domain separators must diverge");
    }
}
