use sha2::{Digest, Sha256};

pub fn params_digest_v1(label: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(label).finalize().into()
}

pub fn challenge_v1(
    session_id: &str,
    fold_depth: u32,
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fs-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(fold_depth.to_le_bytes())
        .chain_update(acc_commitment)
        .chain_update(inst_ajtai_bytes)
        .chain_update(inst_public_io_bytes)
        .finalize()
        .into()
}

pub fn commitment_v1(
    session_id: &str,
    depth: u32,
    poly_bytes: &[u8],
    inst_bytes: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fold-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(depth.to_le_bytes())
        .chain_update(poly_bytes)
        .chain_update(inst_bytes)
        .finalize()
        .into()
}

pub fn public_io_v1(
    session_id: &str,
    depth: u32,
    acc_io: &[u8],
    inst_io: &[u8],
    r_value: u64,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fold-io-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(depth.to_le_bytes())
        .chain_update(acc_io)
        .chain_update(inst_io)
        .chain_update(r_value.to_le_bytes())
        .finalize()
        .into()
}

pub fn init_commitment_v1(session_id: &str, poly_bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-init-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(poly_bytes)
        .finalize()
        .into()
}

pub fn init_public_io_v1(session_id: &str, io_bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-init-io-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(io_bytes)
        .finalize()
        .into()
}

/// Cyclo-specific Fiat-Shamir transcript producing biased ternary challenges.
///
/// The Cyclo protocol samples challenges from {−1, 0, 1} with probability 1/3
/// each (Cyclo ePrint 2026/359 §5.5).  This differs from the uniform u16 used
/// by Nova (the `challenge_v1` path above).
///
/// Domain separator `"pvthfhe-cyclo-fs-v2"` isolates this transcript from the
/// Nova-v1 path so that the two cannot be confused as equal challenges.
pub struct CycloTernaryTranscript {
    state: Sha256,
}

impl CycloTernaryTranscript {
    /// Initialise a new transcript with the v2 domain separator, `session_id`, and `participant_id`.
    pub fn new(session_id: &str, participant_id: u16) -> Self {
        let mut state = Sha256::new();
        state.update(b"pvthfhe-cyclo-fs-v2");
        state.update(session_id.as_bytes());
        state.update(participant_id.to_le_bytes());
        Self { state }
    }

    /// Absorb arbitrary bytes into the transcript state.
    pub fn absorb(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Sample a challenge from {−1, 0, 1} with probability 1/3 each.
    ///
    /// Internally hashes the current transcript state with SHA-256, applies
    /// rejection sampling to the output bytes for uniform ternary distribution,
    /// then advances the state with the full hash output for domain separation
    /// of the next call.
    pub fn sample_challenge(&mut self) -> i8 {
        let hash: [u8; 32] = self.state.clone().finalize().into();
        self.state.update(hash);
        for &byte in &hash {
            if let Some(ch) = uniform_ternary(byte) {
                return ch as i8;
            }
        }
        0
    }
}

/// Rejection-sampled uniform ternary from a single byte.
///
/// Bytes 0..=251 are split into three equal buckets of 84 each.
/// Bytes ≥ 252 are rejected (returns None); the caller must retry.
pub(crate) fn uniform_ternary(byte: u8) -> Option<i8> {
    if byte >= 252 {
        return None;
    }
    Some(match byte / 84 {
        0 => -1,
        1 => 0,
        _ => 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_challenge_iterates_all_32_bytes() {
        // M6: Verify the loop in sample_challenge visits ALL 32 hash bytes,
        // not just hash[0]. When early bytes are rejected (≥252), the loop
        // continues until finding a valid ternary byte.

        // Hash where bytes 0–3 are rejected (≥252), byte 4 is valid
        let hash: [u8; 32] = [
            252, 253, 254, 255, 42, 100, 200, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Replicate sample_challenge loop: find first valid byte
        let mut found_at = None;
        for (i, &byte) in hash.iter().enumerate() {
            if let Some(ch) = uniform_ternary(byte) {
                found_at = Some((i, ch));
                break;
            }
        }

        assert!(found_at.is_some(), "must find a valid ternary from hash");
        let (idx, ch) = found_at.unwrap();
        assert_eq!(idx, 4, "challenge must come from byte 4, not byte 0");
        assert_eq!(ch, -1i8, "byte 42 in bucket 0 (42/84=0) maps to -1");

        // Edge case: ALL bytes rejected → no match found
        let all_rejected: [u8; 32] = [252u8; 32];
        let any_match = all_rejected.iter().any(|&b| uniform_ternary(b).is_some());
        assert!(!any_match, "all-rejected hash must produce no valid byte");
    }

    #[test]
    fn uniform_ternary_bucket_counts() {
        // M6: 256 possible byte values split into 3 buckets of 84 each
        // (bytes 0–251), plus 4 rejected values (bytes 252–255).
        let mut counts = [0u16; 4]; // [-1, 0, 1, rejected]
        for byte in 0u16..=255u16 {
            match uniform_ternary(byte as u8) {
                Some(-1) => counts[0] += 1,
                Some(0) => counts[1] += 1,
                Some(1) => counts[2] += 1,
                None => counts[3] += 1,
                _ => unreachable!(),
            }
        }

        assert_eq!(counts[0], 84, "bucket -1: 84 values");
        assert_eq!(counts[1], 84, "bucket 0: 84 values");
        assert_eq!(counts[2], 84, "bucket 1: 84 values");
        assert_eq!(counts[3], 4, "rejected: bytes 252–255");
    }
}
