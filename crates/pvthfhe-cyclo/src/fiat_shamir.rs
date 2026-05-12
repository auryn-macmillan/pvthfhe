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
/// by Sonobe (the `challenge_v1` path above).
///
/// Domain separator `"pvthfhe-cyclo-fs-v2"` isolates this transcript from the
/// Sonobe-v1 path so that the two cannot be confused as equal challenges.
pub struct CycloTernaryTranscript {
    state: Sha256,
}

impl CycloTernaryTranscript {
    /// Initialise a new transcript with the v2 domain separator and `session_id`.
    pub fn new(session_id: &str) -> Self {
        let mut state = Sha256::new();
        state.update(b"pvthfhe-cyclo-fs-v2");
        state.update(session_id.as_bytes());
        Self { state }
    }

    /// Absorb arbitrary bytes into the transcript state.
    pub fn absorb(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Sample a challenge from {−1, 0, 1} with probability 1/3 each.
    ///
    /// Internally hashes the current transcript state with SHA-256, maps the
    /// first output byte mod 3 onto the set {−1, 0, 1}, then advances the
    /// state with the full hash output for domain separation of the next call.
    pub fn sample_challenge(&mut self) -> i8 {
        let hash: [u8; 32] = self.state.clone().finalize().into();
        self.state.update(hash);
        match hash[0] % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        }
    }
}
