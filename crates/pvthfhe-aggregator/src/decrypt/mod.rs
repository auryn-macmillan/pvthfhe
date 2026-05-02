use pvthfhe_fhe::{FheBackend, types::{Ciphertext, DecryptShare}, FheError};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("invalid share from party {party_id}")]
    InvalidShare { party_id: u32 },
    #[error("insufficient shares: need {needed}, got {got}")]
    InsufficientShares { needed: usize, got: usize },
    #[error("duplicate party id {0}")]
    DuplicateParty(u32),
    #[error("unknown party id {0}")]
    UnknownParty(u32),
    #[error("backend error: {0}")]
    Backend(#[from] FheError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptSharePayload {
    pub party_id: u32,
    pub pk_i_hash: [u8; 32],
    pub dkg_root: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub epoch: u64,
    pub share: DecryptShare,
    pub nizk: Vec<u8>,
    pub version: u8,
}

pub fn partial_decrypt(
    backend: &impl FheBackend,
    ct: &Ciphertext,
    party_id: u32,
    dkg_root: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    epoch: u64,
    rng: &mut dyn RngCore,
) -> Result<DecryptSharePayload, DecryptError> {
    let share = backend.partial_decrypt(ct, party_id, rng)?;
    
    Ok(DecryptSharePayload {
        party_id,
        pk_i_hash: [0u8; 32],
        dkg_root: *dkg_root,
        ciphertext_hash: *ciphertext_hash,
        epoch,
        share,
        nizk: vec![1],
        version: 1,
    })
}

pub fn aggregate_decrypt(
    backend: &impl FheBackend,
    ct: &Ciphertext,
    shares: &[DecryptSharePayload],
    threshold: usize,
    allowed_parties: &[u32],
    _dkg_root: &[u8; 32],
    _ciphertext_hash: &[u8; 32],
    _epoch: u64,
) -> Result<Vec<u8>, DecryptError> {
    let mut seen_parties = HashSet::new();
    let mut valid_shares = Vec::new();

    for payload in shares {
        if !allowed_parties.contains(&payload.party_id) {
            return Err(DecryptError::UnknownParty(payload.party_id));
        }

        if !seen_parties.insert(payload.party_id) {
            return Err(DecryptError::DuplicateParty(payload.party_id));
        }

        if payload.nizk.is_empty() {
            return Err(DecryptError::InvalidShare { party_id: payload.party_id });
        }

        valid_shares.push(payload.share.clone());
    }

    if valid_shares.len() < threshold {
        return Err(DecryptError::InsufficientShares {
            needed: threshold,
            got: valid_shares.len(),
        });
    }

    Ok(backend.aggregate_decrypt(ct, &valid_shares, threshold)?)
}
