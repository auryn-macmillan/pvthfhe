//! CCS instance encoding for one P1 NIZK output.

use crate::{CcsPShareInstance, CycloError};
use sha2::{Digest, Sha256};

/// Encoded CCS instance for a single participant share.
pub struct CcsInstance {
    /// Participant identifier (1-based).
    pub participant_id: u16,
    /// 32-byte hash of the Ajtai commitment (SHA-256).
    pub ajtai_hash: [u8; 32],
    /// 32-byte hash of the public I/O (SHA-256).
    pub public_io_hash: [u8; 32],
    /// 32-byte binding tag (from `CcsPShareInstance::sha256_binding_bytes`).
    pub sha256_binding: [u8; 32],
    /// The raw witness bytes (copied from `CcsPShareInstance::ccs_witness_bytes`).
    pub witness_bytes: Vec<u8>,
}

/// Encodes a `CcsPShareInstance` into a `CcsInstance`.
///
/// Deterministic: the same input always produces the same output.
pub fn encode(share: &CcsPShareInstance) -> Result<CcsInstance, CycloError> {
    let binding_slice = share.sha256_binding_bytes.as_slice();
    if binding_slice.len() != 32 {
        return Err(CycloError::InvalidInstance(
            "sha256_binding_bytes must be exactly 32 bytes",
        ));
    }
    let mut sha256_binding = [0u8; 32];
    sha256_binding.copy_from_slice(binding_slice);

    let ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(&share.ajtai_commitment_bytes)
        .finalize()
        .into();

    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(&share.public_io_bytes)
        .finalize()
        .into();

    Ok(CcsInstance {
        participant_id: share.participant_id,
        ajtai_hash,
        public_io_hash,
        sha256_binding,
        witness_bytes: share.ccs_witness_bytes.clone(),
    })
}

/// Checks the CCS satisfiability relation for `instance`.
///
/// Relation: `SHA256(ajtai_hash ∥ public_io_hash ∥ witness_bytes) == sha256_binding`.
pub fn check_satisfiability(instance: &CcsInstance) -> Result<(), CycloError> {
    let computed: [u8; 32] = Sha256::new()
        .chain_update(instance.ajtai_hash)
        .chain_update(instance.public_io_hash)
        .chain_update(&instance.witness_bytes)
        .finalize()
        .into();

    if computed != instance.sha256_binding {
        return Err(CycloError::AccumulatorVerificationFailed(
            "sha256 binding mismatch",
        ));
    }
    Ok(())
}
