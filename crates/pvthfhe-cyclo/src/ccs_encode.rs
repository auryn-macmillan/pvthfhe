//! CCS instance encoding for one P1 NIZK output.

use crate::{CcsPShareInstance, CycloError};

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
pub fn encode(_share: &CcsPShareInstance) -> Result<CcsInstance, CycloError> {
    Err(CycloError::InvalidInstance("not yet implemented"))
}

/// Checks the CCS satisfiability relation for `instance`.
///
/// Relation: `SHA256(ajtai_commitment_bytes ∥ public_io_bytes ∥ witness_bytes) == sha256_binding`.
pub fn check_satisfiability(_instance: &CcsInstance) -> Result<(), CycloError> {
    Err(CycloError::AccumulatorVerificationFailed(
        "not yet implemented",
    ))
}
