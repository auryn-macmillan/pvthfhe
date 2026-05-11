//! CCS instance encoding for one P1 NIZK output.

use crate::{CcsPShareInstance, CycloError};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
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
    /// Serialized CCS constraint matrix: [rows:u32 BE][cols:u32 BE][data: rows*cols Fr LE].
    /// Empty for instances created via the legacy SHA path.
    pub ccs_matrix: Vec<u8>,
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
        .chain_update(share.ajtai_commitment_bytes.as_slice())
        .finalize()
        .into();

    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(share.public_io_bytes.as_slice())
        .finalize()
        .into();

    Ok(CcsInstance {
        participant_id: share.participant_id,
        ajtai_hash,
        public_io_hash,
        sha256_binding,
        witness_bytes: share.ccs_witness_bytes.to_wire_bytes(),
        ccs_matrix: share.ccs_matrix_bytes.0.clone(),
    })
}

const FR_SERIALIZED_LEN: usize = 32;
const U32_LEN: usize = 4;

/// Parse a serialized CCS matrix into `(num_rows, num_cols, flat data)`.
fn parse_matrix(bytes: &[u8]) -> Result<(u32, u32, Vec<Fr>), CycloError> {
    if bytes.len() < 2 * U32_LEN {
        return Err(CycloError::InvalidInstance("ccs_matrix too short for header"));
    }
    let rows = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let cols = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let expected_data_len = rows as usize * cols as usize * FR_SERIALIZED_LEN;
    if bytes.len() != 2 * U32_LEN + expected_data_len {
        return Err(CycloError::InvalidInstance("ccs_matrix length mismatch"));
    }
    let mut elems = Vec::with_capacity((rows as usize) * (cols as usize));
    for chunk in bytes[2 * U32_LEN..].chunks_exact(FR_SERIALIZED_LEN) {
        let fr = fr_from_bytes_le(chunk)?;
        elems.push(fr);
    }
    Ok((rows, cols, elems))
}

/// Parse serialized witness bytes into a vector of Fr elements.
pub fn parse_witness(bytes: &[u8]) -> Result<Vec<Fr>, CycloError> {
    if bytes.len() < U32_LEN {
        return Err(CycloError::InvalidInstance("witness_bytes too short for header"));
    }
    let num_vars = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let expected_len = U32_LEN + num_vars as usize * FR_SERIALIZED_LEN;
    if bytes.len() != expected_len {
        return Err(CycloError::InvalidInstance("witness_bytes length mismatch"));
    }
    let mut elems = Vec::with_capacity(num_vars as usize);
    for chunk in bytes[U32_LEN..].chunks_exact(FR_SERIALIZED_LEN) {
        let fr = fr_from_bytes_le(chunk)?;
        elems.push(fr);
    }
    Ok(elems)
}

fn fr_from_bytes_le(bytes: &[u8]) -> Result<Fr, CycloError> {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = i * 8;
        let end = start + 8;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[start..end]);
        *limb = u64::from_le_bytes(arr);
    }
    let bigint = ark_ff::BigInt::new(limbs);
    Fr::from_bigint(bigint)
        .ok_or_else(|| CycloError::InvalidInstance("Fr deserialization failure"))
}

/// Compute `m · z` (matrix-vector multiply, field arithmetic).
fn mat_vec_mul(rows: u32, cols: u32, m: &[Fr], z: &[Fr]) -> Vec<Fr> {
    let mut result = vec![Fr::ZERO; rows as usize];
    for r in 0..rows as usize {
        let mut acc = Fr::ZERO;
        for c in 0..cols as usize {
            acc += m[r * cols as usize + c] * z[c];
        }
        result[r] = acc;
    }
    result
}

/// Checks the CCS satisfiability relation for `instance`.
///
/// Enforces `M·z ⊙ z == 0` (the real CCS relation over the BN254 scalar field).
pub fn check_satisfiability(instance: &CcsInstance) -> Result<(), CycloError> {
    let (rows, cols, m) = parse_matrix(&instance.ccs_matrix)?;
    let z = parse_witness(&instance.witness_bytes)?;

    if z.len() != cols as usize {
        return Err(CycloError::InvalidInstance(
            "witness length does not match matrix column count",
        ));
    }

    if rows as usize != z.len() {
        return Err(CycloError::InvalidInstance(
            "CCS matrix must be square (rows == cols) for M·z ⊙ z == 0",
        ));
    }

    let mz = mat_vec_mul(rows, cols, &m, &z);

    for (i, elem) in mz.iter().enumerate() {
        if *elem * z[i] != Fr::ZERO {
            return Err(CycloError::AccumulatorVerificationFailed(
                "CCS relation unsatisfied: (M·z)⊙z ≠ 0",
            ));
        }
    }

    Ok(())
}

