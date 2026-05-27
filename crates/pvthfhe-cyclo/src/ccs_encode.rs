//! CCS instance encoding for one P1 NIZK output.
//!
//! Supports two domains:
//! - Fr (BN254 scalar field) via `CcsInstance` and `check_satisfiability()`
//! - R_q (polynomial ring) via `CcsRqInstance` and `check_satisfiability_rq()`

use crate::ring::{ntt_mul, ring_add_poly, rqpoly_to_bytes, RqPoly, PHI_COMMIT, Q_COMMIT};
use crate::{CcsPShareInstance, CycloError, MultiTrackPShareInstance};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use sha2::{Digest, Sha256};

/// Encoded CCS instance for a single participant share (Fr domain).
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

/// Encoded CCS instance over R_q (polynomial domain).
///
/// Each matrix entry and witness entry is an `RqPoly` (256 coefficients over Z_q).
///
/// The satisfiability check supports two modes:
/// - **1-matrix (legacy)**: `M·z ⊙ z == 0` over `R_{q_commit}` using NTT arithmetic.
///   Uses the `matrix_data` field (backward compat).
/// - **3-matrix (full CCS)**: `(M₁·z) ⊙ (M₂·z) == M₃·z`. Uses `m1_bytes`,
///   `m2_bytes`, `m3_bytes`. Automatically selected when `m2_bytes` or `m3_bytes`
///   is non-empty.
pub struct CcsRqInstance {
    /// 32-byte hash of the Ajtai commitment (SHA-256).
    pub ajtai_hash: [u8; 32],
    /// 32-byte hash of the public I/O (SHA-256).
    pub public_io_hash: [u8; 32],
    /// Witness vector: each entry is a polynomial in R_q.
    pub witness: Vec<RqPoly>,
    /// Serialized CCS constraint matrix over R_q (backward compat, 1-matrix):
    /// [rows:u32 BE][cols:u32 BE][entry0: PHI_COMMIT*u64 LE]...[entryN: PHI_COMMIT*u64 LE].
    pub matrix_data: Vec<u8>,
    /// Serialized first CCS constraint matrix M₁ over R_q (same internal format).
    pub m1_bytes: Vec<u8>,
    /// Serialized second CCS constraint matrix M₂ over R_q (same internal format).
    pub m2_bytes: Vec<u8>,
    /// Serialized third CCS constraint matrix M₃ over R_q (same internal format).
    pub m3_bytes: Vec<u8>,
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

    Ok(CcsInstance {
        participant_id: share.participant_id,
        ajtai_hash,
        public_io_hash: public_io_legacy_hash(share),
        sha256_binding,
        witness_bytes: share.ccs_witness_bytes.to_wire_bytes(),
        ccs_matrix: share.ccs_matrix_bytes.0.clone(),
    })
}

/// Encodes a multi-track fold instance while binding public track metadata.
pub fn encode_multitrack(share: &MultiTrackPShareInstance) -> Result<CcsInstance, CycloError> {
    let mut encoded = encode(&share.base)?;
    encoded.public_io_hash = public_io_hash_with_metadata(share);
    Ok(encoded)
}

/// Canonical public-IO bytes bound by fold challenges and public IO hashing.
pub fn public_io_binding_bytes(share: &MultiTrackPShareInstance) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"pvthfhe-cyclo-public-io-binding-v1");
    out.extend_from_slice(&(share.base.public_io_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(share.base.public_io_bytes.as_slice());
    match &share.multi_track_metadata {
        Some(metadata) => {
            let metadata_bytes = metadata.canonical_bytes();
            out.push(1);
            out.extend_from_slice(&(metadata_bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(&metadata_bytes);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&0u64.to_be_bytes());
        }
    }
    out
}

fn public_io_legacy_hash(share: &CcsPShareInstance) -> [u8; 32] {
    Sha256::new()
        .chain_update(share.public_io_bytes.as_slice())
        .finalize()
        .into()
}

fn public_io_hash_with_metadata(share: &MultiTrackPShareInstance) -> [u8; 32] {
    Sha256::new()
        .chain_update(public_io_binding_bytes(share))
        .finalize()
        .into()
}

const FR_SERIALIZED_LEN: usize = 32;
const U32_LEN: usize = 4;

/// Parse a serialized CCS matrix into `(num_rows, num_cols, flat data)`.
fn parse_matrix(bytes: &[u8]) -> Result<(u32, u32, Vec<Fr>), CycloError> {
    if bytes.len() < 2 * U32_LEN {
        return Err(CycloError::InvalidInstance(
            "ccs_matrix too short for header",
        ));
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
        return Err(CycloError::InvalidInstance(
            "witness_bytes too short for header",
        ));
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
    Fr::from_bigint(bigint).ok_or(CycloError::InvalidInstance("Fr deserialization failure"))
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

// ── R_q polynomial domain CCS ──────────────────────────────────────────────

/// Bytes per serialized `RqPoly`: `PHI_COMMIT` u64-LE coefficients.
const RQ_POLY_BYTES: usize = PHI_COMMIT * 8;

/// Parse a serialized R_q CCS matrix into `(rows, cols, flat data)`.
fn parse_rq_matrix(bytes: &[u8]) -> Result<(u32, u32, Vec<RqPoly>), CycloError> {
    const U32_LEN: usize = 4;
    if bytes.len() < 2 * U32_LEN {
        return Err(CycloError::InvalidInstance(
            "ccs_rq_matrix too short for header",
        ));
    }
    let rows = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let cols = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let num_entries = (rows as usize) * (cols as usize);
    let expected_data_len = num_entries * RQ_POLY_BYTES;
    if bytes.len() != 2 * U32_LEN + expected_data_len {
        return Err(CycloError::InvalidInstance("ccs_rq_matrix length mismatch"));
    }
    let mut polys = Vec::with_capacity(num_entries);
    let data_start = 2 * U32_LEN;
    for chunk in bytes[data_start..].chunks_exact(RQ_POLY_BYTES) {
        let mut coeffs = Vec::with_capacity(PHI_COMMIT);
        for u64_chunk in chunk.chunks_exact(8) {
            let arr: [u8; 8] = u64_chunk
                .try_into()
                .map_err(|_| CycloError::InvalidInstance("u64 deserialization failure"))?;
            coeffs.push(u64::from_le_bytes(arr));
        }
        let poly = RqPoly::new(coeffs)?;
        polys.push(poly);
    }
    Ok((rows, cols, polys))
}

fn zero_rq_poly() -> RqPoly {
    RqPoly::zero()
}

fn is_zero_rq_poly(p: &RqPoly) -> bool {
    p.0.iter().all(|&c| c == 0)
}

/// Computes `M·z` over R_q: matrix-vector multiply with NTT polynomial arithmetic.
fn mat_vec_mul_rq(rows: u32, cols: u32, m: &[RqPoly], z: &[RqPoly]) -> Vec<RqPoly> {
    let mut result = vec![zero_rq_poly(); rows as usize];
    for r in 0..rows as usize {
        let mut acc = zero_rq_poly();
        for c in 0..cols as usize {
            let prod = ntt_mul(&m[r * cols as usize + c], &z[c]).unwrap_or_else(|_| zero_rq_poly());
            acc = ring_add_poly(&acc, &prod);
        }
        result[r] = acc;
    }
    result
}

/// Checks the CCS satisfiability relation for `instance` over R_q.
///
/// Two modes, selected automatically:
/// - **1-matrix (legacy)**: if `m2_bytes` and `m3_bytes` are both empty, enforces
///   `M·z ⊙ z == 0` using `matrix_data`.
/// - **3-matrix (full CCS)**: if `m1_bytes`, `m2_bytes`, and `m3_bytes` are all
///   non-empty, enforces `(M₁·z) ⊙ (M₂·z) == M₃·z`.
pub fn check_satisfiability_rq(instance: &CcsRqInstance) -> Result<(), CycloError> {
    let has_three_matrices = !instance.m2_bytes.is_empty() || !instance.m3_bytes.is_empty();

    if has_three_matrices {
        if instance.m1_bytes.is_empty()
            || instance.m2_bytes.is_empty()
            || instance.m3_bytes.is_empty()
        {
            return Err(CycloError::InvalidInstance(
                "3-matrix CCS: m1_bytes, m2_bytes, and m3_bytes must all be non-empty",
            ));
        }
        return check_three_matrix_rq(instance);
    }

    let (rows, cols, m) = parse_rq_matrix(&instance.matrix_data)?;
    let z = &instance.witness;

    if z.len() != cols as usize {
        return Err(CycloError::InvalidInstance(
            "witness length does not match R_q matrix column count",
        ));
    }

    if rows as usize != z.len() {
        return Err(CycloError::InvalidInstance(
            "CCS R_q matrix must be square (rows == cols) for M·z ⊙ z == 0",
        ));
    }

    let mz = mat_vec_mul_rq(rows, cols, &m, z);

    for (i, prod) in mz.iter().enumerate() {
        let hadamard = ntt_mul(prod, &z[i])
            .map_err(|_| CycloError::InvalidInstance("NTT mul failed during CCS Hadamard check"))?;
        if !is_zero_rq_poly(&hadamard) {
            return Err(CycloError::AccumulatorVerificationFailed(
                "CCS R_q relation unsatisfied: (M·z)⊙z ≠ 0",
            ));
        }
    }

    Ok(())
}

/// Full 3-matrix CCS satisfiability check: `(M₁·z) ⊙ (M₂·z) == M₃·z`.
///
/// Computes the full matrix-vector products for each of the three matrices,
/// then checks the Hadamard product equality row-by-row using NTT arithmetic.
fn check_three_matrix_rq(instance: &CcsRqInstance) -> Result<(), CycloError> {
    let (rows1, cols1, m1) = parse_rq_matrix(&instance.m1_bytes)?;
    let (rows2, cols2, m2) = parse_rq_matrix(&instance.m2_bytes)?;
    let (rows3, cols3, m3) = parse_rq_matrix(&instance.m3_bytes)?;
    let z = &instance.witness;

    if rows1 != rows2 || rows2 != rows3 {
        return Err(CycloError::InvalidInstance(
            "3-matrix CCS: M1, M2, M3 must have the same number of rows",
        ));
    }
    if cols1 != cols2 || cols2 != cols3 {
        return Err(CycloError::InvalidInstance(
            "3-matrix CCS: M1, M2, M3 must have the same number of columns",
        ));
    }
    if z.len() != cols1 as usize {
        return Err(CycloError::InvalidInstance(
            "3-matrix CCS: witness length does not match matrix column count",
        ));
    }

    let rows = rows1;
    let cols = cols1;

    let v1 = mat_vec_mul_rq(rows, cols, &m1, z);
    let v2 = mat_vec_mul_rq(rows, cols, &m2, z);
    let v3 = mat_vec_mul_rq(rows, cols, &m3, z);

    for r in 0..rows as usize {
        let h = ntt_mul(&v1[r], &v2[r])
            .map_err(|_| CycloError::InvalidInstance("NTT mul failed in 3-matrix CCS check"))?;
        let diff = ring_sub(&h, &v3[r]);
        if !is_zero_rq_poly(&diff) {
            return Err(CycloError::AccumulatorVerificationFailed(
                "3-matrix CCS relation unsatisfied: (M₁·z)⊙(M₂·z) ≠ M₃·z",
            ));
        }
    }

    Ok(())
}

/// Polynomial subtraction in `R_{q_commit}`: `a - b = a + (-b)`.
fn ring_sub(a: &RqPoly, b: &RqPoly) -> RqPoly {
    let neg_b = RqPoly(
        b.0.iter()
            .map(|&c| if c == 0 { 0 } else { Q_COMMIT - c })
            .collect(),
    );
    ring_add_poly(a, &neg_b)
}

/// Encodes an `R_q` CCS instance into the 3-matrix wire format.
///
/// Format: `[num_rows:u32 BE][num_cols:u32 BE][m1_len:u32 BE][m1_bytes]
/// [m2_len:u32 BE][m2_bytes][m3_len:u32 BE][m3_bytes]
/// [num_vars:u32 BE][witness: num_vars × RQ_POLY_BYTES]
/// [ajtai_hash:32][public_io_hash:32]`
///
/// If `m1_bytes` is empty but `matrix_data` is set (backward compat),
/// `matrix_data` is used as the M₁ matrix.
pub fn encode_rq_instance(instance: &CcsRqInstance) -> Vec<u8> {
    let m1 = if instance.m1_bytes.is_empty() && !instance.matrix_data.is_empty() {
        &instance.matrix_data
    } else {
        &instance.m1_bytes
    };
    let m2 = &instance.m2_bytes;
    let m3 = &instance.m3_bytes;

    let (num_rows, num_cols) = if !m1.is_empty() {
        match parse_rq_matrix(m1) {
            Ok((r, c, _)) => (r, c),
            Err(_) => (0, 0),
        }
    } else {
        (0, 0)
    };

    let mut out = Vec::new();
    out.extend_from_slice(&num_rows.to_be_bytes());
    out.extend_from_slice(&num_cols.to_be_bytes());

    out.extend_from_slice(&(m1.len() as u32).to_be_bytes());
    out.extend_from_slice(m1);

    out.extend_from_slice(&(m2.len() as u32).to_be_bytes());
    out.extend_from_slice(m2);

    out.extend_from_slice(&(m3.len() as u32).to_be_bytes());
    out.extend_from_slice(m3);

    let num_vars = instance.witness.len() as u32;
    out.extend_from_slice(&num_vars.to_be_bytes());
    for poly in &instance.witness {
        out.extend_from_slice(&rqpoly_to_bytes(poly));
    }

    out.extend_from_slice(&instance.ajtai_hash);
    out.extend_from_slice(&instance.public_io_hash);
    out
}

/// Decodes a wire-format `R_q` CCS instance from bytes (3-matrix format).
///
/// If `m2_len == 0` and `m3_len == 0`, the instance uses only M₁ (1-matrix mode)
/// and `matrix_data` is populated for backward compat.
pub fn decode_rq_instance(bytes: &[u8]) -> Result<CcsRqInstance, CycloError> {
    const HDR_MIN: usize = 4 + 4   // num_rows + num_cols
        + 4                        // first m1_len
        + 32 + 32; // ajtai_hash + public_io_hash

    if bytes.len() < HDR_MIN {
        return Err(CycloError::InvalidInstance(
            "encoded R_q instance too short for 3-matrix format",
        ));
    }

    let mut pos = 0;

    let _num_rows =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;
    let _num_cols =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;

    // Read m1_len then m1_bytes (interleaved)
    let m1_len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;
    if bytes.len() < pos + m1_len as usize {
        return Err(CycloError::InvalidInstance(
            "encoded R_q instance truncated in m1 section",
        ));
    }
    let m1_bytes = if m1_len > 0 {
        bytes[pos..pos + m1_len as usize].to_vec()
    } else {
        Vec::new()
    };
    pos += m1_len as usize;

    // Read m2_len then m2_bytes (interleaved)
    if bytes.len() < pos + 4 {
        return Err(CycloError::InvalidInstance(
            "encoded R_q instance truncated at m2_len",
        ));
    }
    let m2_len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;
    if bytes.len() < pos + m2_len as usize {
        return Err(CycloError::InvalidInstance(
            "encoded R_q instance truncated in m2 section",
        ));
    }
    let m2_bytes = if m2_len > 0 {
        bytes[pos..pos + m2_len as usize].to_vec()
    } else {
        Vec::new()
    };
    pos += m2_len as usize;

    // Read m3_len then m3_bytes (interleaved)
    if bytes.len() < pos + 4 {
        return Err(CycloError::InvalidInstance(
            "encoded R_q instance truncated at m3_len",
        ));
    }
    let m3_len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;
    if bytes.len() < pos + m3_len as usize {
        return Err(CycloError::InvalidInstance(
            "encoded R_q instance truncated in m3 section",
        ));
    }
    let m3_bytes = if m3_len > 0 {
        bytes[pos..pos + m3_len as usize].to_vec()
    } else {
        Vec::new()
    };
    pos += m3_len as usize;

    let num_vars = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;

    let expected_witness_bytes = num_vars as usize * RQ_POLY_BYTES;
    if bytes.len() < pos + expected_witness_bytes + 64 {
        return Err(CycloError::InvalidInstance(
            "encoded R_q instance truncated in witness section",
        ));
    }

    let mut witness = Vec::with_capacity(num_vars as usize);
    for _ in 0..num_vars {
        let poly_bytes = &bytes[pos..pos + RQ_POLY_BYTES];
        let mut coeffs = Vec::with_capacity(PHI_COMMIT);
        for u64_chunk in poly_bytes.chunks_exact(8) {
            let arr: [u8; 8] = u64_chunk
                .try_into()
                .map_err(|_| CycloError::InvalidInstance("u64 deserialization failure"))?;
            coeffs.push(u64::from_le_bytes(arr));
        }
        witness.push(RqPoly::new(coeffs)?);
        pos += RQ_POLY_BYTES;
    }

    let mut ajtai_hash = [0u8; 32];
    ajtai_hash.copy_from_slice(&bytes[pos..pos + 32]);
    pos += 32;

    let mut public_io_hash = [0u8; 32];
    public_io_hash.copy_from_slice(&bytes[pos..pos + 32]);

    let is_one_matrix = m2_len == 0 && m3_len == 0;
    let matrix_data = if is_one_matrix {
        m1_bytes.clone()
    } else {
        Vec::new()
    };

    Ok(CcsRqInstance {
        ajtai_hash,
        public_io_hash,
        witness,
        matrix_data,
        m1_bytes,
        m2_bytes,
        m3_bytes,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn one_poly() -> RqPoly {
        let mut coeffs = vec![0u64; PHI_COMMIT];
        coeffs[0] = 1;
        RqPoly(coeffs)
    }

    fn serialize_matrix_rq(rows: u32, cols: u32, data: &[RqPoly]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + data.len() * RQ_POLY_BYTES);
        out.extend_from_slice(&rows.to_be_bytes());
        out.extend_from_slice(&cols.to_be_bytes());
        for poly in data {
            out.extend_from_slice(&rqpoly_to_bytes(poly));
        }
        out
    }

    #[test]
    fn encode_decode_rq_roundtrip() {
        let z = vec![one_poly(), RqPoly::zero()];
        let m = vec![RqPoly::zero(), one_poly(), RqPoly::zero(), RqPoly::zero()];
        let matrix_data = serialize_matrix_rq(2, 2, &m);

        let instance = CcsRqInstance {
            ajtai_hash: [1u8; 32],
            public_io_hash: [2u8; 32],
            witness: z,
            matrix_data,
            m1_bytes: Vec::new(),
            m2_bytes: Vec::new(),
            m3_bytes: Vec::new(),
        };

        let encoded = encode_rq_instance(&instance);
        let decoded = decode_rq_instance(&encoded).expect("roundtrip should succeed");
        assert_eq!(instance.ajtai_hash, decoded.ajtai_hash);
        assert_eq!(instance.public_io_hash, decoded.public_io_hash);
        assert_eq!(instance.witness, decoded.witness);
        assert_eq!(instance.matrix_data, decoded.matrix_data);
    }

    #[test]
    fn encode_decode_rq_three_matrix_roundtrip() {
        let z = vec![
            one_poly(),
            one_poly(),
            one_poly(),
            one_poly(),
            RqPoly::zero(),
        ];
        // 1×5 matrices for a*b=c check:
        // M1 selects z[0]=a, M2 selects z[1]=b, M3 selects z[2]=c
        let m1_data = serialize_matrix_rq(
            1,
            5,
            &[
                one_poly(),
                RqPoly::zero(),
                RqPoly::zero(),
                RqPoly::zero(),
                RqPoly::zero(),
            ],
        );
        let m2_data = serialize_matrix_rq(
            1,
            5,
            &[
                RqPoly::zero(),
                one_poly(),
                RqPoly::zero(),
                RqPoly::zero(),
                RqPoly::zero(),
            ],
        );
        let m3_data = serialize_matrix_rq(
            1,
            5,
            &[
                RqPoly::zero(),
                RqPoly::zero(),
                one_poly(),
                RqPoly::zero(),
                RqPoly::zero(),
            ],
        );

        let instance = CcsRqInstance {
            ajtai_hash: [3u8; 32],
            public_io_hash: [4u8; 32],
            witness: z,
            matrix_data: Vec::new(),
            m1_bytes: m1_data,
            m2_bytes: m2_data,
            m3_bytes: m3_data,
        };

        let encoded = encode_rq_instance(&instance);
        let decoded = decode_rq_instance(&encoded).expect("3-matrix roundtrip should succeed");
        assert_eq!(instance.ajtai_hash, decoded.ajtai_hash);
        assert_eq!(instance.public_io_hash, decoded.public_io_hash);
        assert_eq!(instance.witness, decoded.witness);
        assert_eq!(instance.m1_bytes, decoded.m1_bytes);
        assert_eq!(instance.m2_bytes, decoded.m2_bytes);
        assert_eq!(instance.m3_bytes, decoded.m3_bytes);
    }

    #[test]
    fn decode_rq_rejects_short_input() {
        let result = decode_rq_instance(&[0u8; 16]);
        assert!(result.is_err(), "short input should be rejected");
    }
}
