//! RED test: real CCS satisfiability check (M·z ⊙ z == 0).
//!
//! The current `check_satisfiability` in `ccs_encode.rs` is a SHA-256 tautology
//! that rehashes the instance fields and checks against a stored binding tag.
//! It must FAIL this test because it returns Ok for non-satisfying witnesses.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::ccs_encode::{check_satisfiability, CcsInstance};
use sha2::{Digest, Sha256};

/// Serialize a flat row-major matrix of Fr elements into CCS matrix wire format:
/// [rows: u32 BE][cols: u32 BE][elements: each 32 bytes LE]
fn serialize_matrix(rows: u32, cols: u32, data: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len() * 32);
    out.extend_from_slice(&rows.to_be_bytes());
    out.extend_from_slice(&cols.to_be_bytes());
    for elem in data {
        out.extend_from_slice(&elem.into_bigint().to_bytes_le());
    }
    out
}

/// Serialize a witness vector of Fr elements into witness wire format:
/// [num_vars: u32 BE][elements: each 32 bytes LE]
fn serialize_witness(data: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len() * 32);
    let num = u32::try_from(data.len()).expect("witness too long");
    out.extend_from_slice(&num.to_be_bytes());
    for elem in data {
        out.extend_from_slice(&elem.into_bigint().to_bytes_le());
    }
    out
}

/// Build a `CcsInstance` with CCS matrix and witness for testing.
fn make_instance(m_rows: u32, m_cols: u32, matrix: &[Fr], witness: &[Fr]) -> CcsInstance {
    let ccs_matrix = serialize_matrix(m_rows, m_cols, matrix);
    let witness_bytes = serialize_witness(witness);

    // Compute SHA-256 binding to match current tautology:
    // sha256_binding = SHA256(SHA256(ajtai) ∥ SHA256(pub_io) ∥ witness_bytes)
    let ajtai_raw: Vec<u8> = (0..32).map(|i| i as u8).collect();
    let pub_io_raw: Vec<u8> = (0..32).map(|i| (i as u8).wrapping_add(1)).collect();
    let ajtai_hash: [u8; 32] = Sha256::new().chain_update(&ajtai_raw).finalize().into();
    let public_io_hash: [u8; 32] = Sha256::new().chain_update(&pub_io_raw).finalize().into();
    let sha256_binding: [u8; 32] = Sha256::new()
        .chain_update(ajtai_hash)
        .chain_update(public_io_hash)
        .chain_update(&witness_bytes)
        .finalize()
        .into();

    CcsInstance {
        participant_id: 1,
        ajtai_hash,
        public_io_hash,
        sha256_binding,
        witness_bytes,
        ccs_matrix,
    }
}

#[test]
fn positive_satisfying_witness_returns_ok() {
    // z = [1, 2, 3]
    // M: rows=3, cols=3
    // Row 0: [0, 0, 0] → 0·z = 0
    // Row 1: [3, 0, -1] → 3·1 + 0·2 + (-1)·3 = 0
    // Row 2: [-6, 3, 0] → (-6)·1 + 3·2 + 0·3 = 0
    // M·z = [0, 0, 0] → M·z ⊙ z = [0, 0, 0] ✓

    let z = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let m = [
        Fr::ZERO, Fr::ZERO, Fr::ZERO,
        Fr::from(3u64), Fr::ZERO, -Fr::from(1u64),
        -Fr::from(6u64), Fr::from(3u64), Fr::ZERO,
    ];

    let instance = make_instance(3, 3, &m, &z);
    let result = check_satisfiability(&instance);
    assert!(
        result.is_ok(),
        "satisfying witness should return Ok, got: {result:?}"
    );
}

#[test]
fn negative_non_satisfying_witness_returns_err() {
    // Same M as above, z' = [1, 2, 4] (non-satisfying)
    // Row 0: [0, 0, 0] → 0·z' = 0   → z'[0]·0 = 0
    // Row 1: [3, 0, -1] → 3·1+0·2+(-1)·4 = -1 → z'[1]·(-1) = 2·(-1) = -2 ≠ 0
    // Row 2: [-6, 3, 0] → (-6)·1+3·2+0·4 = 0 → z'[2]·0 = 0
    // M·z' ⊙ z' = [0, -2, 0] ≠ 0 → should return Err

    let z = [Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)];
    let m = [
        Fr::ZERO, Fr::ZERO, Fr::ZERO,
        Fr::from(3u64), Fr::ZERO, -Fr::from(1u64),
        -Fr::from(6u64), Fr::from(3u64), Fr::ZERO,
    ];

    let instance = make_instance(3, 3, &m, &z);
    let result = check_satisfiability(&instance);
    assert!(
        result.is_err(),
        "non-satisfying witness should return Err, got: {result:?}"
    );
}
