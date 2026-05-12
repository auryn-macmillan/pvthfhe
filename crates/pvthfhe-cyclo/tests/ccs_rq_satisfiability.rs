//! RED test: CCS satisfiability check over R_q (polynomial domain).
//!
//! Uses `CcsRqInstance` with `RqPoly` witnesses and `check_satisfiability_rq()`
//! that computes `M·z ⊙ z == 0` over `R_{q_commit}` using NTT arithmetic from `ring.rs`.
//!
//! These tests are initially **RED** (no implementation), then turn **GREEN**
//! after the real implementation is committed.

use pvthfhe_cyclo::ccs_encode::{check_satisfiability_rq, CcsRqInstance};
use pvthfhe_cyclo::ring::{ntt_mul, ring_add_poly, rqpoly_to_bytes, RqPoly, PHI_COMMIT, Q_COMMIT};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

/// Polynomial with constant coefficient 1, all others 0.
fn one_poly() -> RqPoly {
    let mut coeffs = vec![0u64; PHI_COMMIT];
    coeffs[0] = 1;
    RqPoly(coeffs)
}

/// Zero polynomial (all 256 coefficients are 0).
fn zero_poly() -> RqPoly {
    RqPoly(vec![0u64; PHI_COMMIT])
}

/// Serialize a flat row-major matrix of `RqPoly` elements into wire format:
/// [rows: u32 BE][cols: u32 BE][entry0: 2048 bytes]...[entryN: 2048 bytes]
fn serialize_matrix_rq(rows: u32, cols: u32, data: &[RqPoly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len() * PHI_COMMIT * 8);
    out.extend_from_slice(&rows.to_be_bytes());
    out.extend_from_slice(&cols.to_be_bytes());
    for poly in data {
        out.extend_from_slice(&rqpoly_to_bytes(poly));
    }
    out
}

/// Build a `CcsRqInstance` with matrix and witness for testing.
fn make_rq_instance(
    participant_id: u16,
    m_rows: u32,
    m_cols: u32,
    matrix: &[RqPoly],
    witness: &[RqPoly],
) -> CcsRqInstance {
    let matrix_data = serialize_matrix_rq(m_rows, m_cols, matrix);

    // Compute hashes for instance identity
    let ajtai_data: Vec<u8> = vec![participant_id as u8; 32];
    let public_io_data: Vec<u8> = vec![(participant_id as u8).wrapping_add(1); 32];
    let ajtai_hash: [u8; 32] = Sha256::new().chain_update(&ajtai_data).finalize().into();
    let public_io_hash: [u8; 32] =
        Sha256::new().chain_update(&public_io_data).finalize().into();

    CcsRqInstance {
        ajtai_hash,
        public_io_hash,
        witness: witness.to_vec(),
        matrix_data,
        m1_bytes: Vec::new(),
        m2_bytes: Vec::new(),
        m3_bytes: Vec::new(),
    }
}

/// Sample a random `RqPoly` with coefficients in `[0, Q_COMMIT)`.
fn random_poly(rng: &mut ChaCha20Rng) -> RqPoly {
    let coeffs: Vec<u64> = (0..PHI_COMMIT).map(|_| rng.next_u64() % Q_COMMIT).collect();
    RqPoly(coeffs)
}

// ---------------------------------------------------------------------------
// Positive test: 1×1 matrix, witness = [zero_poly], matrix = [one_poly]
// (one · zero) ⊙ [zero] = [zero·zero] = [zero] ✓
// ---------------------------------------------------------------------------
#[test]
fn positive_1x1_zero_witness_satisfies() {
    let m = [one_poly()];
    let z = [zero_poly()];

    let instance = make_rq_instance(1, 1, 1, &m, &z);
    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_ok(),
        "1×1 zero witness should satisfy, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative test: 1×1 matrix, witness = [one_poly], matrix = [one_poly]
// (one · one) ⊙ [one] = [one·one] = [one] ≠ [zero]  ✗
// ---------------------------------------------------------------------------
#[test]
fn negative_1x1_nonzero_witness_rejected() {
    let m = [one_poly()];
    let z = [one_poly()];

    let instance = make_rq_instance(1, 1, 1, &m, &z);
    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "1×1 one_poly witness should be rejected, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Positive test: 2×2 matrix, relation residual * d_i == 0
// M = [[zero, one], [zero, zero]]
// witness z = [d_i, residual] where residual = 0
// M·z = [residual, 0]
// (M·z) ⊙ z = [residual * d_i, 0 * residual] = [0, 0] ✓
// ---------------------------------------------------------------------------
#[test]
fn positive_2x2_residual_zero_satisfies() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let d_i = random_poly(&mut rng);
    let residual = zero_poly();

    let m = [zero_poly(), one_poly(), zero_poly(), zero_poly()];
    let z = [d_i, residual];

    let instance = make_rq_instance(1, 2, 2, &m, &z);
    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_ok(),
        "2×2 with residual=0 should satisfy, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative test: 2×2 matrix with non-zero residual
// Same M as above, but residual = one_poly (non-zero)
// (M·z) ⊙ z = [one_poly * d_i, 0] → first entry non-zero → fails ✗
// ---------------------------------------------------------------------------
#[test]
fn negative_2x2_nonzero_residual_rejected() {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let d_i = random_poly(&mut rng);
    let residual = one_poly(); // non-zero residual

    let m = [zero_poly(), one_poly(), zero_poly(), zero_poly()];
    let z = [d_i, residual];

    let instance = make_rq_instance(1, 2, 2, &m, &z);
    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "2×2 with non-zero residual should be rejected, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Positive test: 3×3 matrix with zero-witness constraint
// z = [zero, b, zero] where M[2] = [0, 1, -1] and b = zero_poly
// M·z = [0, 0, b - zero] = [0, 0, 0]
// (M·z) ⊙ z = [0, 0, 0] ✓
// ---------------------------------------------------------------------------
#[test]
fn positive_3x3_zero_witness_satisfies() {
    let a = zero_poly();
    let b = zero_poly();
    let z2 = zero_poly();

    let m = [
        zero_poly(), zero_poly(), zero_poly(), // row 0
        zero_poly(), zero_poly(), zero_poly(), // row 1
        zero_poly(), one_poly(), {
            // -one_poly mod q_commit
            let mut neg_coeffs = vec![0u64; PHI_COMMIT];
            neg_coeffs[0] = Q_COMMIT - 1;
            RqPoly(neg_coeffs)
        }, // row 2: [0, 1, -1]
    ];
    let z = [a, b, z2];

    let instance = make_rq_instance(1, 3, 3, &m, &z);
    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_ok(),
        "3×3 zero witness should satisfy, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative test: 3×3 matrix with non-zero mismatch
// M[2] = [0, one, -one], z = [zero, one, one]
// M[2]·z = 0*zero + one*one + (-one)*one = one - one = zero
// But z[2] = one → zero * one = 0 → passes! (let's use a case that fails)
// 
// M[2] = [0, one, zero], z = [zero, one, one]
// M[2]·z = 0*zero + one*one + zero*one = one
// z[2] = one → one * one = one ≠ 0 → fails ✗
// ---------------------------------------------------------------------------
#[test]
fn negative_3x3_nonzero_product_rejected() {
    let a = zero_poly();
    let b = one_poly();
    let z2 = one_poly();

    let m = [
        zero_poly(), zero_poly(), zero_poly(), // row 0
        zero_poly(), zero_poly(), zero_poly(), // row 1
        zero_poly(), one_poly(), zero_poly(), // row 2: [0, 1, 0]
    ];
    let z = [a, b, z2];

    let instance = make_rq_instance(1, 3, 3, &m, &z);
    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "3×3 non-zero Hadamard product should be rejected, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Positive test: 1×1 matrix, witness = [random_poly], matrix = [zero_poly]
// (zero · random) ⊙ [random] = [zero·random] = [zero] ✓
// ---------------------------------------------------------------------------
#[test]
fn positive_1x1_zero_matrix_always_satisfies() {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let z = [random_poly(&mut rng)];
    let m = [zero_poly()];

    let instance = make_rq_instance(1, 1, 1, &m, &z);
    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_ok(),
        "1×1 zero matrix should always satisfy, got: {result:?}"
    );
}
