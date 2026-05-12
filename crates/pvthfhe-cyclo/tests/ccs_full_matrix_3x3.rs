//! RED test: 3-matrix CCS satisfiability over R_q for `a * b = c`.
//!
//! Encodes the relation `a * b = c` as a 3-matrix CCS instance with a
//! 5-element witness `[a, b, c, one, zero]`. Valid witnesses satisfy;
//! tampered `c` is rejected.

use pvthfhe_cyclo::ccs_encode::{check_satisfiability_rq, CcsRqInstance};
use pvthfhe_cyclo::ring::{ntt_mul, rqpoly_to_bytes, RqPoly, PHI_COMMIT};
use sha2::{Digest, Sha256};

fn one_poly() -> RqPoly {
    let mut coeffs = vec![0u64; PHI_COMMIT];
    coeffs[0] = 1;
    RqPoly(coeffs)
}

fn zero_poly() -> RqPoly {
    RqPoly(vec![0u64; PHI_COMMIT])
}

fn serialize_matrix_rq(rows: u32, cols: u32, data: &[RqPoly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len() * PHI_COMMIT * 8);
    out.extend_from_slice(&rows.to_be_bytes());
    out.extend_from_slice(&cols.to_be_bytes());
    for poly in data {
        out.extend_from_slice(&rqpoly_to_bytes(poly));
    }
    out
}

#[test]
fn three_matrix_valid_a_times_b_equals_c_satisfies() {
    // Witness: [a, b, c, one, zero]
    let a = one_poly();
    let b = one_poly();
    let c = ntt_mul(&a, &b).expect("a*b should succeed");
    let one = one_poly();
    let zero = zero_poly();

    let witness = vec![a.clone(), b.clone(), c.clone(), one.clone(), zero.clone()];

    // M1 selects a (index 0)
    let m1_data = serialize_matrix_rq(1, 5, &[
        one.clone(), zero.clone(), zero.clone(), zero.clone(), zero.clone(),
    ]);
    // M2 selects b (index 1)
    let m2_data = serialize_matrix_rq(1, 5, &[
        zero.clone(), one.clone(), zero.clone(), zero.clone(), zero.clone(),
    ]);
    // M3 selects c (index 2)
    let m3_data = serialize_matrix_rq(1, 5, &[
        zero.clone(), zero.clone(), one.clone(), zero.clone(), zero,
    ]);

    let ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(b"test_a_times_b")
        .finalize()
        .into();
    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(b"test_public_io")
        .finalize()
        .into();

    let instance = CcsRqInstance {
        ajtai_hash,
        public_io_hash,
        witness,
        matrix_data: Vec::new(),
        m1_bytes: m1_data,
        m2_bytes: m2_data,
        m3_bytes: m3_data,
    };

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_ok(),
        "3-matrix a*b=c with valid witness should satisfy, got: {result:?}"
    );
}

#[test]
fn three_matrix_tampered_c_rejected() {
    let a = one_poly();
    let b = one_poly();
    let _correct_c = ntt_mul(&a, &b).expect("a*b should succeed");
    let one = one_poly();
    let zero = zero_poly();

    // Tamper: use zero instead of correct c
    let witness = vec![a.clone(), b.clone(), zero.clone(), one.clone(), zero.clone()];

    let m1_data = serialize_matrix_rq(1, 5, &[
        one.clone(), zero.clone(), zero.clone(), zero.clone(), zero.clone(),
    ]);
    let m2_data = serialize_matrix_rq(1, 5, &[
        zero.clone(), one.clone(), zero.clone(), zero.clone(), zero.clone(),
    ]);
    let m3_data = serialize_matrix_rq(1, 5, &[
        zero.clone(), zero.clone(), one.clone(), zero.clone(), zero,
    ]);

    let ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(b"test_tampered_c")
        .finalize()
        .into();
    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(b"test_public_io")
        .finalize()
        .into();

    let instance = CcsRqInstance {
        ajtai_hash,
        public_io_hash,
        witness,
        matrix_data: Vec::new(),
        m1_bytes: m1_data,
        m2_bytes: m2_data,
        m3_bytes: m3_data,
    };

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "3-matrix a*b=c with tampered c should be rejected, got: {result:?}"
    );
}
