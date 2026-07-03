#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FF2 RED: exact-length witness validation tests.
//!
//! These tests verify that `validate_witness` rejects secret_share_poly and
//! error vectors whose lengths differ from `rlwe_n()`.  A prover with a
//! shorter (N=1024) secret could otherwise produce proofs that appear valid
//! for N=8192 because `pad_or_truncate_to_rlwe_n` silently pads with zeros.

use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::sigma::rlwe_n;
use pvthfhe_nizk::{NizkAdapter, NizkStatement, NizkWitness};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn make_witness(secret_share_poly: Vec<i64>, error: Vec<i64>) -> NizkWitness {
    let secret_share: u64 = secret_share_poly
        .first()
        .map(|&v| v.unsigned_abs())
        .unwrap_or(0);
    NizkWitness {
        secret_share,
        secret_share_poly,
        error,
        randomness: vec![],
    }
}

fn make_statement() -> NizkStatement {
    NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment: [0xBBu8; 32],
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: "ff2-test".to_owned(),
        participant_id: 1,
        epoch: 0,
    }
}

/// FF2-T1 (RED): prove must reject a witness whose secret_share_poly is
/// shorter than rlwe_n().  Without exact-length checks, `pad_or_truncate_to_rlwe_n`
/// would silently pad the short witness with zeros, producing a valid-looking
/// proof for a different RLWE dimension.
#[test]
fn validate_witness_rejects_short_secret_share_poly() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xFF02_0001);
    let adapter = CycloNizkAdapter;
    let stmt = make_statement();

    // secret_share_poly with only half the required coefficients
    let short_len = rlwe_n() / 2;
    let short_poly = vec![1i64; short_len];
    let error = vec![0i64; rlwe_n()];
    let witness = make_witness(short_poly, error);

    let result = adapter.prove(&stmt, &witness, &mut rng);
    assert!(
        result.is_err(),
        "FF2: prove must reject witness with short secret_share_poly (len={}, expected={}). Got: {result:?}",
        short_len,
        rlwe_n(),
    );
}

/// FF2-T2 (RED): prove must reject a witness whose error vector is shorter
/// than rlwe_n().  The same zero-padding issue applies: a short error vector
/// padded with zeros could satisfy the sigma verifier trivially.
#[test]
fn validate_witness_rejects_short_error() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xFF02_0002);
    let adapter = CycloNizkAdapter;
    let stmt = make_statement();

    let poly = vec![0i64; rlwe_n()];
    let short_len = rlwe_n() / 4;
    let short_error = vec![2i64; short_len];

    let witness = make_witness(poly, short_error);

    let result = adapter.prove(&stmt, &witness, &mut rng);
    assert!(
        result.is_err(),
        "FF2: prove must reject witness with short error (len={}, expected={}). Got: {result:?}",
        short_len,
        rlwe_n(),
    );
}

/// FF2-T3 (RED): prove must reject a witness whose secret_share_poly is
/// longer than rlwe_n().  A longer witness could carry extra adversarial
/// coefficients that are silently truncated by `pad_or_truncate_to_rlwe_n`.
#[test]
fn validate_witness_rejects_long_secret_share_poly() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xFF02_0003);
    let adapter = CycloNizkAdapter;
    let stmt = make_statement();

    let long_len = rlwe_n() * 2;
    let long_poly = vec![0i64; long_len];
    let error = vec![0i64; rlwe_n()];

    let witness = make_witness(long_poly, error);

    let result = adapter.prove(&stmt, &witness, &mut rng);
    assert!(
        result.is_err(),
        "FF2: prove must reject witness with long secret_share_poly (len={}, expected={}). Got: {result:?}",
        long_len,
        rlwe_n(),
    );
}

/// FF2-T4 (RED): prove must reject a witness whose error vector is longer
/// than rlwe_n().
#[test]
fn validate_witness_rejects_long_error() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xFF02_0004);
    let adapter = CycloNizkAdapter;
    let stmt = make_statement();

    let poly = vec![0i64; rlwe_n()];
    let long_len = rlwe_n() + 128;
    let long_error = vec![1i64; long_len];

    let witness = make_witness(poly, long_error);

    let result = adapter.prove(&stmt, &witness, &mut rng);
    assert!(
        result.is_err(),
        "FF2: prove must reject witness with long error (len={}, expected={}). Got: {result:?}",
        long_len,
        rlwe_n(),
    );
}

/// FF2-T5: An exactly-sized witness must still be accepted (sanity check).
#[test]
fn validate_witness_accepts_exact_length() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xFF02_0005);
    let adapter = CycloNizkAdapter;
    let stmt = make_statement();

    let poly = vec![0i64; rlwe_n()];
    let error = vec![0i64; rlwe_n()];
    let witness = make_witness(poly, error);

    let result = adapter.prove(&stmt, &witness, &mut rng);
    match result {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                !msg.contains("secret_share_poly") && !msg.contains("error"),
                "FF2: exact-length witness was rejected for length reason: {e}"
            );
        }
    }
}
