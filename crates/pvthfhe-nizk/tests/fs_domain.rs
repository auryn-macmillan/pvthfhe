//! Domain-separator isolation tests for the Fiat-Shamir transcript (N5).
//!
//! These tests verify:
//! - Different domain separators (session_id or participant_id) produce
//!   distinct challenge bytes.
//! - Identical inputs produce identical challenge bytes (determinism).
//! - A concrete golden vector is pinned for cross-implementation checks.

use pvthfhe_nizk::fiat_shamir::Transcript;

/// Test A: different session_id → different challenge bytes.
#[test]
fn test_different_session_id_yields_distinct_challenge() {
    let mut t1 = Transcript::new(b"alpha", 1);
    t1.absorb(b"msg", b"hello world");
    let mut out1 = [0u8; 32];
    t1.challenge_bytes(b"chall", &mut out1);

    let mut t2 = Transcript::new(b"beta", 1);
    t2.absorb(b"msg", b"hello world");
    let mut out2 = [0u8; 32];
    t2.challenge_bytes(b"chall", &mut out2);

    assert_ne!(
        out1, out2,
        "different session_id must yield distinct challenges"
    );
}

/// Test B: identical inputs → identical challenge bytes (determinism).
#[test]
fn test_same_inputs_yields_identical_challenge() {
    let make = || {
        let mut t = Transcript::new(b"session42", 7);
        t.absorb(b"round", b"commitment_data");
        t.absorb(b"extra", b"more_data");
        let mut out = [0u8; 32];
        t.challenge_bytes(b"challenge", &mut out);
        out
    };

    assert_eq!(
        make(),
        make(),
        "determinism: identical inputs must produce identical output"
    );
}

/// Test C: different participant_id → different challenge bytes.
#[test]
fn test_different_participant_id_yields_distinct_challenge() {
    let mut t1 = Transcript::new(b"session", 1);
    t1.absorb(b"msg", b"data");
    let mut out1 = [0u8; 32];
    t1.challenge_bytes(b"chall", &mut out1);

    let mut t2 = Transcript::new(b"session", 2);
    t2.absorb(b"msg", b"data");
    let mut out2 = [0u8; 32];
    t2.challenge_bytes(b"chall", &mut out2);

    assert_ne!(
        out1, out2,
        "different participant_id must yield distinct challenges"
    );
}

/// Test D: golden vector — concrete pinned output cross-checked against
/// `bench/scripts/fs_golden_ref.py`.
///
/// Inputs: session_id = b"golden", participant_id = 42
/// Absorb: label = b"field", data = b"test_vector"
/// Challenge: label = b"squeeze", out = 32 bytes
///
/// Expected hex computed by `bench/scripts/fs_golden_ref.py`.
#[test]
fn test_golden_vector() {
    let mut t = Transcript::new(b"golden", 42);
    t.absorb(b"field", b"test_vector");
    let mut out = [0u8; 32];
    t.challenge_bytes(b"squeeze", &mut out);

    let got = hex::encode(out);
    // Value computed by bench/scripts/fs_golden_ref.py — do not change without
    // updating the Python reference script and re-verifying.
    let expected = "b012abf2c80da2bffa22b01322ab65695ab0685c0deb810e49277d23f4aa6fcd";
    assert_eq!(got, expected, "golden vector mismatch");
}
