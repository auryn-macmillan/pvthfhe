//! RED test: Ajtai commitment over R_{q_commit}.
//!
//! Tests the commit→verify roundtrip and the binding property
//! (different witness → different commitment). Initially RED —
//! the `ajtai` module does not exist yet.

use pvthfhe_cyclo::ajtai::{
    commit, decode_commitment, encode_commitment, verify, AjtaiCommitment, AjtaiParams,
};
use pvthfhe_cyclo::ring::RqPoly;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Build a square `AjtaiParams` for testing with configurable m, n.
fn test_params(m: usize, n: usize) -> AjtaiParams {
    AjtaiParams {
        m,
        n,
        q_commit: pvthfhe_cyclo::ring::Q_COMMIT,
        seed: [0xABu8; 32],
    }
}

/// Generate a random witness of length `n`. Each element is a random RqPoly.
fn random_witness(n: usize, rng: &mut ChaCha20Rng) -> Vec<RqPoly> {
    let phi = pvthfhe_cyclo::ring::PHI_COMMIT;
    let q = pvthfhe_cyclo::ring::Q_COMMIT;
    (0..n)
        .map(|_| {
            let coeffs: Vec<u64> = (0..phi).map(|_| rng.next_u64() % q).collect();
            RqPoly(coeffs)
        })
        .collect()
}

// ── commit → verify roundtrip ────────────────────────────────────────────

#[test]
fn roundtrip_commit_then_verify() {
    let params = test_params(4, 2);
    let mut rng = ChaCha20Rng::from_seed([0x11u8; 32]);
    let witness = random_witness(params.n, &mut rng);

    let commitment = commit(&params, &witness, &mut rng)
        .expect("commit should succeed on valid witness");

    assert!(
        verify(&params, &commitment, &witness),
        "verify must accept the committed witness"
    );
}

// ── binding property: different witness → different commitment ───────────

#[test]
fn binding_different_witness_different_commitment() {
    let params = test_params(4, 2);
    let mut rng = ChaCha20Rng::from_seed([0x22u8; 32]);

    let w1 = random_witness(params.n, &mut rng);
    let w2 = random_witness(params.n, &mut rng);

    // The witnesses must be different; just to be safe, ensure w1 != w2
    assert_ne!(w1, w2, "test setup: witnesses should differ");

    let c1 = commit(&params, &w1, &mut rng)
        .expect("commit should succeed");

    // The binding property: verifying c1 with w2 should fail
    assert!(
        !verify(&params, &c1, &w2),
        "binding violation: different witness verified against same commitment"
    );
}

// ── wire format roundtrip ────────────────────────────────────────────────

#[test]
fn wire_format_roundtrip() {
    let params = test_params(4, 2);
    let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
    let witness = random_witness(params.n, &mut rng);

    let c = commit(&params, &witness, &mut rng)
        .expect("commit should succeed");

    let encoded = encode_commitment(&c);
    let decoded = decode_commitment(&encoded, params.m)
        .expect("decode should succeed on valid wire bytes");

    assert_eq!(c.commitment, decoded.commitment,
        "commitment wire-format roundtrip must be lossless");
}

// ── reject too-short witness ─────────────────────────────────────────────

#[test]
fn reject_wrong_witness_length() {
    let params = test_params(4, 2); // expects n=2
    let mut rng = ChaCha20Rng::from_seed([0x44u8; 32]);

    let short_witness = random_witness(1, &mut rng); // only 1 element

    let result = commit(&params, &short_witness, &mut rng);
    assert!(
        result.is_err(),
        "commit must reject witness with wrong length"
    );
}

// ── verify with wrong-length witness ─────────────────────────────────────

#[test]
fn verify_wrong_witness_length() {
    let params = test_params(4, 2);
    let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
    let witness = random_witness(params.n, &mut rng);

    let c = commit(&params, &witness, &mut rng)
        .expect("commit should succeed");

    let short_witness = random_witness(1, &mut rng);
    assert!(
        !verify(&params, &c, &short_witness),
        "verify must reject witness with wrong length"
    );
}

// ── verify with wrong-length commitment ──────────────────────────────────

#[test]
fn verify_wrong_commitment_length() {
    let params = test_params(4, 2);
    let mut rng = ChaCha20Rng::from_seed([0x66u8; 32]);
    let witness = random_witness(params.n, &mut rng);

    // Build a commitment with the wrong number of rows
    let bad_commitment = AjtaiCommitment {
        commitment: vec![RqPoly::zero()], // only 1 row, but m=4
    };

    let c = commit(&params, &witness, &mut rng)
        .expect("commit should succeed");

    assert!(
        verify(&params, &bad_commitment, &witness) != verify(&params, &c, &witness)
            || !verify(&params, &bad_commitment, &witness),
        "commitment length mismatch must not pass silently"
    );
}
