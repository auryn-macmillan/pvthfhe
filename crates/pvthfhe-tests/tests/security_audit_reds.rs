//! Regression tests for error handling and fault tolerance (audit findings F5–F10).
//!
//! These verify the remediations that landed from the 2026-06/07 security audits:
//! 1. Errors propagate properly instead of panicking
//! 2. Party identifiers are included in error messages
//! 3. Invalid inputs are rejected gracefully
//!
//! Placeholder tests that asserted hardcoded booleans (old F7/F11/F12/F13/P1/P2
//! entries) were removed in the 2026-07 refactor: they pinned no behavior.

use pvthfhe_nizk::NizkError;
use pvthfhe_pvss::PvssError;
use pvthfhe_foundations::types::rlwe_n;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ---------------------------------------------------------------------------
// F6: prove/verify return errors instead of panicking on bad input
// ---------------------------------------------------------------------------

/// F6-1: NIZK prove fails gracefully (no panic) when given an invalid witness
/// (secret share poly with coefficients outside the ternary range).
#[test]
fn invalid_witness_should_return_error_not_panic() {
    use pvthfhe_nizk::adapter::CycloNizkAdapter;
    use pvthfhe_nizk::hash_bridge;
    use pvthfhe_nizk::{NizkAdapter, NizkStatement, NizkWitness};

    let session = "test-session";
    let mut rng = ChaCha20Rng::seed_from_u64(0xF6_01);
    let adapter = CycloNizkAdapter;

    // Coefficients outside {-1, 0, 1}.
    let s_i = vec![2i64, 3, -2, -3];
    let e_i = vec![0i64; rlwe_n()];
    let secret_share: u64 = 0;
    let pvss_commitment = hash_bridge::commit(session, 1, secret_share);

    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session.to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };

    let result = adapter.prove(&stmt, &witness, &mut rng);
    assert!(
        result.is_err(),
        "F6-1: invalid witness should produce an error, got {:?}",
        result
    );
}

/// F6-2: NIZK verify fails gracefully (no panic) on malformed proof bytes.
#[test]
fn malformed_proof_should_return_error_not_panic() {
    use pvthfhe_nizk::adapter::CycloNizkAdapter;
    use pvthfhe_nizk::hash_bridge;
    use pvthfhe_nizk::{NizkAdapter, NizkProof, NizkStatement};

    let session = "test-session";
    let adapter = CycloNizkAdapter;

    let pvss_commitment = hash_bridge::commit(session, 1, 0);

    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session.to_owned(),
        participant_id: 1,
        epoch: 0,
    };

    let malformed_proof = NizkProof {
        backend_id: "wrong-backend".to_owned(),
        proof_bytes: vec![0u8; 100],
    };

    let result = adapter.verify(&stmt, &malformed_proof);
    assert!(
        result.is_err(),
        "F6-2: malformed proof should produce an error, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// F5: errors carry party_id for blame attribution
// ---------------------------------------------------------------------------

/// F5-1: NizkError includes party_id in its display.
#[test]
fn nizk_error_should_include_party_id() {
    let error = NizkError::VerificationFailed {
        reason: "test failure",
        party_id: Some(42),
    };

    let error_str = format!("{}", error);
    assert!(
        error_str.contains("42"),
        "F5-1: error message should contain party_id, got: {}",
        error_str
    );
}

/// F5-2: PvssError includes party_id in relevant variants.
#[test]
fn pvss_error_should_include_party_id() {
    let error = PvssError::InvalidShare { party_id: Some(99) };

    let error_str = format!("{}", error);
    assert!(
        error_str.contains("99"),
        "F5-2: error message should contain party_id, got: {}",
        error_str
    );
}

// ---------------------------------------------------------------------------
// F7: DKG rounds surface timeout information
// ---------------------------------------------------------------------------

/// F7-1: DkgError has a RoundTimeout variant carrying the round number and the
/// parties that failed to respond — the structural hook for round timeouts.
#[test]
fn dkg_round_timeout_should_identify_round_and_missing_parties() {
    use pvthfhe_pvss::keygen::dkg::DkgError;

    let error = DkgError::RoundTimeout {
        round: 2,
        missing_parties: vec![3, 7],
    };

    let error_str = format!("{}", error);
    assert!(
        error_str.contains('2'),
        "F7-1: timeout error should name the round, got: {}",
        error_str
    );
}

// ---------------------------------------------------------------------------
// F8: DkgError carries party context
// ---------------------------------------------------------------------------

/// F8-1: DkgError variants include party_id for blame attribution.
#[test]
fn dkg_error_should_include_party_context() {
    use pvthfhe_pvss::keygen::dkg::DkgError;

    let error = DkgError::InvalidParams {
        party_id: Some(5),
        message: "test".to_owned(),
    };

    let error_str = format!("{}", error);
    assert!(
        error_str.contains('5'),
        "F8-1: DkgError should include party_id, got: {}",
        error_str
    );
}

// ---------------------------------------------------------------------------
// F9: deserialization validates curve points
// ---------------------------------------------------------------------------

/// F9-1: NonEquivSignature::from_bytes rejects an off-curve point.
/// Layout: signer_id [0..4] | rx [4..36] | ry [36..68] | s [68..100]; (0, 0)
/// is not on BN254 G1 (y² = x³ + 3).
#[test]
fn deserialization_should_validate_curve_point() {
    use pvthfhe_non_equiv::NonEquivSignature;

    let mut bytes = [0u8; 100];
    bytes[0..4].copy_from_slice(&1u32.to_be_bytes());

    let result = NonEquivSignature::from_bytes(&bytes);
    assert!(
        result.is_err(),
        "F9-1: off-curve point should be rejected during deserialization, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// F10: proof decoding returns errors, never panics or silently truncates
// ---------------------------------------------------------------------------

/// F10-1: verifying a keygen NIZK with a truncated proof returns an error
/// instead of panicking or succeeding.
#[test]
fn verify_should_return_error_on_truncated_proof() {
    use pvthfhe_pvss::nizk_keygen::{verify_keygen_nizk, KeygenNizkProof};

    let proof = KeygenNizkProof {
        proof_bytes: vec![1, 2, 3],
    };

    let result = verify_keygen_nizk(&[0u8; 32], &[0u8; 32], &proof, b"session", 1);
    assert!(
        result.is_err(),
        "F10-1: truncated proof should produce an error, got {:?}",
        result
    );
}
