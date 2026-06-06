//! M5 RED→GREEN: Greyhound PCS challenge binds session_id and prover_id.
//!
//! Verifies that `derive_challenge` produces different challenges when
//! session_id or prover_id differ, even with identical protocol data
//! (commitment_u, v, x, y). This prevents cross-session and cross-prover
//! challenge replay attacks.

#![cfg(feature = "enable-greyhound")]

use ark_bn254::Fr;
use ark_ff::Zero;
use pvthfhe_compressor::nova::greyhound_pcs::{derive_challenge, GreyhoundPCS, GreyhoundParamSet};

fn make_test_params() -> pvthfhe_compressor::nova::greyhound_pcs::GreyhoundParams {
    let srs_hash = [0x42u8; 32];
    let param_set = GreyhoundParamSet::small();
    GreyhoundPCS::setup(&srs_hash, &param_set)
}

#[test]
fn different_session_ids_produce_different_challenges() {
    let params = make_test_params();
    let n = params.n;

    let commitment_u = vec![Fr::zero(); n];
    let v = vec![Fr::zero(); n];
    let x = Fr::from(42u64);
    let y = Fr::from(99u64);

    let challenge_a = derive_challenge(&params, &commitment_u, &v, &x, &y, "session-alpha", 1);
    let challenge_b = derive_challenge(&params, &commitment_u, &v, &x, &y, "session-beta", 1);

    assert!(!challenge_a.is_empty(), "challenge_a must not be empty");
    assert!(!challenge_b.is_empty(), "challenge_b must not be empty");
    assert_ne!(
        challenge_a, challenge_b,
        "different session_ids must produce different challenges"
    );
}

#[test]
fn different_prover_ids_produce_different_challenges() {
    let params = make_test_params();
    let n = params.n;

    let commitment_u = vec![Fr::zero(); n];
    let v = vec![Fr::zero(); n];
    let x = Fr::from(42u64);
    let y = Fr::from(99u64);

    let challenge_a = derive_challenge(&params, &commitment_u, &v, &x, &y, "shared", 1);
    let challenge_b = derive_challenge(&params, &commitment_u, &v, &x, &y, "shared", 2);

    assert!(!challenge_a.is_empty(), "challenge_a must not be empty");
    assert!(!challenge_b.is_empty(), "challenge_b must not be empty");
    assert_ne!(
        challenge_a, challenge_b,
        "different prover_ids must produce different challenges"
    );
}

#[test]
fn identical_session_and_prover_produce_identical_challenges() {
    let params = make_test_params();
    let n = params.n;

    let commitment_u = vec![Fr::zero(); n];
    let v = vec![Fr::zero(); n];
    let x = Fr::from(42u64);
    let y = Fr::from(99u64);

    let challenge_a = derive_challenge(&params, &commitment_u, &v, &x, &y, "det", 7);
    let challenge_b = derive_challenge(&params, &commitment_u, &v, &x, &y, "det", 7);

    assert_eq!(
        challenge_a, challenge_b,
        "identical inputs must produce identical challenges (deterministic)"
    );
}
