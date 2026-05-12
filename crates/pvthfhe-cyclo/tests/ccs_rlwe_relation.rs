//! RED test: RLWE decryption-share relation encoding as CCS over R_q.
//!
//! Tests `encode_rlwe_share_relation(ciphertext, secret_key, error_poly, party_id)`
//! which encodes the relation `d_i = c · s_i + e_i` as a `CcsRqInstance`.
//! Valid witnesses satisfy; tampered witnesses are rejected by `check_satisfiability_rq`.
//!
//! These tests are initially **RED** (no implementation), then turn **GREEN**
//! after the real implementation is committed.

use pvthfhe_cyclo::ccs_encode::check_satisfiability_rq;
use pvthfhe_cyclo::ccs_rlwe::encode_rlwe_share_relation;
use pvthfhe_cyclo::ring::{ntt_mul, ring_add_poly, RqPoly, PHI_COMMIT, Q_COMMIT};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn random_poly(rng: &mut ChaCha20Rng) -> RqPoly {
    let coeffs: Vec<u64> = (0..PHI_COMMIT).map(|_| rng.next_u64() % Q_COMMIT).collect();
    RqPoly(coeffs)
}

fn one_poly() -> RqPoly {
    let mut coeffs = vec![0u64; PHI_COMMIT];
    coeffs[0] = 1;
    RqPoly(coeffs)
}

fn zero_poly() -> RqPoly {
    RqPoly(vec![0u64; PHI_COMMIT])
}

#[test]
fn valid_rlwe_share_satisfies() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let ciphertext = random_poly(&mut rng);
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);
    let party_id = 1u16;

    let instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
        .expect("encode_rlwe_share_relation should succeed");

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_ok(),
        "valid RLWE share (d_i = c·s_i + e_i) should satisfy CCS, got: {result:?}"
    );
}

#[test]
fn tampered_ciphertext_rejected() {
    let mut rng = ChaCha20Rng::from_seed([43u8; 32]);
    let ciphertext = random_poly(&mut rng);
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);
    let party_id = 1u16;

    let mut instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
        .expect("encode should succeed");

    let tampered_ct = random_poly(&mut rng);
    instance.witness[0] = tampered_ct;

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "tampered ciphertext should be rejected by CCS check"
    );
}

#[test]
fn tampered_secret_key_rejected() {
    let mut rng = ChaCha20Rng::from_seed([44u8; 32]);
    let ciphertext = random_poly(&mut rng);
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);
    let party_id = 2u16;

    let mut instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
        .expect("encode should succeed");

    let tampered_sk = random_poly(&mut rng);
    instance.witness[1] = tampered_sk;

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "tampered secret key should be rejected by CCS check"
    );
}

#[test]
fn tampered_error_poly_rejected() {
    let mut rng = ChaCha20Rng::from_seed([45u8; 32]);
    let ciphertext = random_poly(&mut rng);
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);
    let party_id = 3u16;

    let mut instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
        .expect("encode should succeed");

    let tampered_err = random_poly(&mut rng);
    instance.witness[2] = tampered_err;

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "tampered error polynomial should be rejected by CCS check"
    );
}

#[test]
fn tampered_decryption_share_rejected() {
    let mut rng = ChaCha20Rng::from_seed([46u8; 32]);
    let ciphertext = random_poly(&mut rng);
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);
    let party_id = 4u16;

    let mut instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
        .expect("encode should succeed");

    let tampered_di = random_poly(&mut rng);
    instance.witness[3] = tampered_di;

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "tampered decryption share should be rejected by CCS check"
    );
}

#[test]
fn multiple_valid_parties() {
    let mut rng = ChaCha20Rng::from_seed([47u8; 32]);

    for party_id in 1u16..=16u16 {
        let ciphertext = random_poly(&mut rng);
        let secret_key = random_poly(&mut rng);
        let error_poly = random_poly(&mut rng);

        let instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
            .expect("encode should succeed");

        let result = check_satisfiability_rq(&instance);
        assert!(
            result.is_ok(),
            "valid RLWE share for party {party_id} should satisfy CCS, got: {result:?}"
        );
    }
}

#[test]
fn zero_ciphertext_still_satisfies() {
    let mut rng = ChaCha20Rng::from_seed([48u8; 32]);
    let ciphertext = zero_poly();
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);
    let party_id = 1u16;

    let instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
        .expect("encode should succeed");

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_ok(),
        "RLWE share with zero ciphertext should still satisfy, got: {result:?}"
    );
}

#[test]
fn deterministic_encoding() {
    let mut rng = ChaCha20Rng::from_seed([49u8; 32]);
    let ciphertext = random_poly(&mut rng);
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);

    let instance1 = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, 1).unwrap();
    let instance2 = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, 1).unwrap();

    assert_eq!(instance1.ajtai_hash, instance2.ajtai_hash);
    assert_eq!(instance1.public_io_hash, instance2.public_io_hash);
    assert_eq!(
        instance1.matrix_data, instance2.matrix_data,
        "encode_rlwe_share_relation should be deterministic"
    );
    assert_eq!(
        instance1.m1_bytes, instance2.m1_bytes,
        "m1_bytes should be deterministic"
    );
    assert_eq!(
        instance1.m2_bytes, instance2.m2_bytes,
        "m2_bytes should be deterministic"
    );
    assert_eq!(
        instance1.m3_bytes, instance2.m3_bytes,
        "m3_bytes should be deterministic"
    );
    assert_eq!(instance1.witness, instance2.witness);
}

#[test]
fn tampered_residual_rejected() {
    let mut rng = ChaCha20Rng::from_seed([50u8; 32]);
    let ciphertext = random_poly(&mut rng);
    let secret_key = random_poly(&mut rng);
    let error_poly = random_poly(&mut rng);
    let party_id = 1u16;

    let mut instance = encode_rlwe_share_relation(&ciphertext, &secret_key, &error_poly, party_id)
        .expect("encode should succeed");

    // Index 4 is `one` in V2 layout — replacing with random poly breaks
    // the sanity row (random·random ≠ random) with overwhelming probability.
    instance.witness[4] = random_poly(&mut rng);

    let result = check_satisfiability_rq(&instance);
    assert!(
        result.is_err(),
        "tampered one (ex-residual) should be rejected by CCS check"
    );
}
