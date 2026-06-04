#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Roundtrip tests for [`EncryptionWitness`] returned by
//! [`FheBackend::encrypt_with_witness`].
//!
//! These tests verify that the witness material matches the ciphertext and is
//! non-empty. They use the real `FhersBackend` over the canonical BFV parameters.

use fhe::bfv::Ciphertext as BfvCiphertext;
use fhe_traits::{DeserializeParametrized, Serialize};
use pvthfhe_fhe::{fhers::FhersBackend, EncryptionWitness, FheBackend};
use rand::rngs::StdRng;
use rand::SeedableRng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn encrypt_with_witness_returns_extended_material() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [42u8; 32];
    let mut rng = StdRng::seed_from_u64(0xdead);

    let shares = (1u32..=3)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let plaintext = b"hello witness roundtrip";

    let (ct, witness) = backend
        .encrypt_with_witness(&pk, plaintext, &mut rng)
        .expect("encrypt_with_witness should succeed");

    // 1. Ciphertext bytes must be non-empty and match canonical serialization.
    assert!(!ct.bytes.is_empty(), "ciphertext bytes should be non-empty");
    assert_eq!(
        ct.bytes, witness.ciphertext_bytes,
        "ciphertext from opaque type must match witness canonical bytes"
    );

    // 2. All witness polynomial bytes must be non-empty.
    assert!(
        witness.is_complete(),
        "witness must have all fields populated"
    );

    // 3. The ciphertext must parse correctly and have 2 polys.
    let bfv_ct =
        BfvCiphertext::from_bytes(&ct.bytes, backend.bfv_params()).expect("deserialize ciphertext");
    assert_eq!(bfv_ct.c.len(), 2, "fresh BFV ct must have 2 polys");

    // 4. The ct0 and ct1 polynomial bytes in the witness must match the
    //    ciphertext's internal polynomials.
    let ct0_bytes = bfv_ct.get(0).expect("ct0 poly").to_bytes();
    let ct1_bytes = bfv_ct.get(1).expect("ct1 poly").to_bytes();
    assert_eq!(
        witness.ct0_poly_bytes, ct0_bytes,
        "witness ct0 must match ciphertext ct0"
    );
    assert_eq!(
        witness.ct1_poly_bytes, ct1_bytes,
        "witness ct1 must match ciphertext ct1"
    );

    // 5. The u_poly, e0_poly, e1_poly, and plaintext_poly bytes must all be
    //    non-empty (they were witnessed during encryption).
    assert!(
        !witness.u_poly_bytes.is_empty(),
        "u polynomial must be non-empty"
    );
    assert!(
        !witness.e0_poly_bytes.is_empty(),
        "e0 polynomial must be non-empty"
    );
    assert!(
        !witness.e1_poly_bytes.is_empty(),
        "e1 polynomial must be non-empty"
    );
    assert!(
        !witness.plaintext_poly_bytes.is_empty(),
        "plaintext polynomial must be non-empty"
    );
}

#[test]
fn encrypt_with_witness_uses_same_pk_as_normal_encrypt() {
    // Regression: ciphertext obtained via encrypt_with_witness must be
    // semantically compatible with the ciphertext from the ordinary `encrypt`.
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [43u8; 32];
    let mut rng_for_keys = StdRng::seed_from_u64(0xbee);

    let shares = (1u32..=3)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng_for_keys))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let plaintext = b"compat check";

    // Use two independent seeded RNGs from the same seed to get identical
    // randomness streams for the witness and normal paths.
    let seed: u64 = 0xcafe;
    let mut rng_witness = StdRng::seed_from_u64(seed);
    let mut rng_normal = StdRng::seed_from_u64(seed);

    let (ct_witness, _witness) = backend
        .encrypt_with_witness(&pk, plaintext, &mut rng_witness)
        .expect("encrypt_with_witness");

    let ct_normal = backend
        .encrypt(&pk, plaintext, &mut rng_normal)
        .expect("encrypt");

    // With identical randomness, the ciphertext bytes must match.
    assert_eq!(
        ct_witness.bytes, ct_normal.bytes,
        "ciphertexts from encrypt_with_witness and encrypt must match"
    );
}

#[test]
fn witness_debug_redacts_content() {
    // The Debug output must not leak polynomial bytes.
    let witness = EncryptionWitness {
        plaintext_poly_bytes: vec![1, 2, 3],
        u_poly_bytes: vec![4, 5, 6],
        e0_poly_bytes: vec![7, 8, 9],
        e1_poly_bytes: vec![10, 11, 12],
        ct0_poly_bytes: vec![13, 14, 15],
        ct1_poly_bytes: vec![16, 17, 18],
        ciphertext_bytes: vec![19, 20, 21],
        recipient_pk0_bytes: vec![22, 23, 24],
        recipient_pk1_bytes: vec![25, 26, 27],
    };
    let debug_str = format!("{witness:?}");
    assert!(
        !debug_str.contains("1, 2, 3"),
        "Debug must not leak plaintext polynomial bytes"
    );
    assert!(
        !debug_str.contains("4, 5, 6"),
        "Debug must not leak u polynomial bytes"
    );
    assert!(
        debug_str.contains("EncryptionWitness"),
        "Debug should mention the type name"
    );
}
