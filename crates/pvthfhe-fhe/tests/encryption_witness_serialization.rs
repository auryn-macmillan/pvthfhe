#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Serialization roundtrip tests for [`EncryptionWitness`].
//!
//! Since [`EncryptionWitness`] intentionally does not implement `Serialize` or
//! `Deserialize` (it carries secret witness material), these tests verify that
//! the witness can be reconstructed from its individual byte fields — the
//! pattern used by other secret-bearing types in `pvthfhe-types`.

use pvthfhe_fhe::{fhers::FhersBackend, EncryptionWitness, FheBackend};
use rand::rngs::StdRng;
use rand::SeedableRng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn encryption_witness_field_roundtrip() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [99u8; 32];
    let mut rng = StdRng::seed_from_u64(0xfeed);

    let shares = (1u32..=3)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let plaintext = b"wire roundtrip test";

    let (_ct, witness) = backend
        .encrypt_with_witness(&pk, plaintext, &mut rng)
        .expect("encrypt_with_witness");

    // Reconstruct the witness from its individual byte fields.
    let reconstructed = EncryptionWitness {
        plaintext_poly_bytes: witness.plaintext_poly_bytes.clone(),
        u_poly_bytes: witness.u_poly_bytes.clone(),
        e0_poly_bytes: witness.e0_poly_bytes.clone(),
        e1_poly_bytes: witness.e1_poly_bytes.clone(),
        ct0_poly_bytes: witness.ct0_poly_bytes.clone(),
        ct1_poly_bytes: witness.ct1_poly_bytes.clone(),
        ciphertext_bytes: witness.ciphertext_bytes.clone(),
        recipient_pk0_bytes: witness.recipient_pk0_bytes.clone(),
        recipient_pk1_bytes: witness.recipient_pk1_bytes.clone(),
    };

    assert_eq!(
        witness, reconstructed,
        "witness must roundtrip through field reconstruction"
    );
    assert!(
        reconstructed.is_complete(),
        "reconstructed witness must be complete"
    );
}

#[test]
fn encryption_witness_field_bytes_are_non_empty() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [100u8; 32];
    let mut rng = StdRng::seed_from_u64(0xbeef);

    let shares = (1u32..=3)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");

    let (_ct, witness) = backend
        .encrypt_with_witness(&pk, b"non-empty check", &mut rng)
        .expect("encrypt_with_witness");

    // Each individual field must have reasonable minimum sizes.
    // For n=8192, log₂q=174, each Poly is ~3 * 8192 * 8 ≈ 196KB.
    // Allow a generous tolerance for different parameter sets.
    let min_poly_bytes: usize = 1024; // sanity floor: much less than expected

    assert!(witness.plaintext_poly_bytes.len() > min_poly_bytes);
    assert!(witness.u_poly_bytes.len() > min_poly_bytes);
    assert!(witness.e0_poly_bytes.len() > min_poly_bytes);
    assert!(witness.e1_poly_bytes.len() > min_poly_bytes);
    assert!(witness.ct0_poly_bytes.len() > min_poly_bytes);
    assert!(witness.ct1_poly_bytes.len() > min_poly_bytes);
    assert!(witness.ciphertext_bytes.len() > min_poly_bytes);
}
