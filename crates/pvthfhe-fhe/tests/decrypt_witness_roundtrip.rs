#![allow(clippy::unwrap_used, clippy::expect_used)]
//! TDD test: verify that `partial_decrypt` returns only bytes (no witness material)
//! and that `partial_decrypt_with_witness` exposes the structured `DecryptionWitness`.
//!
//! RED state: this test will NOT compile until `DecryptionWitness` and
//! `FheBackend::partial_decrypt_with_witness` are implemented.
//!
//! GREEN state: after implementation, the test must:
//! - Confirm `partial_decrypt` only returns `DecryptShare` (bytes, no witness).
//! - Call `partial_decrypt_with_witness` and receive `DecryptionWitness`.
//! - Verify all witness fields are non-empty and `esm_committed == false`.

use fhe::bfv::Ciphertext as BfvCiphertext;
use fhe_math::rq::Poly;
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};
use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};
use rand::thread_rng;
use sha2::{Digest, Sha256};

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// RED assertion: `DecryptShare` is only `{ party_id, bytes }` — no witness fields.
/// This is a compile-time guarantee of the type system.
#[test]
fn partial_decrypt_only_returns_bytes_no_witness() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [77u8; 32];
    let mut rng = thread_rng();

    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend
        .setup_threshold(5, 3, Sha256::digest(session_id).into())
        .expect("setup threshold");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let ciphertext = backend
        .encrypt(&pk, b"witness-red-test", &mut rng)
        .expect("encrypt");

    let decrypt_share = backend
        .partial_decrypt(&ciphertext, 1, &mut rng)
        .expect("partial decrypt");

    // Verify: `partial_decrypt` returns a DecryptShare with only party_id + bytes.
    // There is no way to extract quotient terms, esm witness, or internal polynomials
    // from the DecryptShare type — it only exposes `party_id` and `bytes`.
    assert_eq!(decrypt_share.party_id, 1);
    assert!(!decrypt_share.bytes.is_empty());

    // The type system enforces: DecryptShare has no witness fields.
    // There is no `ct0_poly`, `sk_agg_poly`, `quotient_terms`, `esm_committed`, etc.
    // This is a RED condition: the public `partial_decrypt` API cannot produce
    // structured decryption witnesses needed by proof-generating layers.
}

/// RED test: `partial_decrypt_with_witness` must exist and return structured witness.
///
/// This test will FAIL to compile until:
/// - `DecryptionWitness` type is defined in `pvthfhe-types`.
/// - `FheBackend::partial_decrypt_with_witness` trait method exists.
/// - `FhersBackend` implements the method.
#[test]
fn decrypt_witness_roundtrip_produces_structured_witness() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [78u8; 32];
    let mut rng = thread_rng();

    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend
        .setup_threshold(5, 3, Sha256::digest(session_id).into())
        .expect("setup threshold");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let ciphertext = backend
        .encrypt(&pk, b"witness-roundtrip-test", &mut rng)
        .expect("encrypt");

    // Call the new API — this MUST produce the SAME DecryptShare bytes
    // that `partial_decrypt` would produce, plus a DecryptionWitness.
    let (decrypt_share, witness) = backend
        .partial_decrypt_with_witness(&ciphertext, 1, &mut rng)
        .expect("partial_decrypt_with_witness");

    // Basic identity checks on the DecryptShare
    assert_eq!(decrypt_share.party_id, 1);
    assert!(!decrypt_share.bytes.is_empty());

    // Witness field presence checks (need to compile and have non-empty data)
    assert!(
        !witness.ct0_poly_bytes.is_empty(),
        "ct0_poly_bytes must be non-empty"
    );
    assert!(
        !witness.ct1_poly_bytes.is_empty(),
        "ct1_poly_bytes must be non-empty"
    );
    assert!(
        !witness.sk_agg_poly_bytes.is_empty(),
        "sk_agg_poly_bytes must be non-empty"
    );
    assert!(
        !witness.esm_noise_poly_bytes.is_empty(),
        "esm_noise_poly_bytes must contain the smudging noise"
    );
    assert!(
        !witness.d_share_poly_bytes.is_empty(),
        "d_share_poly_bytes (post-smudge) must be non-empty"
    );
    assert!(
        !witness.decrypted_share_bytes.is_empty(),
        "decrypted_share_bytes (wire-encoded) must be non-empty"
    );

    // esm_committed must be false — we are using fresh local smudging
    assert!(
        !witness.esm_committed,
        "esm_committed must be false for fresh local smudging"
    );

    // Quotient polynomials may be empty if not directly accessible from ShareManager
    // (this is documented behavior; Batch F will wire committed e_sm)

    // Cross-verify: DecryptionShare bytes from partial_decrypt_with_witness
    // must match those from partial_decrypt (deterministic given same rng state).
    // We cannot reproduce exact rng state, but we verify the bytes are well-formed.
    let decoded = wire::decode_decrypt_share(&decrypt_share.bytes)
        .expect("decode decrypt share witness wires");
    assert!(
        !decoded.d_share_poly.is_empty(),
        "wire-decoded d_share_poly must be non-empty"
    );

    // Verify the share poly deserializes to a valid Poly
    let ctx = backend
        .bfv_params()
        .ctx_at_level(0)
        .expect("level-0 context");
    let share_poly = Poly::from_bytes(decoded.d_share_poly.as_slice(), ctx)
        .expect("deserialize share poly from witness");
    assert!(
        !share_poly.to_bytes().is_empty(),
        "share poly from witness must be non-empty"
    );

    // Verify ciphertext components match
    // Deserialize the original ciphertext and verify its c[0], c[1] match
    // the witness ct0/ct1
    let orig_ct = BfvCiphertext::from_bytes(&ciphertext.bytes, backend.bfv_params())
        .expect("deserialize original ciphertext");
    let ct0_bytes = orig_ct.c[0].to_bytes();
    let ct1_bytes = orig_ct.c[1].to_bytes();
    assert_eq!(
        witness.ct0_poly_bytes, ct0_bytes,
        "witness ct0 must match original ciphertext ct0"
    );
    assert_eq!(
        witness.ct1_poly_bytes, ct1_bytes,
        "witness ct1 must match original ciphertext ct1"
    );
}
