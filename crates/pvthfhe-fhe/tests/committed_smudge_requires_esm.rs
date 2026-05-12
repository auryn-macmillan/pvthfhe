//! TDD test suite for committed-smudge path (Batch B.3).
//!
//! RED state: these tests will NOT compile until `partial_decrypt_committed_smudge`
//! and `partial_decrypt_committed_smudge_with_witness` exist on `FheBackend`.
//!
//! GREEN state: after implementation:
//! - Test: empty `esm_noise_poly_bytes` is rejected with a clear error.
//! - Test: garbage/invalid `esm_noise_poly_bytes` is rejected.
//! - Test: valid committed-smudge decrypt succeeds and produces a `DecryptShare`.
//! - Test: witness from `_with_witness` has `esm_committed == true`.
//! - Test: committed-smudge `DecryptShare` bytes differ from fresh-local path.
//! - Test: witness faithfully records the provided esm bytes.

use fhe_math::rq::Poly;
use fhe_traits::DeserializeWithContext;
use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};
use rand::thread_rng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Helper: set up a FhersBackend with n=5,t=3, encrypt a message, return (backend, ciphertext).
fn setup_backend_and_ct() -> (FhersBackend, pvthfhe_fhe::Ciphertext) {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [42u8; 32];
    let mut rng = thread_rng();

    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend.setup_threshold(5, 3).expect("setup threshold");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let ciphertext = backend
        .encrypt(&pk, b"committed-smudge-test", &mut rng)
        .expect("encrypt");

    (backend, ciphertext)
}

// ── RED test 1: empty esm bytes must be rejected ────────────────────────────
#[test]
fn committed_smudge_rejects_empty_esm_bytes() {
    let (backend, ct) = setup_backend_and_ct();
    let mut rng = thread_rng();

    let result = backend.partial_decrypt_committed_smudge(
        &ct,
        1,
        &[], // empty esm bytes — should error
        &mut rng,
    );

    assert!(
        result.is_err(),
        "committed-smudge path must reject empty esm_noise_poly_bytes"
    );

    match result {
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("empty") || msg.contains("esm"),
                "error message must mention empty/esm, got: {e}"
            );
        }
        Ok(_) => unreachable!(),
    }
}

// ── RED test 2: garbage esm bytes must be rejected ──────────────────────────
#[test]
fn committed_smudge_rejects_garbage_esm_bytes() {
    let (backend, ct) = setup_backend_and_ct();
    let mut rng = thread_rng();

    // Provide bytes that cannot deserialize into a valid Poly
    let garbage = vec![0xFFu8; 128];

    let result = backend.partial_decrypt_committed_smudge(&ct, 1, &garbage, &mut rng);

    assert!(
        result.is_err(),
        "committed-smudge path must reject garbage esm bytes"
    );
}

// ── GREEN test 3: valid committed-smudge decrypt succeeds ───────────────────
#[test]
fn committed_smudge_with_valid_esm_succeeds() {
    let (backend, ct) = setup_backend_and_ct();
    let mut rng = thread_rng();

    // Produce a valid smudging noise polynomial by doing a normal
    // partial_decrypt_with_witness and extracting the esm bytes from it.
    let (_decrypt_share_fresh, fresh_witness) = backend
        .partial_decrypt_with_witness(&ct, 2, &mut rng)
        .expect("fresh with-witness");

    let esm_bytes = fresh_witness.esm_noise_poly_bytes.clone();
    assert!(
        !esm_bytes.is_empty(),
        "fresh witness must have non-empty esm bytes"
    );

    // Now use those esm bytes in the committed-smudge path
    let result = backend.partial_decrypt_committed_smudge(&ct, 2, &esm_bytes, &mut rng);

    assert!(
        result.is_ok(),
        "committed-smudge path must succeed with valid esm bytes"
    );

    let decrypt_share = result.unwrap();
    assert_eq!(decrypt_share.party_id, 2);
    assert!(!decrypt_share.bytes.is_empty());
}

// ── GREEN test 4: witness esm_committed == true ─────────────────────────────
#[test]
fn committed_smudge_witness_marks_esm_committed_true() {
    let (backend, ct) = setup_backend_and_ct();
    let mut rng = thread_rng();

    // Get a valid esm from the fresh path first
    let (_decrypt_share_fresh, fresh_witness) = backend
        .partial_decrypt_with_witness(&ct, 3, &mut rng)
        .expect("fresh with-witness");

    let esm_bytes = fresh_witness.esm_noise_poly_bytes.clone();

    // Use the committed-smudge witness path
    let (_decrypt_share, witness) = backend
        .partial_decrypt_committed_smudge_with_witness(&ct, 3, &esm_bytes, &mut rng)
        .expect("committed smudge with witness");

    assert!(
        witness.esm_committed,
        "committed-smudge witness must have esm_committed == true"
    );

    assert!(
        !witness.ct0_poly_bytes.is_empty(),
        "witness ct0 must be non-empty"
    );
    assert!(
        !witness.ct1_poly_bytes.is_empty(),
        "witness ct1 must be non-empty"
    );
    assert!(
        !witness.sk_agg_poly_bytes.is_empty(),
        "witness sk_agg must be non-empty"
    );
    assert!(
        !witness.esm_noise_poly_bytes.is_empty(),
        "witness esm must be non-empty"
    );
    assert!(
        !witness.d_share_poly_bytes.is_empty(),
        "witness d_share must be non-empty"
    );
    assert!(
        !witness.decrypted_share_bytes.is_empty(),
        "witness decrypted_share must be non-empty"
    );
}

// ── GREEN test 5: witness faithfully records provided esm ──────────────────
#[test]
fn committed_smudge_witness_records_provided_esm_bytes() {
    let (backend, ct) = setup_backend_and_ct();
    let mut rng = thread_rng();

    // Get a valid esm polynomial bytes from fresh path
    let (_decrypt_share_fresh, fresh_witness) = backend
        .partial_decrypt_with_witness(&ct, 4, &mut rng)
        .expect("fresh with-witness");

    let esm_bytes = fresh_witness.esm_noise_poly_bytes.clone();

    // Committed smudge with witness
    let (_decrypt_share, witness) = backend
        .partial_decrypt_committed_smudge_with_witness(&ct, 4, &esm_bytes, &mut rng)
        .expect("committed smudge with witness");

    // The witness must record exactly the esm we provided
    assert_eq!(
        witness.esm_noise_poly_bytes, esm_bytes,
        "witness must faithfully record the provided esm bytes"
    );
}

// ── GREEN test 6: committed-smudge bytes differ from fresh-local ────────────
#[test]
fn committed_smudge_produces_different_bytes_than_fresh_local() {
    let (backend, ct) = setup_backend_and_ct();
    let mut rng = thread_rng();

    // Fresh local path: partial_decrypt samples its own noise
    let decrypt_share_fresh = backend
        .partial_decrypt(&ct, 5, &mut rng)
        .expect("fresh partial decrypt");

    // Get the esm noise bytes from a different fresh call (different rng state)
    let (_ds, fresh_witness) = backend
        .partial_decrypt_with_witness(&ct, 1, &mut rng)
        .expect("fresh witness for esm");

    let esm_bytes = fresh_witness.esm_noise_poly_bytes.clone();

    // Committed-smudge path uses those exact esm bytes
    let decrypt_share_committed = backend
        .partial_decrypt_committed_smudge(&ct, 5, &esm_bytes, &mut rng)
        .expect("committed smudge decrypt");

    // The bytes MUST differ because:
    // - The fresh path samples new Gaussian noise via RNG (different each call)
    // - The committed path uses the exact esm bytes we provided
    // - Even if the esm bytes came from an earlier fresh call, the rng state
    //   has advanced, so the fresh call to party 5 uses different noise than
    //   the esm we captured for party 1.
    assert_ne!(
        decrypt_share_fresh.bytes.as_slice(),
        decrypt_share_committed.bytes.as_slice(),
        "committed-smudge DecryptShare bytes must differ from fresh-local path (different noise)"
    );

    // Also verify both deserialize to valid Polys
    let ctx = backend
        .bfv_params()
        .ctx_at_level(0)
        .expect("level-0 context");

    for share_bytes in [&decrypt_share_fresh.bytes, &decrypt_share_committed.bytes] {
        let decoded = wire::decode_decrypt_share(share_bytes).expect("decode decrypt share");
        let _poly = Poly::from_bytes(decoded.d_share_poly.as_slice(), &ctx)
            .expect("deserialize share poly");
    }
}

// ── RED test 7: witness mismatch detection (api-level check) ───────────────
///
/// Verify that if someone accidentally uses a different esm than what was
/// committed, the witness faithfully records the *actual* esm used, making
/// the mismatch detectable by an external check.
#[test]
fn committed_smudge_witness_detects_esm_mismatch_at_api_level() {
    let (backend, ct) = setup_backend_and_ct();
    let mut rng = thread_rng();

    // Capture two different esm noise polynomials from fresh decryptions
    let (_ds1, w1) = backend
        .partial_decrypt_with_witness(&ct, 1, &mut rng)
        .expect("fresh witness 1");

    let (_ds2, w2) = backend
        .partial_decrypt_with_witness(&ct, 2, &mut rng)
        .expect("fresh witness 2");

    let esm_a = w1.esm_noise_poly_bytes.clone();
    let esm_b = w2.esm_noise_poly_bytes.clone();

    // esm_a and esm_b should be different (different rng state)
    assert_ne!(
        esm_a, esm_b,
        "different fresh calls should produce different esm noise"
    );

    // Use esm_a with the committed-smudge witness path for party 1
    let (_ds_a, witness_a) = backend
        .partial_decrypt_committed_smudge_with_witness(&ct, 1, &esm_a, &mut rng)
        .expect("committed smudge with esm_a");

    // Witness must contain exactly esm_a (the one we provided)
    assert_eq!(
        witness_a.esm_noise_poly_bytes, esm_a,
        "witness must reflect the actual esm used"
    );
    assert_ne!(
        witness_a.esm_noise_poly_bytes, esm_b,
        "witness must NOT silently substitute a different esm"
    );

    // Conversely: provide esm_b but expect esm_a — witness records esm_b
    let (_ds_b, witness_b) = backend
        .partial_decrypt_committed_smudge_with_witness(&ct, 2, &esm_b, &mut rng)
        .expect("committed smudge with esm_b");

    assert_eq!(witness_b.esm_noise_poly_bytes, esm_b);
    // Mismatch against a hypothetical "expected esm" is detectable:
    assert_ne!(witness_b.esm_noise_poly_bytes, esm_a);
}
