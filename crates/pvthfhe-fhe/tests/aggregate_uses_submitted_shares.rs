#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Regression test for F67: `aggregate_decrypt` MUST reject submitted
//! decrypt-share envelopes that are bound to a different ciphertext.
//!
//! A share polynomial produced for one ciphertext is structurally valid, so a
//! recombination-only path can fail nondeterministically by decoding garbage.
//! The v2 decrypt-share wire envelope binds `party_id` and `SHA256(ct.bytes)`
//! so cross-ciphertext substitution is rejected deterministically before any
//! recombination.

use pvthfhe_fhe::{fhers::FhersBackend, FheBackend, FheError};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn setup_backend() -> (FhersBackend, pvthfhe_fhe::PublicKey) {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [51u8; 32];
    let mut rng = ChaCha8Rng::seed_from_u64(0xF67A_0001);
    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend
        .setup_threshold(5, 3, Sha256::digest(session_id).into())
        .expect("setup threshold");
    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    (backend, pk)
}

#[test]
fn aggregate_must_use_submitted_shares_not_internal_state() {
    let (backend, pk) = setup_backend();
    let mut rng = ChaCha8Rng::seed_from_u64(0xF67A_0002);
    let ct_hello = backend
        .encrypt(&pk, b"hello", &mut rng)
        .expect("encrypt hello");
    let ct_other = backend
        .encrypt(&pk, b"OTHER", &mut rng)
        .expect("encrypt other");

    let share1 = backend
        .partial_decrypt(&ct_hello, 1, &mut rng)
        .expect("share 1 for hello");
    let share2 = backend
        .partial_decrypt(&ct_hello, 2, &mut rng)
        .expect("share 2 for hello");
    let share3_other = backend
        .partial_decrypt(&ct_other, 3, &mut rng)
        .expect("share 3 for other");

    let tampered_share3 = share3_other.clone();

    let result = backend.aggregate_decrypt(&ct_hello, &[share1, share2, tampered_share3], 3, b"");

    assert!(
        matches!(
            result,
            Err(FheError::DecryptShareContextMismatch {
                party_id: 3,
                field: "ct_hash"
            })
        ),
        "F67: expected deterministic ct_hash mismatch for share3 from a different ciphertext: {result:?}"
    );
}
