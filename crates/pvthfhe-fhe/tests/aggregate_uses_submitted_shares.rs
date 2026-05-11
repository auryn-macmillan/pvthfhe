//! RED test for F67: `aggregate_decrypt` MUST consume submitted shares,
//! not silently recompute from internal state by `party_id`.
//!
//! On current `main`, `fhers.rs:680-691` parses submitted shares, discards them,
//! and recomputes from internal state. This test provides shares from a
//! DIFFERENT ciphertext (valid wire format + valid polynomial) and asserts
//! `aggregate_decrypt` FAILS. Currently the function succeeds because
//! internal state is used — which is the F67 vulnerability.

use pvthfhe_fhe::wire;
use pvthfhe_fhe::{fhers::FhersBackend, FheBackend};
use rand::thread_rng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn setup_backend() -> (FhersBackend, pvthfhe_fhe::PublicKey) {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [51u8; 32];
    let mut rng = thread_rng();
    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend.setup_threshold(5, 3).expect("setup threshold");
    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    (backend, pk)
}

#[test]
fn aggregate_must_use_submitted_shares_not_internal_state() {
    let (backend, pk) = setup_backend();
    let mut rng = thread_rng();
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

    let mut decoded = wire::decode_decrypt_share(&share3_other.bytes).expect("decode share3");
    let len = decoded.d_share_poly.len();
    decoded.d_share_poly[len - 1] ^= 0x01;
    let mut tampered_share3 = share3_other.clone();
    tampered_share3.bytes =
        wire::encode_decrypt_share(decoded.d_share_poly.as_slice()).into();

    let result = backend.aggregate_decrypt(
        &ct_hello,
        &[share1, share2, tampered_share3],
        3,
    );

    // RED assertion: submitted share3 is from ct_other (+ byte flip).
    // Valid wire format, valid Poly — validation at fhers.rs:664-679 passes.
    // But internal-state recomputation at fhers.rs:680-691 silently uses
    // party_id=3 internal state for ct_hello, ignoring submitted data.
    //
    // On current main, this ASSERTION FAILS — function returns Ok("hello").
    assert!(
        result.is_err(),
        "F67: aggregate_decrypt returned Ok even though share3 was from \
         a different ciphertext (+ byte flip). Got: {:?}. \
         This confirms fhers.rs:680-691 silently recomputes shares from \
         internal state by party_id instead of using submitted share bytes.",
        result
    );
}
