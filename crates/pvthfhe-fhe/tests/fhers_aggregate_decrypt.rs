//! Integration tests for threshold plaintext reconstruction in `FhersBackend`.

use pvthfhe_fhe::{fhers::FhersBackend, FheBackend, FheError};
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
fn fhers_aggregate_decrypt_happy_path() {
    let (backend, pk) = setup_backend();
    let mut rng = thread_rng();
    let ciphertext = backend.encrypt(&pk, b"42", &mut rng).expect("encrypt");
    let shares = [1u32, 3, 5]
        .into_iter()
        .map(|party_id| backend.partial_decrypt(&ciphertext, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("partial decrypt shares");

    let recovered = backend
        .aggregate_decrypt(&ciphertext, &shares, 3)
        .expect("aggregate decrypt");

    assert_eq!(recovered, b"42");
}

#[test]
fn fhers_aggregate_decrypt_insufficient_shares() {
    let (backend, pk) = setup_backend();
    let mut rng = thread_rng();
    let ciphertext = backend.encrypt(&pk, b"42", &mut rng).expect("encrypt");
    let shares = [2u32, 4]
        .into_iter()
        .map(|party_id| backend.partial_decrypt(&ciphertext, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("partial decrypt shares");

    let result = backend.aggregate_decrypt(&ciphertext, &shares, 3);

    assert_eq!(
        result,
        Err(FheError::InsufficientShares { have: 2, need: 3 })
    );
}

#[test]
fn fhers_aggregate_decrypt_all_shares() {
    let (backend, pk) = setup_backend();
    let mut rng = thread_rng();
    let ciphertext = backend.encrypt(&pk, b"42", &mut rng).expect("encrypt");
    let shares = (1u32..=5)
        .map(|party_id| backend.partial_decrypt(&ciphertext, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("partial decrypt shares");

    let recovered = backend
        .aggregate_decrypt(&ciphertext, &shares, 3)
        .expect("aggregate decrypt");

    assert_eq!(recovered, b"42");
}

#[test]
fn fhers_aggregate_decrypt_wrong_ciphertext() {
    let (backend, pk) = setup_backend();
    let mut rng = thread_rng();
    let ct_a = backend.encrypt(&pk, b"42", &mut rng).expect("encrypt ct_a");
    let ct_b = backend.encrypt(&pk, b"99", &mut rng).expect("encrypt ct_b");
    let share_a_1 = backend
        .partial_decrypt(&ct_a, 1, &mut rng)
        .expect("ct_a share 1");
    let share_a_2 = backend
        .partial_decrypt(&ct_a, 2, &mut rng)
        .expect("ct_a share 2");
    let share_b_3 = backend
        .partial_decrypt(&ct_b, 3, &mut rng)
        .expect("ct_b share 3");
    let mut share_b_3 = share_b_3;
    let mut decoded =
        pvthfhe_fhe::wire::decode_decrypt_share(&share_b_3.bytes).expect("decode share");
    let len = decoded.d_share_poly.len();
    decoded.d_share_poly[len - 1] ^= 0x01;
    share_b_3.bytes = pvthfhe_fhe::wire::encode_decrypt_share(&decoded.d_share_poly);

    let recovered = backend
        .aggregate_decrypt(&ct_b, &[share_a_1, share_a_2, share_b_3], 3)
        .expect("aggregate decrypt should produce garbled bytes");

    assert_ne!(recovered, b"42");
}
