//! A proofless decrypt share must be rejected (R10 hardening).
//!
//! `partial_decrypt` with no secret-key material yields a payload whose NIZK
//! field is empty; `aggregate_decrypt` must refuse it with
//! `DecryptError::NizkVerify` instead of releasing plaintext.
#![allow(clippy::unwrap_used)]

use pvthfhe_aggregator::decrypt::{aggregate_decrypt, partial_decrypt, DecryptError};
use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};
use serde_json::Value;
use std::fs;

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn decrypt_rejects_proofless_share() {
    acknowledge_mock_backend();
    let vector_str = fs::read_to_string("../../crates/pvthfhe-tests/tests/vectors/vector_01.json")
        .expect("read golden vector");
    let vector: Value = serde_json::from_str(&vector_str).unwrap();

    let ct_hex = vector["ciphertext"].as_str().unwrap();
    let ct = Ciphertext {
        bytes: hex::decode(ct_hex).unwrap(),
    };

    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10").unwrap();

    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];
    let party_pk = vec![0u8; 32];
    let share1 = partial_decrypt(
        &backend,
        &ct,
        1,
        &dkg_root,
        &ciphertext_hash,
        1,
        &party_pk,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    let share2 = partial_decrypt(
        &backend,
        &ct,
        2,
        &dkg_root,
        &ciphertext_hash,
        1,
        &party_pk,
        None,
        None,
        &mut rng,
    )
    .unwrap();

    assert!(
        share1.nizk.is_empty(),
        "share produced without secret key material must carry an empty NIZK"
    );

    let result = aggregate_decrypt(
        &backend,
        &ct,
        &[share1, share2],
        2,
        &[1, 2, 3],
        &dkg_root,
        &ciphertext_hash,
        "test-session",
        1,
    );

    assert!(
        matches!(result, Err(DecryptError::NizkVerify { party_id: 1 })),
        "proofless share must be rejected with NizkVerify, got {result:?}"
    );
}
