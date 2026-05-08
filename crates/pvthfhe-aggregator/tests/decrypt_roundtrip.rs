//! Integration tests: decrypt_roundtrip.
#![allow(clippy::unwrap_used)]

use pvthfhe_aggregator::decrypt::{aggregate_decrypt, partial_decrypt};
use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};
use serde_json::Value;
use std::fs;

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => unreachable!("{ctx}: {e:?}"),
    }
}

#[test]
fn decrypt_roundtrip_golden() {
    acknowledge_mock_backend();
    let vector_str = ok(
        fs::read_to_string("../../crates/pvthfhe-core/tests/vectors/vector_01.json"),
        "Failed to read golden vector",
    );
    let vector: Value = serde_json::from_str(&vector_str).unwrap();

    let plaintext_hex = vector["plaintext"].as_str().unwrap();
    let expected_plaintext = hex::decode(plaintext_hex).unwrap();

    let ct_hex = vector["ciphertext"].as_str().unwrap();
    let ct = Ciphertext {
        bytes: hex::decode(ct_hex).unwrap(),
    };

    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10").unwrap();

    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];

    let share1 =
        partial_decrypt(&backend, &ct, 1, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    let share2 =
        partial_decrypt(&backend, &ct, 2, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();

    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];

    let recovered = aggregate_decrypt(
        &backend,
        &ct,
        &[share1, share2],
        threshold,
        &allowed_parties,
        &dkg_root,
        &ciphertext_hash,
        1,
    )
    .unwrap();

    assert_eq!(recovered, expected_plaintext);
}
