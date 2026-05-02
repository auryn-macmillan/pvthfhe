#![allow(clippy::unwrap_used)]

use pvthfhe_aggregator::decrypt::{aggregate_decrypt, partial_decrypt};
use pvthfhe_fhe::{mock::MockBackend, types::{Ciphertext}, FheBackend};
use std::fs;
use serde_json::Value;

#[test]
fn decrypt_roundtrip_golden() {
    let vector_str = fs::read_to_string("../../crates/pvthfhe-core/tests/vectors/vector_01.json")
        .expect("Failed to read golden vector");
    let vector: Value = serde_json::from_str(&vector_str).unwrap();

    let plaintext_hex = vector["plaintext"].as_str().unwrap();
    let expected_plaintext = hex::decode(plaintext_hex).unwrap();

    let ct_hex = vector["ciphertext"].as_str().unwrap();
    let ct = Ciphertext { bytes: hex::decode(ct_hex).unwrap() };

    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536").unwrap();
    
    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];
    
    let share1 = partial_decrypt(&backend, &ct, 1, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    let share2 = partial_decrypt(&backend, &ct, 2, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    
    let threshold = 2;
    let allowed_parties = vec![0, 1, 2];
    
    let recovered = aggregate_decrypt(&backend, &ct, &[share1, share2], threshold, &allowed_parties, &dkg_root, &ciphertext_hash, 1).unwrap();
    
    assert_eq!(recovered, expected_plaintext);
}
