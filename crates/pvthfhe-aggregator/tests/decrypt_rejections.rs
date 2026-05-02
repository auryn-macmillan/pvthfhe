#![allow(clippy::unwrap_used)]

use pvthfhe_aggregator::decrypt::{aggregate_decrypt, partial_decrypt, DecryptError};
use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};

#[test]
fn rejects_malformed_share() {
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536").unwrap();
    let ct = Ciphertext { bytes: vec![1, 2, 3] };
    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];
    
    let mut share1 = partial_decrypt(&backend, &ct, 1, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    share1.nizk.clear();
    
    let share2 = partial_decrypt(&backend, &ct, 2, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    
    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];
    
    let result = aggregate_decrypt(&backend, &ct, &[share1, share2], threshold, &allowed_parties, &dkg_root, &ciphertext_hash, 1);
    
    assert!(matches!(result, Err(DecryptError::InvalidShare { party_id: 1 })));
}

#[test]
fn rejects_insufficient_shares() {
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536").unwrap();
    let ct = Ciphertext { bytes: vec![1, 2, 3] };
    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];
    
    let share1 = partial_decrypt(&backend, &ct, 1, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    
    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];
    
    let result = aggregate_decrypt(&backend, &ct, &[share1], threshold, &allowed_parties, &dkg_root, &ciphertext_hash, 1);
    
    assert!(matches!(result, Err(DecryptError::InsufficientShares { needed: 2, got: 1 })));
}

#[test]
fn rejects_duplicate_party() {
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536").unwrap();
    let ct = Ciphertext { bytes: vec![1, 2, 3] };
    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];
    
    let share1 = partial_decrypt(&backend, &ct, 1, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    
    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];
    
    let result = aggregate_decrypt(&backend, &ct, &[share1.clone(), share1], threshold, &allowed_parties, &dkg_root, &ciphertext_hash, 1);
    
    assert!(matches!(result, Err(DecryptError::DuplicateParty(1))));
}

#[test]
fn rejects_unknown_party() {
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536").unwrap();
    let ct = Ciphertext { bytes: vec![1, 2, 3] };
    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];
    
    let share1 = partial_decrypt(&backend, &ct, 4, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    let share2 = partial_decrypt(&backend, &ct, 2, &dkg_root, &ciphertext_hash, 1, &mut rng).unwrap();
    
    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];
    
    let result = aggregate_decrypt(&backend, &ct, &[share1, share2], threshold, &allowed_parties, &dkg_root, &ciphertext_hash, 1);
    
    assert!(matches!(result, Err(DecryptError::UnknownParty(4))));
}
