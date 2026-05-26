//! Integration tests: decrypt_rejections.
#![allow(clippy::unwrap_used)]

use pvthfhe_aggregator::decrypt::{aggregate_decrypt, partial_decrypt, DecryptError};
use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};
use pvthfhe_types::ProtocolBytes;

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn rejects_malformed_share() {
    acknowledge_mock_backend();
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10").unwrap();
    let ct = Ciphertext {
        bytes: vec![1, 2, 3],
    };
    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];

    let party_pk = vec![0u8; 32];
    let mut share1 = partial_decrypt(
        &backend,
        &ct,
        1,
        &dkg_root,
        &ciphertext_hash,
        1,
        &party_pk,
        None,
        &mut rng,
    )
    .unwrap();
    share1.nizk = ProtocolBytes(vec![]);

    let share2 = partial_decrypt(
        &backend,
        &ct,
        2,
        &dkg_root,
        &ciphertext_hash,
        1,
        &party_pk,
        None,
        &mut rng,
    )
    .unwrap();

    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];

    let result = aggregate_decrypt(
        &backend,
        &ct,
        &[share1, share2],
        threshold,
        &allowed_parties,
        &dkg_root,
        &ciphertext_hash,
        "test-session",
        1,
    );

    assert!(matches!(
        result,
        Err(DecryptError::NizkVerify { party_id: 1 })
    ));
}

#[test]
fn rejects_insufficient_shares() {
    acknowledge_mock_backend();
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10").unwrap();
    let ct = Ciphertext {
        bytes: vec![1, 2, 3],
    };
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
        &mut rng,
    )
    .unwrap();

    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];

    let result = aggregate_decrypt(
        &backend,
        &ct,
        &[share1],
        threshold,
        &allowed_parties,
        &dkg_root,
        &ciphertext_hash,
        "test-session",
        1,
    );

    assert!(matches!(
        result,
        Err(DecryptError::InsufficientShares { needed: 2, got: 1 })
    ));
}

#[test]
fn rejects_duplicate_party() {
    acknowledge_mock_backend();
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10").unwrap();
    let ct = Ciphertext {
        bytes: vec![1, 2, 3],
    };
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
        &mut rng,
    )
    .unwrap();

    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];

    let result = aggregate_decrypt(
        &backend,
        &ct,
        &[share1.clone(), share1],
        threshold,
        &allowed_parties,
        &dkg_root,
        &ciphertext_hash,
        "test-session",
        1,
    );

    assert!(matches!(result, Err(DecryptError::DuplicateParty(1))));
}

#[test]
fn rejects_unknown_party() {
    acknowledge_mock_backend();
    let mut rng = rand::thread_rng();
    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10").unwrap();
    let ct = Ciphertext {
        bytes: vec![1, 2, 3],
    };
    let dkg_root = [0u8; 32];
    let ciphertext_hash = [0u8; 32];

    let party_pk = vec![0u8; 32];
    let share1 = partial_decrypt(
        &backend,
        &ct,
        4,
        &dkg_root,
        &ciphertext_hash,
        1,
        &party_pk,
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
        &mut rng,
    )
    .unwrap();

    let threshold = 2;
    let allowed_parties = vec![1, 2, 3];

    let result = aggregate_decrypt(
        &backend,
        &ct,
        &[share1, share2],
        threshold,
        &allowed_parties,
        &dkg_root,
        &ciphertext_hash,
        "test-session",
        1,
    );

    assert!(matches!(result, Err(DecryptError::UnknownParty(4))));
}
