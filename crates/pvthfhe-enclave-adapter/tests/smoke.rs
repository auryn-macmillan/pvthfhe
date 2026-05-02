#![allow(clippy::unwrap_used)]
#![cfg(feature = "stub")]

use pvthfhe_enclave_adapter::{
    EnclaveAggregator, EnclaveCiphernode, EnclaveCiphertext, EnclaveKeyShare,
    PvthfheEnclaveAggregator, PvthfheEnclaveCiphernode,
};
use pvthfhe_fhe::{mock::MockBackend, FheBackend};

const TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\n";

#[test]
fn smoke_ciphernode_generate_key_share() {
    let backend = MockBackend::load_params(TOML).unwrap();
    let node = PvthfheEnclaveCiphernode::new(backend, 0);
    let mut rng = rand::thread_rng();
    let share = node.generate_key_share(&mut rng);
    assert!(share.is_ok(), "generate_key_share failed: {:?}", share.err());
}

#[test]
fn smoke_aggregator_aggregate_keys() {
    let backend = MockBackend::load_params(TOML).unwrap();
    let agg = PvthfheEnclaveAggregator::new(backend, 3);

    let shares: Vec<EnclaveKeyShare> = (0u32..3)
        .map(|i| EnclaveKeyShare(i.to_le_bytes().to_vec()))
        .collect();

    let pk = agg.aggregate_keys(&shares);
    assert!(pk.is_ok(), "aggregate_keys failed: {:?}", pk.err());
}

#[test]
fn smoke_aggregator_aggregate_decrypt() {
    let backend = MockBackend::load_params(TOML).unwrap();
    let agg = PvthfheEnclaveAggregator::new(backend, 3);

    let ct = EnclaveCiphertext(vec![0xAB, 0xCD, 0xEF, 0x00]);
    let shares: Vec<pvthfhe_enclave_adapter::EnclaveDecryptShare> = (0u32..3)
        .map(|i| pvthfhe_enclave_adapter::EnclaveDecryptShare(i.to_le_bytes().to_vec()))
        .collect();

    let result = agg.aggregate_decrypt(&ct, &shares);
    assert!(
        result.is_ok(),
        "aggregate_decrypt failed: {:?}",
        result.err()
    );
}
