//! R5.3 RED: compressor exposes srsHash() for on-chain commitment.
//!
//! This test must FAIL (compile error) against current main because
//! `NovaCompressor` has no `srs_hash()` method.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::NovaCompressor;
use pvthfhe_compressor::nova::ToyStepCircuit;

#[test]
fn srs_hash_method_exists_and_is_deterministic() {
    let epoch: [u8; 32] = [0x5Au8; 32];

    // RED: `new` does not accept `[u8; 32]` on main, and `srs_hash()` does not exist.
    let compressor =
        NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch, 4).expect("construct compressor");

    // srsHash() returns a 32-byte hash.
    let hash = compressor.srs_hash();
    assert_eq!(hash.len(), 32, "srsHash must be 32 bytes");

    // Same epoch → same srsHash (deterministic).
    let compressor2 =
        NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch, 4).expect("construct second compressor");
    assert_eq!(
        hash,
        compressor2.srs_hash(),
        "srsHash must be deterministic for same epoch"
    );

    // Different epoch → different srsHash.
    let other_epoch: [u8; 32] = [0x5Bu8; 32];
    let compressor3 = NovaCompressor::<ToyStepCircuit<Fr>>::new(other_epoch, 4)
        .expect("construct third compressor");
    assert_ne!(
        hash,
        compressor3.srs_hash(),
        "srsHash must differ for different epochs"
    );

    // srsHash is embedded in the verifier key.
    let vk = compressor.verifier_key();
    assert!(
        vk.srs_id.contains("srs"),
        "VerifierKey srs_id must reference the SRS"
    );
}

#[test]
fn srs_committed_onchain_contract_has_matching_hash() {
    // This test exists to assert that the srsHash() method is part of the
    // public API. The actual on-chain matching is tested in R6.
    let epoch: [u8; 32] = [0xAAu8; 32];
    let compressor =
        NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch, 4).expect("construct compressor");

    let _hash = compressor.srs_hash();
}
