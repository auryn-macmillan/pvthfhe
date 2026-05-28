#![cfg(feature = "legacy-nova")]
//! R5.3 RED: SRS is bound to on-chain epoch, not a seed: u64.
//!
//! This test must FAIL (compile error) against current main because
//! `NovaCompressor::new` takes `_seed: u64`, not `epoch_hash: [u8; 32]`.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::NovaCompressor;
use pvthfhe_compressor::nova::ToyStepCircuit;
use pvthfhe_compressor::ProofCompressor;

#[test]
fn srs_is_derived_from_epoch_hash_not_seed() {
    // RED: `new` does not accept `[u8; 32]` on main, only `u64` seed.
    let epoch_a: [u8; 32] = [0xA0u8; 32];
    let epoch_b: [u8; 32] = [0xB0u8; 32];

    let comp_a = NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch_a, 4)
        .expect("construct compressor with epoch_a");
    let comp_b = NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch_b, 4)
        .expect("construct compressor with epoch_b");

    // Different epochs must produce different verifier keys (SRS is epoch-bound).
    assert_ne!(
        comp_a.vk_bytes(),
        comp_b.vk_bytes(),
        "Different epochs must produce different SRS"
    );

    // Same epoch must produce identical verifier keys (deterministic SRS).
    let comp_a2 = NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch_a, 4)
        .expect("construct second compressor with epoch_a");
    assert_eq!(
        comp_a.vk_bytes(),
        comp_a2.vk_bytes(),
        "Same epoch must produce identical SRS"
    );
}

#[test]
fn new_does_not_accept_seed_u64() {
    // RED: this test simply verifies that the new signature has changed.
    // On current main, new(42u64) compiles, new([0u8; 32], 4) does not.
    // This is verified by the test above failing to compile.
}
