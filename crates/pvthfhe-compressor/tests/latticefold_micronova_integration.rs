//! P2-M5 LatticeFold+ to MicroNova integration test.

use ark_bn254::Fr;
use pvthfhe_compressor::sonobe::{
    encode_triple, latticefold_hashes_to_inputs, FoldVerifierStepCircuit, SonobeCompressor,
};

#[test]
fn latticefold_accumulate_then_verify() {
    let epoch = [5u8; 32];
    let compressor = SonobeCompressor::<FoldVerifierStepCircuit<Fr>>::new(epoch, 1).unwrap();
    let left = [1u8; 32];
    let right = [2u8; 32];
    let parent = [3u8; 32];
    let inputs = vec![latticefold_hashes_to_inputs::<Fr>(&left, &right, &parent)];
    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let proof = compressor.prove_steps(&acc, &inputs).unwrap();
    let vk = compressor.verifier_key();
    assert!(compressor.verify_steps(&vk, &proof, &inputs).unwrap());
}
