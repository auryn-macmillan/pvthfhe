#![cfg(feature = "legacy-nova")]
//! P2-M5 LatticeFold+ to MicroNova integration tests.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::{
    encode_triple, latticefold_hashes_to_inputs, ExternalInputs3, FoldVerifierStepCircuit,
    NovaCompressor,
};

#[test]
fn latticefold_accumulate_then_verify() {
    let epoch = [5u8; 32];
    let compressor = NovaCompressor::<FoldVerifierStepCircuit<Fr>>::new(epoch, 1).unwrap();
    let left = [1u8; 32];
    let right = [2u8; 32];
    let parent = [3u8; 32];
    let inputs = vec![latticefold_hashes_to_inputs::<Fr>(&left, &right, &parent)];
    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let proof = compressor.prove_steps(&acc, &inputs).unwrap();
    let vk = compressor.verifier_key();
    assert!(compressor.verify_steps(&vk, &proof, &inputs).unwrap());
}

#[test]
fn latticefold_4_leaf_tree_to_root() {
    // Build a 4-leaf tree, fold all levels through heterogeneous IVC,
    // and verify the root proof.
    use ark_ff::PrimeField;
    use pvthfhe_compressor::micronova::compressor::MicroNovaCompressor;
    use sha2::{Digest, Sha256};

    let leaves: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let depth = 2;
    let total_nodes = 7;

    // Compute parent hashes bottom-up.
    let mut hasher = Sha256::new();
    hasher.update(&leaves[0]);
    hasher.update(&leaves[1]);
    let p0: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(&leaves[2]);
    hasher.update(&leaves[3]);
    let p1: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(&p0);
    hasher.update(&p1);
    let root: [u8; 32] = hasher.finalize().into();

    // Build level-order steps: root, P0, P1, leaves.
    let mut steps: Vec<ExternalInputs3<Fr>> = Vec::with_capacity(total_nodes);

    // Root node (internal): children are P0, P1.
    steps.push(latticefold_hashes_to_inputs::<Fr>(&p0, &p1, &root));

    // P0 (internal): children are leaves[0], leaves[1].
    steps.push(latticefold_hashes_to_inputs::<Fr>(
        &leaves[0], &leaves[1], &p0,
    ));

    // P1 (internal): children are leaves[2], leaves[3].
    steps.push(latticefold_hashes_to_inputs::<Fr>(
        &leaves[2], &leaves[3], &p1,
    ));

    // Leaves (circuit 0): ext.0=ext.1=1, ext.2=leaf_hash.
    for leaf in &leaves {
        steps.push(ExternalInputs3(
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from_be_bytes_mod_order(leaf),
        ));
    }

    let epoch = [5u8; 32];
    let compressor = MicroNovaCompressor::new(depth, epoch);
    let proof = compressor.prove_tree(&steps).unwrap();
    assert!(compressor.verify_tree(&proof, &steps).unwrap());
}
