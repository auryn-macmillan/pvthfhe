//! MicroNova heterogeneous IVC tests (MN.4).
//!
//! Tests the [`HeterogeneousCircuitFamily`] trait, the
//! [`LatticeFoldTreeCircuitFamily`], and the [`HeterogeneousStepCircuit`]
//! integrated with [`SonobeCompressor`].

use ark_bn254::Fr;
use ark_ff::Zero;
use pvthfhe_compressor::sonobe::{
    encode_triple, heterogeneous::HeterogeneousCircuitFamily,
    latticefold_circuit_family::LatticeFoldTreeCircuitFamily, ExternalInputs3,
    HeterogeneousStepCircuit, SonobeCompressor,
};

// Helper: call trait methods with concrete Fr type to resolve the generic F.
fn num_circuits(family: &LatticeFoldTreeCircuitFamily) -> usize {
    <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::num_circuits(family)
}
fn circuit_index(family: &LatticeFoldTreeCircuitFamily, i: usize) -> usize {
    <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::circuit_index(family, i)
}

#[test]
fn heterogeneous_two_circuit_family() {
    let family = LatticeFoldTreeCircuitFamily { depth: 2 };
    assert_eq!(num_circuits(&family), 2);
    // Internal nodes: 0,1,2 (leaf_start = 3) → circuit 1
    assert_eq!(circuit_index(&family, 0), 1);
    assert_eq!(circuit_index(&family, 1), 1);
    assert_eq!(circuit_index(&family, 2), 1);
    // Leaf nodes: 3,4,5,6 → circuit 0
    assert_eq!(circuit_index(&family, 3), 0);
    assert_eq!(circuit_index(&family, 6), 0);
}

#[test]
fn heterogeneous_two_level_tree_folds() {
    // Depth=2 tree: 3 internal + 4 leaves = 7 total nodes.
    // We use 3 steps (just the internal nodes for a simple demo).
    let family = LatticeFoldTreeCircuitFamily { depth: 2 };
    HeterogeneousStepCircuit::<Fr>::set_family(family);

    let compressor = SonobeCompressor::<HeterogeneousStepCircuit<Fr>>::new([1u8; 32], 3).unwrap();
    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero()));
    let steps: Vec<ExternalInputs3<Fr>> = (0..3)
        .map(|i| ExternalInputs3(Fr::from(1u64), Fr::from((i + 1) as u64), Fr::zero()))
        .collect();
    let proof = compressor.prove_steps(&acc, &steps).unwrap();
    let vk = compressor.verifier_key();
    assert!(compressor.verify_steps(&vk, &proof, &steps).unwrap());
}

#[test]
fn heterogeneous_leaf_vs_internal_differ() {
    let family = LatticeFoldTreeCircuitFamily { depth: 2 };
    let h0 =
        <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::circuit_hash(&family, 0);
    let h1 =
        <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::circuit_hash(&family, 1);
    assert_ne!(h0, h1);
}

#[test]
fn heterogeneous_depth_three_tree_folds() {
    // Depth=3 tree: 7 internal + 8 leaves = 15 total nodes.
    // 7 steps exercises the heterogeneous dispatch.
    let family = LatticeFoldTreeCircuitFamily { depth: 3 };
    HeterogeneousStepCircuit::<Fr>::set_family(family);

    let compressor = SonobeCompressor::<HeterogeneousStepCircuit<Fr>>::new([2u8; 32], 7).unwrap();
    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero()));
    let steps: Vec<ExternalInputs3<Fr>> = (0..7)
        .map(|i| ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from((i + 1) as u64)))
        .collect();
    let proof = compressor.prove_steps(&acc, &steps).unwrap();
    let vk = compressor.verifier_key();
    assert!(compressor.verify_steps(&vk, &proof, &steps).unwrap());
}

#[test]
fn heterogeneous_depth_four_tree_folds() {
    // Depth=4 tree: 15 internal + 16 leaves = 31 total nodes.
    // 15 steps exercises the heterogeneous dispatch.
    let family = LatticeFoldTreeCircuitFamily { depth: 4 };
    HeterogeneousStepCircuit::<Fr>::set_family(family);

    let compressor = SonobeCompressor::<HeterogeneousStepCircuit<Fr>>::new([3u8; 32], 15).unwrap();
    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero()));
    let steps: Vec<ExternalInputs3<Fr>> = (0..15)
        .map(|i| ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from((i + 1) as u64)))
        .collect();
    let proof = compressor.prove_steps(&acc, &steps).unwrap();
    let vk = compressor.verifier_key();
    assert!(compressor.verify_steps(&vk, &proof, &steps).unwrap());
}

#[test]
fn heterogeneous_num_circuits_depth_zero() {
    let family = LatticeFoldTreeCircuitFamily { depth: 0 };
    assert_eq!(num_circuits(&family), 1);
}

#[test]
fn heterogeneous_num_circuits_depth_one() {
    let family = LatticeFoldTreeCircuitFamily { depth: 1 };
    assert_eq!(num_circuits(&family), 2);
}
