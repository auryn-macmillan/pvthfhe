//! MicroNova heterogeneous IVC tests (MN.4).
//!
//! Tests the [`HeterogeneousCircuitFamily`] trait and the
//! [`LatticeFoldTreeCircuitFamily`].
//!
//! KNOWN_LIMITATION(heterogeneous-nova): HeterogeneousStepCircuit does not
//! implement nova_snark::traits::circuit::StepCircuit and cannot be used with
//! the current NovaCompressor. The fold tests (two_level_tree_folds,
//! depth_three_tree_folds, depth_four_tree_folds) are suspended until
//! HeterogeneousStepCircuit is ported to the nova-snark backend.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::{
    heterogeneous::HeterogeneousCircuitFamily,
    latticefold_circuit_family::LatticeFoldTreeCircuitFamily,
};

// Helper: call trait methods with concrete Fr type to resolve the generic F.
fn num_circuits(family: &LatticeFoldTreeCircuitFamily) -> usize {
    <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::num_circuits(family)
}
fn circuit_index(family: &LatticeFoldTreeCircuitFamily, i: usize) -> usize {
    <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::circuit_index(family, i)
}

#[test]
fn heterogeneous_num_circuits_depth_one() {
    let family = LatticeFoldTreeCircuitFamily { depth: 1 };
    // Always 3 circuits: leaf, internal, lagrange
    assert_eq!(num_circuits(&family), 3);
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
fn heterogeneous_num_circuits_depth_zero() {
    let family = LatticeFoldTreeCircuitFamily { depth: 0 };
    assert_eq!(num_circuits(&family), 1);
}

#[test]
fn heterogeneous_two_circuit_family() {
    let family = LatticeFoldTreeCircuitFamily { depth: 2 };
    // LatticeFoldTreeCircuitFamily always has 3 circuits regardless of depth:
    // 0 = leaf, 1 = internal, 2 = lagrange
    assert_eq!(num_circuits(&family), 3);
    assert_eq!(circuit_index(&family, 0), 0);
    assert_eq!(circuit_index(&family, 1), 1);
    assert_eq!(circuit_index(&family, 2), 2);
}
