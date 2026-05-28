#![cfg(feature = "legacy-nova")]
//! R5.2 RED: CycloFoldStepCircuit encodes the R4 fold relation (not toy z+ext).
//!
//! This test must FAIL (compile error) against current main because
//! CycloFoldStepCircuit does not exist yet.

use ark_bn254::Fr;
use folding_schemes::frontend::FCircuit; // folding (legacy-nova)
use pvthfhe_compressor::nova::CycloFoldStepCircuit;
use pvthfhe_compressor::StepCircuit;

#[test]
fn cyclo_fold_step_circuit_exists_and_has_cyclic_fold_state_width() {
    // RED: CycloFoldStepCircuit type does not exist on main.
    let circuit = CycloFoldStepCircuit::<Fr>::new(()).expect("construct cyclo fold step circuit");

    // Cyclo fold relation has wider state than the toy step circuit (width 1).
    let desc = circuit.descriptor();
    assert!(
        desc.width > 1,
        "CycloFoldStepCircuit must have state width > 1, got {}",
        desc.width
    );

    // Circuit hash must use the CycloFold tag, not the toy-step tag.
    let hash = circuit.circuit_hash();
    assert_ne!(hash, [0u8; 32], "circuit_hash must be non-zero");
}
