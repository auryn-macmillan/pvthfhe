//! P2-M5 LatticeFold+ to MicroNova integration tests.
//!
//! KNOWN_LIMITATION(latticefold-foldverifier): FoldVerifierStepCircuit does not
//! implement nova_snark::traits::circuit::StepCircuit and cannot be used with the
//! current NovaCompressor. The latticefold_accumulate_then_verify test is suspended
//! until FoldVerifierStepCircuit is ported to the nova-snark backend.
//!
//! KNOWN_LIMITATION(micronova-legacy-nova): MicroNovaCompressor requires the
//! legacy-nova feature and is Sonobe-specific. The latticefold_4_leaf_tree_to_root
//! test is suspended until MicroNovaCompressor is ported to nova-snark.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::{latticefold_hashes_to_inputs, ExternalInputs3};

// ── LatticeFold hashes-to-inputs sanity ─────────────────────────────────

#[test]
fn latticefold_hashes_to_inputs_produces_consistent_output() {
    let left = [1u8; 32];
    let right = [2u8; 32];
    let parent = [3u8; 32];
    let input1 = latticefold_hashes_to_inputs::<Fr>(&left, &right, &parent);
    let input2 = latticefold_hashes_to_inputs::<Fr>(&left, &right, &parent);
    assert_eq!(input1.0, input2.0);
    assert_eq!(input1.1, input2.1);
    assert_eq!(input1.2, input2.2);
}
