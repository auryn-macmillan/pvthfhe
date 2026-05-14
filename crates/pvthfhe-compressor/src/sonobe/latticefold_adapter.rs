//! P2-M5 LatticeFold+ to MicroNova adapter.
//!
//! Converts LatticeFold+ accumulator hashes into FoldVerifierStepCircuit
//! external inputs, bridging the LatticeFold+ folding pipeline (P2) to the
//! MicroNova compression pipeline (P3).

use ark_ff::PrimeField;

use super::ExternalInputs3;

/// Convert LatticeFold+ accumulator hashes to FoldVerifierStepCircuit external inputs.
///
/// Each input: (acc_left_hash, acc_right_hash, expected_parent_hash) as Fr elements.
/// The underlying field is BN254 Fr, but the function is generic over any `PrimeField`.
pub fn latticefold_hashes_to_inputs<F: PrimeField>(
    left_hash: &[u8; 32],
    right_hash: &[u8; 32],
    parent_hash: &[u8; 32],
) -> ExternalInputs3<F> {
    let l = F::from_be_bytes_mod_order(left_hash);
    let r = F::from_be_bytes_mod_order(right_hash);
    let p = F::from_be_bytes_mod_order(parent_hash);
    ExternalInputs3(l, r, p)
}
