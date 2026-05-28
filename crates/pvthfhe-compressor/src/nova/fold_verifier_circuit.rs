//! FoldVerifierStepCircuit — Nova step circuit for verifying compressed proofs.
//!
//! ## Status: DEFERRED (G.17, security review finding D.2)
//!
//! The current implementation is a **placeholder** — constraints only increment
//! state counters (`z[0] += 1`, `z[1] += ext.2`, `z[2] += 1`). Left/right accumulator
//! hashes are received as external inputs but **never verified** against any
//! folding relation.
//!
//! Real fold verification requires:
//! 1. Verify that external_inputs represent valid Nova accumulation of CycloFold proofs
//! 2. Check left/right accumulator hash consistency
//! 3. Enforce the Nova recurrence relation: H(z_i, w_i) = H(z_{i-1}, w_{i-1})
//! 4. Cross-circuit binding: the compressed C7 proof + CycloFold proof compose correctly
//!
//! This is deferred to the Interfold/composite IVC design phase (G.16).
//!
//! Recursive compression pipeline (compress_latticefold_tree) deferred to P3-M2.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(feature = "legacy-nova")]
use folding_schemes::frontend::FCircuit; // folding (legacy-nova)
use sha3::{Digest, Keccak256};

use pvthfhe_domain_tags::Tag;

use super::{ExternalInputs3, ExternalInputs3Var};
use crate::{StepCircuit, StepCircuitDescriptor};

/// Terminal verifier step circuit for LatticeFold+ folding.
///
/// State (3 elements):
///   z[0] = verified_count   number of fold steps verified so far
///   z[1] = running_hash      accumulated hash of parent commitments
///   z[2] = step_index        IVC step index (matches i parameter)
///
/// Per-step external inputs:
///   ext.0 = acc_left_hash        hash commitment to left accumulator
///   ext.1 = acc_right_hash       hash commitment to right accumulator
///   ext.2 = expected_parent_hash hash commitment to expected parent (folded) accumulator
///
/// In M1, the relation is a placeholder: the circuit verifies that external
/// inputs are present (non-trivial) and accumulates them into the running state.
/// Full Cyclo CCS R1CS encoding (including ∞-norm and ring-equation checks)
/// is deferred to M2.
#[derive(Clone, Copy, Debug)]
pub struct FoldVerifierStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for FoldVerifierStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> { // folding (legacy-nova)
        Ok(Self {
            _field: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // PLACEHOLDER — real fold verification is deferred (see G.17 / security review D.2).
        // These counter-only constraints ensure the circuit compiles and can be folded,
        // but provide ZERO actual verification of left/right accumulator hashes.

        // z'[0] = z[0] + 1                              (verified_count += 1)
        let verified_count = z_i[0].clone() + FpVar::constant(F::from(1u64));

        // z'[1] = z[1] + ext.2                          (running_hash += expected_parent_hash)
        let running_hash = z_i[1].clone() + external_inputs.2;

        // z'[2] = z[2] + 1                              (step_index += 1)
        let step_index = z_i[2].clone() + FpVar::constant(F::from(1u64));

        Ok(vec![verified_count, running_hash, step_index])
    }
}

impl<F: PrimeField> StepCircuit for FoldVerifierStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::PvssFoldVerifier.as_bytes()).into()
    }
}
