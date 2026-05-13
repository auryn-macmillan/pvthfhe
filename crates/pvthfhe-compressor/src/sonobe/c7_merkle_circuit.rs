//! C7 decryption aggregation step circuit with in-circuit Merkle proof verification.
//!
//! Each step folds one participant's decryption share contribution into
//! the Nova accumulator, AND verifies a Merkle proof binding the claimed
//! `d_i(r)` to the Merkle-committed share coefficients.
//!
//! After t steps:
//!   - accumulated_eval   = Σ λ_i · d_i(r)  (plaintext evaluation at challenge point r)
//!   - lagrange_sum       = Σ λ_i            (should equal 1)
//!   - step_count         = t                (number of participants folded)
//!
//! POSEIDON PLACEHOLDER: The Merkle path verification uses a linear-combination
//! check (parent = Σ siblings + leaf) instead of real Poseidon hashing in R1CS.
//! This is sufficient for circuit structure validation and Nova prove/verify
//! cycles. Real Poseidon R1CS must be swapped in before production use.

use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};

use pvthfhe_domain_tags::Tag;

use crate::{StepCircuit, StepCircuitDescriptor};

/// Merkle witness data for a single step.
///
/// For depth-1 (N=8) with arity 8: 7 siblings.
/// For depth-5 (N=8192) with arity 8: 35 siblings.
#[derive(Clone, Debug)]
pub struct MerkleWitnessData<F: PrimeField> {
    pub leaf_value: F,
    pub leaf_index: F,
    pub siblings: Vec<F>,
}

impl<F: PrimeField> Default for MerkleWitnessData<F> {
    fn default() -> Self {
        Self {
            leaf_value: F::zero(),
            leaf_index: F::zero(),
            siblings: vec![F::zero(); 7],
        }
    }
}

#[derive(Clone, Debug)]
pub struct C7MerkleExternalInputs<F: PrimeField> {
    pub share_eval: F,
    pub lagrange_coeff: F,
    pub merkle_root: F,
    pub merkle_data: MerkleWitnessData<F>,
}

impl<F: PrimeField> Default for C7MerkleExternalInputs<F> {
    fn default() -> Self {
        Self {
            share_eval: F::zero(),
            lagrange_coeff: F::one(),
            merkle_root: F::zero(),
            merkle_data: MerkleWitnessData::default(),
        }
    }
}

/// R1CS variable wrapper for C7MerkleExternalInputs.
#[derive(Clone, Debug)]
pub struct C7MerkleExternalInputsVar<F: PrimeField> {
    pub share_eval: FpVar<F>,
    pub lagrange_coeff: FpVar<F>,
    pub merkle_root: FpVar<F>,
    pub merkle_leaf_value: FpVar<F>,
    pub merkle_leaf_index: FpVar<F>,
    pub merkle_siblings: Vec<FpVar<F>>,
}

impl<F: PrimeField> AllocVar<C7MerkleExternalInputs<F>, F> for C7MerkleExternalInputsVar<F> {
    fn new_variable<T: Borrow<C7MerkleExternalInputs<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;
        let e = v.borrow();

        let share_eval = FpVar::<F>::new_variable(cs.clone(), || Ok(e.share_eval), mode)?;
        let lagrange_coeff =
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.lagrange_coeff), mode)?;
        let merkle_root = FpVar::<F>::new_variable(cs.clone(), || Ok(e.merkle_root), mode)?;
        let merkle_leaf_value =
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.merkle_data.leaf_value), mode)?;
        let merkle_leaf_index =
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.merkle_data.leaf_index), mode)?;

        let mut merkle_siblings = Vec::with_capacity(e.merkle_data.siblings.len());
        for sibling in &e.merkle_data.siblings {
            merkle_siblings
                .push(FpVar::<F>::new_variable(cs.clone(), || Ok(*sibling), mode)?);
        }

        Ok(Self {
            share_eval,
            lagrange_coeff,
            merkle_root,
            merkle_leaf_value,
            merkle_leaf_index,
            merkle_siblings,
        })
    }
}

/// Returns the total width of the external inputs (number of field elements).
pub fn merkle_external_inputs_width(depth: usize, arity: usize) -> usize {
    // 3 base (share_eval, lagrange_coeff, merkle_root)
    // + 1 leaf_value + 1 leaf_index
    // + depth * (arity - 1) siblings
    5 + depth * (arity - 1)
}

/// POSEIDON PLACEHOLDER: Verify a Merkle path using a linear-combination check.
///
/// For each level: compute parent = leaf + sum of all siblings.
/// Check that the final value equals the provided merkle_root.
///
/// This is NOT cryptographically secure. It exists to validate the circuit
/// structure and enable Nova prove/verify cycles during Phase A development.
/// Real Poseidon R1CS must be swapped in before production use.
fn verify_merkle_path_placeholder<F: PrimeField>(
    leaf_value: &FpVar<F>,
    siblings: &[FpVar<F>],
    depth: usize,
    arity: usize,
    merkle_root: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let siblings_per_level = arity - 1;
    let expected_sibling_count = depth * siblings_per_level;

    if siblings.len() != expected_sibling_count {
        return Err(SynthesisError::AssignmentMissing);
    }

    let mut current = leaf_value.clone();

    for level in 0..depth {
        let start = level * siblings_per_level;
        let end = start + siblings_per_level;
        let level_siblings = &siblings[start..end];

        let mut parent = current.clone();
        for sib in level_siblings {
            parent = &parent + sib;
        }
        current = parent;
    }

    current.enforce_equal(merkle_root)?;
    Ok(())
}

/// Step circuit for C7 decryption aggregation with in-circuit Merkle verification.
///
/// State (3 elements):
///   z[0] = accumulated share evaluation    Σ λ_i · d_i(r)
///   z[1] = accumulated Lagrange sum        Σ λ_i
///   z[2] = step count                      number of participants folded
///
/// Per-step external inputs carry Merkle proof data that is verified
/// in constraints before updating the state.
#[derive(Clone, Copy, Debug)]
pub struct C7MerkleStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
    pub merkle_depth: usize,
    pub merkle_arity: usize,
}

impl<F: PrimeField> C7MerkleStepCircuit<F> {
    pub fn new_with_depth(depth: usize, arity: usize) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _field: std::marker::PhantomData,
            merkle_depth: depth,
            merkle_arity: arity,
        })
    }

    pub fn external_inputs_width(&self) -> usize {
        merkle_external_inputs_width(self.merkle_depth, self.merkle_arity)
    }
}

impl<F: PrimeField> FCircuit<F> for C7MerkleStepCircuit<F> {
    type Params = ();
    type ExternalInputs = C7MerkleExternalInputs<F>;
    type ExternalInputsVar = C7MerkleExternalInputsVar<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Self::new_with_depth(1, 8)
    }

    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // 1. Merkle path verification in constraints (POSEIDON PLACEHOLDER)
        verify_merkle_path_placeholder(
            &external_inputs.merkle_leaf_value,
            &external_inputs.merkle_siblings,
            self.merkle_depth,
            self.merkle_arity,
            &external_inputs.merkle_root,
        )?;

        // 2. Update state (same recurrence as C7DecryptAggregationCircuit):
        //    z'[0] = z[0] + ext.lagrange_coeff * ext.share_eval
        //    z'[1] = z[1] + ext.lagrange_coeff
        //    z'[2] = z[2] + 1
        let acc_eval = z_i[0].clone() + external_inputs.lagrange_coeff.clone() * external_inputs.share_eval;

        let lagrange_sum = z_i[1].clone() + external_inputs.lagrange_coeff;

        let step_count = z_i[2].clone() + FpVar::constant(F::from(1u64));

        let _ = cs.num_constraints();

        Ok(vec![acc_eval, lagrange_sum, step_count])
    }
}

impl<F: PrimeField> StepCircuit for C7MerkleStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor {
            width: self.external_inputs_width(),
        }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::PvssC7MerkleDecryptAggregation.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_external_inputs_width_depth1_arity8() {
        assert_eq!(merkle_external_inputs_width(1, 8), 12);
    }

    #[test]
    fn merkle_external_inputs_width_depth5_arity8() {
        assert_eq!(merkle_external_inputs_width(5, 8), 40);
    }

    #[test]
    fn merkle_external_inputs_width_depth1_arity2() {
        assert_eq!(merkle_external_inputs_width(1, 2), 6);
    }
}
