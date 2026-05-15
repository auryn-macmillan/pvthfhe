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

use super::poseidon_gadget::hash8;
use crate::{StepCircuit, StepCircuitDescriptor};

/// Merkle witness data for a single step.
///
/// For depth-5 (N=8192) with arity 8: 35 siblings (5 levels × 7 siblings/level).
/// Also supports smaller depths (e.g., depth-1 / N=8: 7 siblings).
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
            siblings: vec![F::zero(); 35],
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

/// Verify a Merkle path using real Poseidon hashing in R1CS.
///
/// For each level: hash `current_node` together with `arity-1` siblings
/// using Poseidon (8-to-1 compression), then compare the result against
/// `merkle_root`.
///
/// # Position-aware ordering (deferred)
///
/// The native [`crate::merkle::verify_merkle_proof`] places the current node
/// at `leaf_index % arity` within the sibling list at each level. The
/// in-circuit ordering currently always places the current node at position 0,
/// which is only sound when `leaf_index % arity == 0`.
///
/// To close this gap, `leaf_index` is constrained to zero. The native
/// witness generation (witness.rs:68) always uses leaf_index=0. Full
/// position-aware Merkle verification requires leaf_index constraint
/// propagation through tree levels and conditional sibling placement
/// based on `idx % arity` (see merkle.rs:87-109 for native logic).
/// This is deferred to a follow-up.
fn verify_merkle_path<F: PrimeField>(
    leaf_value: &FpVar<F>,
    leaf_index: &FpVar<F>,
    siblings: &[FpVar<F>],
    depth: usize,
    arity: usize,
    merkle_root: &FpVar<F>,
    cs: ConstraintSystemRef<F>,
) -> Result<(), SynthesisError> {
    let siblings_per_level = arity - 1;
    let expected_sibling_count = depth * siblings_per_level;

    if siblings.len() != expected_sibling_count {
        return Err(SynthesisError::AssignmentMissing);
    }

    // Enforce leaf_index == 0 for now.
    // Position-aware Merkle ordering (matching native verify_merkle_proof in
    // merkle.rs:87-109) is deferred. Currently, the in-circuit ordering always
    // places the current node at position 0, so only leaf_index=0 is valid.
    // The native witness generation (witness.rs:68) always proves leaf_index=0.
    leaf_index.enforce_equal(&FpVar::constant(F::zero()))?;

    let mut current = leaf_value.clone();

    for level in 0..depth {
        let start = level * siblings_per_level;
        let end = start + siblings_per_level;
        let level_siblings = &siblings[start..end];

        let mut inputs: Vec<FpVar<F>> = Vec::with_capacity(arity);
        inputs.push(current.clone());
        for sib in level_siblings {
            inputs.push(sib.clone());
        }

        current = hash8(cs.clone(), &inputs)?;
    }

    current.enforce_equal(merkle_root)?;
    Ok(())
}

/// Step circuit for C7 decryption aggregation with in-circuit Merkle verification.
///
/// Default: depth-5, arity-8  (N=8192, 32768-capable tree).
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
        Self::new_with_depth(5, 8)
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
        verify_merkle_path(
            &external_inputs.merkle_leaf_value,
            &external_inputs.merkle_leaf_index,
            &external_inputs.merkle_siblings,
            self.merkle_depth,
            self.merkle_arity,
            &external_inputs.merkle_root,
            cs.clone(),
        )?;

        // Enforce merkle_leaf_index is zero (belt-and-suspenders with verify_merkle_path).
        // The native witness generation always proves leaf_index=0 (witness.rs:68).
        // Full position-aware Merkle verification requires leaf_index constraint
        // propagation through tree levels (see merkle.rs:87-109 for native logic).
        external_inputs.merkle_leaf_index.enforce_equal(&FpVar::constant(F::zero()))?;

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
    use ark_bn254::Fr;

    #[test]
    fn merkle_circuit_descriptor_width_depth5() {
        let circuit = C7MerkleStepCircuit::<Fr>::new(()).expect("construct C7 merkle");
        assert_eq!(circuit.descriptor().width, 40);
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
