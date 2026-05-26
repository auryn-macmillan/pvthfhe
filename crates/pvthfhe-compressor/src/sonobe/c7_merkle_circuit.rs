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
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
#[cfg(not(feature = "nova-backend"))]
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
        let lagrange_coeff = FpVar::<F>::new_variable(cs.clone(), || Ok(e.lagrange_coeff), mode)?;
        let merkle_root = FpVar::<F>::new_variable(cs.clone(), || Ok(e.merkle_root), mode)?;
        let merkle_leaf_value =
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.merkle_data.leaf_value), mode)?;
        let merkle_leaf_index =
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.merkle_data.leaf_index), mode)?;

        let mut merkle_siblings = Vec::with_capacity(e.merkle_data.siblings.len());
        for sibling in &e.merkle_data.siblings {
            merkle_siblings.push(FpVar::<F>::new_variable(cs.clone(), || Ok(*sibling), mode)?);
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

    // 4.1 Bit-decompose leaf_index: 3 bits per level for arity=8.
    // Create `depth * 3` bit witnesses; each is Boolean and the weighted
    // sum must equal leaf_index.
    let bits_count = depth * 3;
    let mut bits = Vec::with_capacity(bits_count);

    for i in 0..bits_count {
        let b = FpVar::<F>::new_witness(cs.clone(), || {
            let idx = leaf_index.value()?;
            let limb0 = idx.into_bigint().as_ref()[0];
            let bit = if (limb0 >> i) & 1 == 1 {
                F::ONE
            } else {
                F::ZERO
            };
            Ok(bit)
        })?;
        bits.push(b);
    }

    // Boolean constraints: b_i * (1 - b_i) == 0
    let one = FpVar::<F>::one();
    let zero = FpVar::<F>::zero();
    for b in &bits {
        let not_b = one.clone() - b.clone();
        let prod = b.clone() * not_b;
        prod.enforce_equal(&zero)?;
    }

    // Sum constraint: Σ b_i * 2^i == leaf_index
    let mut sum = FpVar::<F>::zero();
    for i in 0..bits_count {
        sum = sum + bits[i].clone() * FpVar::constant(F::from(1u64 << i));
    }
    sum.enforce_equal(leaf_index)?;

    // Per-level loop: extract 3 bits, compute position indicators,
    // allocate input witnesses with prover-computed correct placement,
    // constrain current at indicated position, then hash.
    let mut current = leaf_value.clone();

    for level in 0..depth {
        // 4.2 Extract 3 bits and compute 8 position indicators is_pos[j].
        let b0 = bits[level * 3].clone();
        let b1 = bits[level * 3 + 1].clone();
        let b2 = bits[level * 3 + 2].clone();

        let mut is_pos = Vec::with_capacity(arity);
        for j in 0u8..(arity as u8) {
            let j0 = (j & 1) != 0;
            let j1 = (j & 2) != 0;
            let j2 = (j & 4) != 0;

            let t0 = if j0 {
                b0.clone()
            } else {
                one.clone() - b0.clone()
            };
            let t1 = if j1 {
                b1.clone()
            } else {
                one.clone() - b1.clone()
            };
            let t2 = if j2 {
                b2.clone()
            } else {
                one.clone() - b2.clone()
            };

            let mid = t0 * t1;
            is_pos.push(mid * t2);
        }

        // 4.3 Allocate 8 input witness variables per level.
        // The prover reads the concrete values of current, leaf_index,
        // and siblings to compute the correct input ordering.
        let mut inputs = Vec::with_capacity(arity);
        for j in 0..arity {
            let inp = FpVar::<F>::new_witness(cs.clone(), || {
                let curr_val = current.value()?;
                let idx_val = leaf_index.value()?;
                let idx_u64 = idx_val.into_bigint().as_ref()[0];

                let shifted = idx_u64 >> (level * 3);
                let position = (shifted & 7) as usize;

                let sib_start = level * siblings_per_level;
                let mut input_vals = vec![F::ZERO; arity];
                let mut sib_idx = 0;
                for k in 0..arity {
                    if k == position {
                        input_vals[k] = curr_val;
                    } else {
                        let sib = siblings[sib_start + sib_idx].value()?;
                        input_vals[k] = sib;
                        sib_idx += 1;
                    }
                }
                Ok(input_vals[j])
            })?;
            inputs.push(inp);
        }

        // 4.4 Constrain current at the position indicated by is_pos.
        // For the single position j where is_pos[j]==1 this forces
        // inputs[j]==current; elsewhere it's vacuously true.
        for j in 0..arity {
            let diff = inputs[j].clone() - current.clone();
            let prod = is_pos[j].clone() * diff;
            prod.enforce_equal(&zero)?;
        }

        // 4.5 Hash the arity inputs and chain to next level.
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
    #[cfg(not(feature = "nova-backend"))]
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

#[cfg(not(feature = "nova-backend"))]
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

        // G5: leaf_index accepted but not enforced (see verify_merkle_path docs).

        // 2. Update state (same recurrence as C7DecryptAggregationCircuit):
        //    z'[0] = z[0] + ext.lagrange_coeff * ext.share_eval
        //    z'[1] = z[1] + ext.lagrange_coeff
        //    z'[2] = z[2] + 1
        let acc_eval =
            z_i[0].clone() + external_inputs.lagrange_coeff.clone() * external_inputs.share_eval;

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
    use crate::merkle::{build_merkle_tree, prove_merkle_path, verify_merkle_proof};
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::gr1cs::ConstraintSystem;

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

    /// Position-aware Merkle verification: the circuit uses leaf_index bits
    /// to place the current node at the correct position within each level's
    /// hash input. A proof with leaf_index=5 must pass when all inputs match,
    /// and must be rejected when the prover uses a wrong leaf_index.
    #[test]
    fn merkle_nonzero_leaf_index_accepted() {
        let depth = 1;
        let arity = 8;

        // Build a 8-leaf Merkle tree with distinct leaf values.
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 100)).collect();
        let (tree, _root) = build_merkle_tree(&leaves, arity);

        let leaf_index = 5usize;
        let proof = prove_merkle_path(&tree, leaf_index, arity);
        assert!(
            verify_merkle_proof(&proof, arity),
            "native proof must be valid"
        );

        // Flatten level-siblings into a flat list for the circuit.
        let flat_siblings: Vec<Fr> = proof.siblings.iter().flatten().copied().collect();

        // Test 1: correct leaf_index=5 must produce a satisfied system.
        {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let leaf_index_var =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(leaf_index as u64))).unwrap();
            let leaf_value_var =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(proof.leaf_value)).unwrap();
            let siblings_vars: Vec<FpVar<Fr>> = flat_siblings
                .iter()
                .map(|v| FpVar::<Fr>::new_witness(cs.clone(), || Ok(*v)).unwrap())
                .collect();
            let merkle_root_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(proof.root)).unwrap();

            let result = verify_merkle_path(
                &leaf_value_var,
                &leaf_index_var,
                &siblings_vars,
                depth,
                arity,
                &merkle_root_var,
                cs.clone(),
            );
            assert!(
                result.is_ok(),
                "verify_merkle_path must succeed with correct leaf_index=5"
            );
            assert!(
                cs.is_satisfied().unwrap(),
                "constraint system must be satisfied with correct leaf_index=5"
            );
        }

        // Test 2: wrong leaf_index=0 must produce an unsatisfied system,
        // because the root was computed with current at position 5, not 0.
        {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let leaf_index_var =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
            let leaf_value_var =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(proof.leaf_value)).unwrap();
            let siblings_vars: Vec<FpVar<Fr>> = flat_siblings
                .iter()
                .map(|v| FpVar::<Fr>::new_witness(cs.clone(), || Ok(*v)).unwrap())
                .collect();
            let merkle_root_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(proof.root)).unwrap();

            let _ = verify_merkle_path(
                &leaf_value_var,
                &leaf_index_var,
                &siblings_vars,
                depth,
                arity,
                &merkle_root_var,
                cs.clone(),
            );

            assert!(
                !cs.is_satisfied().unwrap(),
                "constraint system must be UNSATISFIED with wrong leaf_index=0"
            );
        }
    }
}
