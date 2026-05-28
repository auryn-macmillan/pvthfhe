//! PK contribution step circuit — accumulates per-party sigma verification hashes across steps.

use super::{sigma_verify_step, ExternalInputs3, ExternalInputs3Var, PoseidonSpongeVar};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(feature = "legacy-nova")]
use folding_schemes::frontend::FCircuit; // folding (legacy-nova)

#[cfg(feature = "nova-backend")]
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError as BpSynthesisError};
#[cfg(feature = "nova-backend")]
use bp_ff::PrimeField as BpPrimeField;

use crate::{StepCircuit, StepCircuitDescriptor};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;

thread_local! {
    pub static PK_CONTRIBUTION_DATA: RefCell<Vec<ark_bn254::Fr>> = RefCell::new(Vec::new());
}
thread_local! {
    pub static PK_CONTRIBUTION_N: RefCell<usize> = RefCell::new(0);
}

pub fn set_pk_contribution_data(party_ids: Vec<ark_bn254::Fr>, n_parties: usize) {
    PK_CONTRIBUTION_N.with(|cell| *cell.borrow_mut() = n_parties);
    PK_CONTRIBUTION_DATA.with(|cell| *cell.borrow_mut() = party_ids);
}

pub fn clear_pk_contribution_data() {
    PK_CONTRIBUTION_DATA.with(|cell| cell.borrow_mut().clear());
}

/// A step circuit that verifies PK contribution sigma proofs across parties.
///
/// State layout (arity 3):
///   z[0] = accumulated_step_hash
///   z[1] = party_count
///   z[2] = step_count
///
/// Per step: verify the sigma relation for this party's PK contribution,
/// hash (party_id || sigma_result), then accumulate the hash into the state.
#[derive(Clone, Debug, Default)]
pub struct KeyContributionStepCircuit<F> {
    _phantom: std::marker::PhantomData<F>,
    /// Per-step party IDs for the bellpepper backend.
    /// The caller sets this field before iterative `prove_step` calls.
    #[cfg(feature = "nova-backend")]
    pub party_ids: Vec<F>,
    /// Step index for the bellpepper backend.
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_index: usize,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for KeyContributionStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn state_len(&self) -> usize {
        3
    }

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> { // folding (legacy-nova)
        Ok(Self {
            _phantom: std::marker::PhantomData,
        })
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let _n = PK_CONTRIBUTION_N.with(|cell| *cell.borrow());
        let data = PK_CONTRIBUTION_DATA.with(|cell| cell.borrow().clone());
        let party_id = data.get(_i).cloned().unwrap_or_default();

        // Run sigma_verify_step for this party's PK contribution
        let sigma_result = sigma_verify_step(cs.clone(), _i)?;

        let id_f = F::from_le_bytes_mod_order(&party_id.into_bigint().to_bytes_le());
        let id_var = FpVar::<F>::new_witness(cs.clone(), || Ok(id_f))?;
        let mut sponge = PoseidonSpongeVar::new();
        sponge.absorb(&[id_var, sigma_result])?;
        let step_hash = sponge.squeeze_one()?;
        let acc = z_i[0].clone() + step_hash;
        let count = z_i[1].clone() + FpVar::constant(F::one());

        Ok(vec![acc, count, z_i[2].clone() + FpVar::constant(F::one())])
    }
}

#[cfg(feature = "nova-backend")]
impl<F> arecibo::traits::circuit::StepCircuit<F> for KeyContributionStepCircuit<F>
where
    F: BpPrimeField,
{
    fn arity(&self) -> usize {
        3
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, BpSynthesisError> {
        let party_id = self
            .party_ids
            .get(self.step_index)
            .copied()
            .unwrap_or_default();
        AllocatedNum::alloc(cs.namespace(|| "party_id"), || Ok(party_id))?;

        // sigma_verify_step is not yet available in bellpepper; allocate a constant
        // placeholder until a compatible sigma gadget is wired.
        let sigma_result =
            AllocatedNum::alloc(cs.namespace(|| "sigma_result"), || Ok(F::from(1u64)))?;

        // Poseidon is not yet available in bellpepper; allocate a constant
        // placeholder until a compatible Poseidon gadget is wired.
        let step_hash = AllocatedNum::alloc(cs.namespace(|| "step_hash"), || Ok(F::from(1u64)))?;

        let acc = z[0].clone().add(cs.namespace(|| "acc_add"), &step_hash)?;
        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::from(1u64)))?;
        let count = z[1].clone().add(cs.namespace(|| "count_inc"), &one)?;
        let step_count = z[2].clone().add(cs.namespace(|| "step_inc"), &one)?;

        Ok(vec![acc, count, step_count])
    }
}

impl<F: PrimeField> StepCircuit for KeyContributionStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/pk-contribution/v1").into()
    }
}
