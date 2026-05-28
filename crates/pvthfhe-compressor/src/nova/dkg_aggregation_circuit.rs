//! DKG aggregation step circuit — accumulates per-recipient share hashes across steps.

use super::{ExternalInputs3, ExternalInputs3Var, PoseidonSpongeVar};
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
    pub static DKG_AGG_DATA: RefCell<Vec<Vec<ark_bn254::Fr>>> = RefCell::new(Vec::new());
}
thread_local! {
    pub static DKG_AGG_N_STEPS: RefCell<usize> = RefCell::new(0);
}

pub fn set_dkg_agg_data(data: Vec<Vec<ark_bn254::Fr>>) {
    DKG_AGG_N_STEPS.with(|cell| *cell.borrow_mut() = data.len());
    DKG_AGG_DATA.with(|cell| *cell.borrow_mut() = data);
}

pub fn clear_dkg_agg_data() {
    DKG_AGG_DATA.with(|cell| cell.borrow_mut().clear());
}

/// A step circuit that aggregates DKG shares across recipients.
///
/// State layout (arity 3):
///   z[0] = accumulated_step_hash
///   z[1] = share_count
///   z[2] = step_count
///
/// Per step: sum the per-recipient shares, hash (sum || step_index),
/// then accumulate the hash into the state.
#[derive(Clone, Debug, Default)]
pub struct DkgAggregationStepCircuit<F> {
    _phantom: std::marker::PhantomData<F>,
    /// Per-step share data for the bellpepper backend.
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_shares: Vec<F>,
    /// Step index for the bellpepper backend.
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_index: usize,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for DkgAggregationStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn state_len(&self) -> usize {
        3
    }

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        // folding (legacy-nova)
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
        let _n_steps = DKG_AGG_N_STEPS.with(|cell| *cell.borrow());
        let data = DKG_AGG_DATA.with(|cell| cell.borrow().clone());
        let step_shares = data.get(_i).cloned().unwrap_or_default();

        let mut sum = FpVar::<F>::zero();
        for share in &step_shares {
            let s = FpVar::<F>::new_witness(cs.clone(), || {
                let val = F::from_le_bytes_mod_order(&share.into_bigint().to_bytes_le());
                Ok(val)
            })?;
            sum += s;
        }

        let step_f = F::from((_i + 1) as u64);
        let step_var = FpVar::<F>::new_witness(cs.clone(), || Ok(step_f))?;

        let mut sponge = PoseidonSpongeVar::new();
        sponge.absorb(&[sum, step_var])?;
        let step_hash = sponge.squeeze_one()?;
        let acc = z_i[0].clone() + step_hash;
        let count = z_i[1].clone() + FpVar::constant(F::one());

        Ok(vec![acc, count, z_i[2].clone() + FpVar::constant(F::one())])
    }
}

#[cfg(feature = "nova-backend")]
impl<F> arecibo::traits::circuit::StepCircuit<F> for DkgAggregationStepCircuit<F>
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
        let mut sum = AllocatedNum::alloc(cs.namespace(|| "sum_init"), || Ok(F::from(0u64)))?;
        for (i, share) in self.step_shares.iter().enumerate() {
            let s = AllocatedNum::alloc(cs.namespace(|| format!("share_{i}")), || Ok(*share))?;
            sum = sum.add(cs.namespace(|| format!("add_share_{i}")), &s)?;
        }

        let step_f = F::from((self.step_index + 1) as u64);
        AllocatedNum::alloc(cs.namespace(|| "step_index"), || Ok(step_f))?;

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

impl<F: PrimeField> StepCircuit for DkgAggregationStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/dkg-agg/v1").into()
    }
}
