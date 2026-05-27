//! PK aggregation step circuit — accumulates per-party public key hashes across steps.

use super::{sigma_verify_step, ExternalInputs3, ExternalInputs3Var, PoseidonSpongeVar};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(feature = "legacy-nova")]
use folding_schemes::frontend::FCircuit;

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
    pub static PK_AGG_DATA: RefCell<Vec<Vec<ark_bn254::Fr>>> = RefCell::new(Vec::new());
}
thread_local! {
    pub static PK_AGG_N: RefCell<usize> = RefCell::new(0);
}

pub fn set_pk_agg_data(data: Vec<Vec<ark_bn254::Fr>>) {
    PK_AGG_N.with(|cell| *cell.borrow_mut() = data.len());
    PK_AGG_DATA.with(|cell| *cell.borrow_mut() = data);
}

pub fn clear_pk_agg_data() {
    PK_AGG_DATA.with(|cell| cell.borrow_mut().clear());
}

/// A step circuit that aggregates public key hashes across parties.
///
/// State layout (arity 3):
///   z[0] = accumulated_step_hash
///   z[1] = pk_count
///   z[2] = step_count
///
/// Per step: sum the per-party public key hashes, hash (sum || step_index || sigma_ok),
/// then accumulate the hash into the state.
#[derive(Clone, Debug, Default)]
pub struct PkAggregationStepCircuit<F> {
    _phantom: std::marker::PhantomData<F>,
    /// Per-step public key data for the bellpepper backend.
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_pks: Vec<F>,
    /// Step index for the bellpepper backend.
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_index: usize,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for PkAggregationStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn state_len(&self) -> usize {
        3
    }

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
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
        let _n = PK_AGG_N.with(|cell| *cell.borrow());
        let data = PK_AGG_DATA.with(|cell| cell.borrow().clone());
        let step_pks = data.get(_i).cloned().unwrap_or_default();

        let mut sum = FpVar::<F>::zero();
        for pk in &step_pks {
            let s = FpVar::<F>::new_witness(cs.clone(), || {
                let val = F::from_le_bytes_mod_order(&pk.into_bigint().to_bytes_le());
                Ok(val)
            })?;
            sum += s;
        }

        let step_f = F::from((_i + 1) as u64);
        let step_var = FpVar::<F>::new_witness(cs.clone(), || Ok(step_f))?;

        let sigma_ok = sigma_verify_step(cs.clone(), _i)?;

        let mut sponge = PoseidonSpongeVar::new();
        sponge.absorb(&[sum, step_var, sigma_ok])?;
        let step_hash = sponge.squeeze_one()?;
        let acc = z_i[0].clone() + step_hash;
        let count = z_i[1].clone() + FpVar::constant(F::one());

        Ok(vec![acc, count, z_i[2].clone() + FpVar::constant(F::one())])
    }
}

#[cfg(feature = "nova-backend")]
impl<F> arecibo::traits::circuit::StepCircuit<F> for PkAggregationStepCircuit<F>
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
        for (i, pk) in self.step_pks.iter().enumerate() {
            let s = AllocatedNum::alloc(cs.namespace(|| format!("pk_{i}")), || Ok(*pk))?;
            sum = sum.add(cs.namespace(|| format!("add_pk_{i}")), &s)?;
        }

        let step_f = F::from((self.step_index + 1) as u64);
        AllocatedNum::alloc(cs.namespace(|| "step_index"), || Ok(step_f))?;

        // sigma_ok: placeholder until sigma verification is wired in bellpepper
        let _sigma_ok = AllocatedNum::alloc(cs.namespace(|| "sigma_ok"), || Ok(F::from(1u64)))?;

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

impl<F: PrimeField> StepCircuit for PkAggregationStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/pk-aggregation/v1").into()
    }
}
