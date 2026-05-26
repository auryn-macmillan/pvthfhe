//! Lagrange fold step circuit for Sonobe Nova IVC.
//!
//! Each step computes one Lagrange contribution: `λ_i · share_hash_i`
//! and accumulates into a running sum. Replaces the standalone Noir C7
//! Lagrange computation with in-circuit folding.

#[cfg(not(feature = "nova-backend"))]
use super::PoseidonSpongeVar;
#[cfg(not(feature = "nova-backend"))]
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
#[cfg(not(feature = "nova-backend"))]
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(not(feature = "nova-backend"))]
use folding_schemes::frontend::FCircuit;

#[cfg(feature = "nova-backend")]
use bellpepper_core::{
    num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError as BpSynthesisError,
};
#[cfg(feature = "nova-backend")]
use bp_ff::PrimeField as BpPrimeField;

use crate::{StepCircuit, StepCircuitDescriptor};
#[cfg(not(feature = "nova-backend"))]
use ark_ff::BigInteger;
use ark_ff::{PrimeField, Zero};
use sha3::{Digest, Keccak256};
use std::cell::RefCell;

thread_local! {
    pub static LAGRANGE_DATA: RefCell<Vec<(ark_bn254::Fr, ark_bn254::Fr, ark_bn254::Fr)>> = RefCell::new(Vec::new());
}

pub fn set_lagrange_data(data: Vec<(ark_bn254::Fr, ark_bn254::Fr, ark_bn254::Fr)>) {
    LAGRANGE_DATA.with(|cell| *cell.borrow_mut() = data);
}

pub fn clear_lagrange_data() {
    LAGRANGE_DATA.with(|cell| cell.borrow_mut().clear());
}

#[derive(Clone, Debug, Default)]
pub struct LagrangeFoldStepCircuit<F> {
    _phantom: std::marker::PhantomData<F>,
    /// Per-step Lagrange data for the bellpepper backend.
    /// Each tuple: (lambda, share_hash, registered_hash).
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_data: Vec<(F, F, F)>,
    /// Step index for the bellpepper backend.
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_index: usize,
}

#[cfg(not(feature = "nova-backend"))]
impl<F: PrimeField> FCircuit<F> for LagrangeFoldStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ();
    type ExternalInputsVar = ();

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
        i: usize,
        z_i: Vec<FpVar<F>>,
        _ei: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // state = [running_sum, share_chain_hash, step_count]
        LAGRANGE_DATA.with(|cell| {
            let data = cell.borrow();
            let (lambda_fr, share_hash_fr, registered_hash_fr) = data.get(i).copied().unwrap_or((
                ark_bn254::Fr::zero(),
                ark_bn254::Fr::zero(),
                ark_bn254::Fr::zero(),
            ));
            let lambda_f = F::from_le_bytes_mod_order(&lambda_fr.into_bigint().to_bytes_le());
            let share_f = F::from_le_bytes_mod_order(&share_hash_fr.into_bigint().to_bytes_le());
            let registered_f =
                F::from_le_bytes_mod_order(&registered_hash_fr.into_bigint().to_bytes_le());
            let lambda_var = FpVar::new_witness(cs.clone(), || Ok(lambda_f))?;
            let share_var = FpVar::new_witness(cs.clone(), || Ok(share_f))?;
            let registered_var = FpVar::new_witness(cs.clone(), || Ok(registered_f))?;

            // Share provenance: registered hash must match the claimed share hash
            share_var.enforce_equal(&registered_var)?;

            let share_var_clone = share_var.clone();

            // Contribution: lambda_i * share_hash_i
            let contribution = lambda_var * share_var_clone;
            let running_sum = z_i[0].clone() + contribution;

            // Chain hash: Poseidon(prev_hash, share_hash_i)
            let mut sponge = PoseidonSpongeVar::new();
            sponge.absorb(&[z_i[1].clone(), share_var])?;
            let chain_hash = sponge.squeeze_one()?;

            Ok(vec![
                running_sum,
                chain_hash,
                z_i[2].clone() + FpVar::constant(F::one()),
            ])
        })
    }
}

#[cfg(feature = "nova-backend")]
impl<F> arecibo::traits::circuit::StepCircuit<F> for LagrangeFoldStepCircuit<F>
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
        let (lambda, share_hash, registered_hash) = self
            .step_data
            .get(self.step_index)
            .copied()
            .unwrap_or((F::from(0u64), F::from(0u64), F::from(0u64)));

        let lambda_var = AllocatedNum::alloc(cs.namespace(|| "lambda"), || Ok(lambda))?;
        let share_var = AllocatedNum::alloc(cs.namespace(|| "share_hash"), || Ok(share_hash))?;
        let registered_var =
            AllocatedNum::alloc(cs.namespace(|| "registered_hash"), || Ok(registered_hash))?;

        // Share provenance: registered hash must match claimed share hash.
        // Enforce share_var == registered_var via share * 1 == registered.
        let lc_a = LinearCombination::<F>::zero() + share_var.get_variable();
        let lc_b = LinearCombination::<F>::zero() + CS::one();
        let lc_c = LinearCombination::<F>::zero() + registered_var.get_variable();
        cs.enforce(
            || "share_eq_registered",
            |_| lc_a.clone(),
            |_| lc_b.clone(),
            |_| lc_c.clone(),
        );

        // Contribution: lambda_i * share_hash_i
        let contribution = lambda_var.mul(cs.namespace(|| "lambda_times_share"), &share_var)?;
        let running_sum = z[0]
            .clone()
            .add(cs.namespace(|| "running_sum_add"), &contribution)?;

        // Chain hash: placeholder (Poseidon not yet available in bellpepper).
        let chain_hash = AllocatedNum::alloc(cs.namespace(|| "chain_hash"), || Ok(F::from(1u64)))?;

        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::from(1u64)))?;
        let step_count = z[2].clone().add(cs.namespace(|| "step_inc"), &one)?;

        Ok(vec![running_sum, chain_hash, step_count])
    }
}

impl<F: PrimeField> StepCircuit for LagrangeFoldStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/lagrange-fold/v1").into()
    }
}
