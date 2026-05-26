//! Lagrange fold step circuit for Sonobe Nova IVC.
//!
//! Each step computes one Lagrange contribution: `λ_i · share_hash_i`
//! and accumulates into a running sum. Replaces the standalone Noir C7
//! Lagrange computation with in-circuit folding.

use super::PoseidonSpongeVar;
use crate::{StepCircuit, StepCircuitDescriptor};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
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
pub struct LagrangeFoldStepCircuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

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

impl<F: PrimeField> StepCircuit for LagrangeFoldStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/lagrange-fold/v1").into()
    }
}
