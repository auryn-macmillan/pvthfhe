use super::{ExternalInputs3, ExternalInputs3Var, PoseidonSpongeVar};
use crate::{StepCircuit, StepCircuitDescriptor};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
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

#[derive(Clone, Debug, Default)]
pub struct DkgAggregationStepCircuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for DkgAggregationStepCircuit<F> {
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
        let n_steps = DKG_AGG_N_STEPS.with(|cell| *cell.borrow());
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

impl<F: PrimeField> StepCircuit for DkgAggregationStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/dkg-agg/v1").into()
    }
}
