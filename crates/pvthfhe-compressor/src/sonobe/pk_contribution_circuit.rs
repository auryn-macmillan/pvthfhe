use super::{sigma_verify_step, ExternalInputs3, ExternalInputs3Var, PoseidonSpongeVar};
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

#[derive(Clone, Debug, Default)]
pub struct KeyContributionStepCircuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for KeyContributionStepCircuit<F> {
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
        let n = PK_CONTRIBUTION_N.with(|cell| *cell.borrow());
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

impl<F: PrimeField> StepCircuit for KeyContributionStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/pk-contribution/v1").into()
    }
}
