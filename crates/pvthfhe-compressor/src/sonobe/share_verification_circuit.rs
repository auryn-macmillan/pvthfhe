use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;
use super::{ExternalInputs4, ExternalInputs4Var, PoseidonSpongeVar};
use crate::{StepCircuit, StepCircuitDescriptor};

thread_local! {
    pub static SHARE_COEFFS_DATA: RefCell<Vec<Vec<ark_bn254::Fr>>> = RefCell::new(Vec::new());
}

pub fn set_share_coeffs_data(coeffs: Vec<Vec<ark_bn254::Fr>>) {
    SHARE_COEFFS_DATA.with(|cell| *cell.borrow_mut() = coeffs);
}

pub fn clear_share_coeffs_data() {
    SHARE_COEFFS_DATA.with(|cell| cell.borrow_mut().clear());
}

#[derive(Clone, Debug, Default)]
pub struct ShareVerificationStepCircuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for ShareVerificationStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs4<F>;
    type ExternalInputsVar = ExternalInputs4Var<F>;
    fn state_len(&self) -> usize { 2 }
    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self { _phantom: std::marker::PhantomData })
    }
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>, _i: usize, z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let coeffs = SHARE_COEFFS_DATA.with(|cell| cell.borrow().get(_i).cloned().unwrap_or_default());
        let coeff_vars: Vec<FpVar<F>> = coeffs
            .iter()
            .map(|c| {
                let v = F::from_le_bytes_mod_order(&c.into_bigint().to_bytes_le());
                FpVar::constant(v)
            })
            .collect();
        let mut sponge = PoseidonSpongeVar::new();
        sponge.absorb(&coeff_vars)?;
        let h = sponge.squeeze_one()?;
        let acc = z_i[0].clone() + h;
        let cnt = z_i[1].clone() + FpVar::constant(F::one());
        Ok(vec![acc, cnt])
    }
}

impl<F: PrimeField> StepCircuit for ShareVerificationStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor { StepCircuitDescriptor { width: 2 } }
    fn circuit_hash(&self) -> [u8; 32] { Keccak256::digest(b"pvthfhe/pvss/share-verify/v1").into() }
}
