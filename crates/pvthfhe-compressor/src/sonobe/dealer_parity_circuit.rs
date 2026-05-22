//! DealerParityStepCircuit — Verifies H·shares == 0 for all n shares from
//! a single dealer via Schwartz-Zippel randomized evaluation.
//! One circuit instance per dealer, processing all n shares in one step.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;
use super::{ExternalInputs3, ExternalInputs3Var};
use crate::{StepCircuit, StepCircuitDescriptor};

thread_local! {
    /// Per-dealer parity data: (all_n_shares, pre_computed_poly_factors).
    /// Poly_factors[j] = Σ_{k=0}^{n-t-2} α_j^k · r^k for each share index j.
    pub static DEALER_PARITY_DATA: RefCell<(Vec<ark_bn254::Fr>, Vec<ark_bn254::Fr>)> =
        RefCell::new((Vec::new(), Vec::new()));
}

pub fn set_dealer_parity_data(shares: Vec<ark_bn254::Fr>, poly_factors: Vec<ark_bn254::Fr>) {
    DEALER_PARITY_DATA.with(|cell| *cell.borrow_mut() = (shares, poly_factors));
}

pub fn clear_dealer_parity_data() {
    DEALER_PARITY_DATA.with(|cell| *cell.borrow_mut() = (Vec::new(), Vec::new()));
}

#[derive(Clone, Debug, Default)]
pub struct DealerParityStepCircuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for DealerParityStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn state_len(&self) -> usize { 2 }

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self { _phantom: std::marker::PhantomData })
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let (shares, poly_factors) = DEALER_PARITY_DATA.with(|cell| cell.borrow().clone());

        let mut parity_acc = FpVar::<F>::zero();
        for j in 0..shares.len().min(poly_factors.len()) {
            let s = FpVar::<F>::new_witness(cs.clone(), || Ok(to_f(shares[j])))?;
            let p = FpVar::constant(to_f(poly_factors[j]));
            parity_acc += s * p;
        }

        parity_acc.enforce_equal(&FpVar::<F>::zero())?;

        let done = FpVar::constant(F::one());
        let count = z_i[1].clone() + FpVar::constant(F::one());

        Ok(vec![done, count])
    }
}

fn to_f<F: PrimeField>(fr: ark_bn254::Fr) -> F {
    F::from_le_bytes_mod_order(&fr.into_bigint().to_bytes_le())
}

impl<F: PrimeField> StepCircuit for DealerParityStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 2 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/dealer-parity/v1").into()
    }
}
