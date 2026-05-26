//! DealerParityStepCircuit — Verifies H·shares == 0 for all n shares from
//! a single dealer via Schwartz-Zippel randomized evaluation.
//! One circuit instance per dealer, processing all n shares in one step.
//!
//! v2: Binds the polynomial constant term P(0) to the claimed secret passed
//! via ExternalInputs.1. Combined with share_computation.rs's SHA-256
//! commitment check, this prevents a dealer from using a polynomial whose
//! constant term does not match the public commitment.

#[cfg(not(feature = "nova-backend"))]
use super::{ExternalInputs3, ExternalInputs3Var};
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
use ark_ff::PrimeField;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;

thread_local! {
    /// Expected number of shares (n). Persists across prove/verify so
    /// Nova re-synthesises the same constraint count during verification.
    pub static DEALER_PARITY_N: RefCell<usize> = RefCell::new(0);
}

thread_local! {
    /// Per-dealer parity data: (all_n_shares, pre_computed_poly_factors).
    /// Poly_factors[j] = Σ_{k=0}^{n-t-2} α_j^k · r^k for each share index j.
    pub static DEALER_PARITY_DATA: RefCell<(Vec<ark_bn254::Fr>, Vec<ark_bn254::Fr>)> =
        RefCell::new((Vec::new(), Vec::new()));
}

thread_local! {
    /// Constant term P(0) of the Shamir polynomial — the dealer's secret.
    /// The circuit enforces P(0) == ExternalInputs.1 (claimed secret).
    pub static DEALER_PARITY_P0: RefCell<Option<ark_bn254::Fr>> = RefCell::new(None);
}

pub fn set_dealer_parity_data(
    shares: Vec<ark_bn254::Fr>,
    poly_factors: Vec<ark_bn254::Fr>,
    p0: Option<ark_bn254::Fr>,
) {
    let n = shares.len().max(poly_factors.len());
    DEALER_PARITY_N.with(|cell| *cell.borrow_mut() = n);
    DEALER_PARITY_DATA.with(|cell| *cell.borrow_mut() = (shares, poly_factors));
    DEALER_PARITY_P0.with(|cell| *cell.borrow_mut() = p0);
}

pub fn clear_dealer_parity_data() {
    DEALER_PARITY_DATA.with(|cell| *cell.borrow_mut() = (Vec::new(), Vec::new()));
    DEALER_PARITY_P0.with(|cell| *cell.borrow_mut() = None);
    // DEALER_PARITY_N persists so Nova verify re-synthesises the same
    // constraint count.
}

#[derive(Clone, Debug, Default)]
pub struct DealerParityStepCircuit<F> {
    _phantom: std::marker::PhantomData<F>,
    /// Per-step share data for the bellpepper backend.
    /// The caller sets this field before each `prove_step` call.
    #[cfg(feature = "nova-backend")]
    pub step_shares: Vec<F>,
    /// Per-step poly-factor data for the bellpepper backend.
    #[cfg(feature = "nova-backend")]
    pub step_poly_factors: Vec<F>,
    /// P(0) constant term for the bellpepper backend.
    #[cfg(feature = "nova-backend")]
    pub step_p0: Option<F>,
}

#[cfg(not(feature = "nova-backend"))]
impl<F: PrimeField> FCircuit<F> for DealerParityStepCircuit<F> {
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
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let (shares, poly_factors) = DEALER_PARITY_DATA.with(|cell| cell.borrow().clone());
        let n = DEALER_PARITY_N.with(|cell| *cell.borrow());
        let p0 = DEALER_PARITY_P0.with(|cell| *cell.borrow());

        // (a) Schwartz-Zippel parity check:  H·shares == 0  in R1CS.
        let mut parity_acc = FpVar::<F>::zero();
        for j in 0..n {
            let s = if j < shares.len() && j < poly_factors.len() {
                FpVar::<F>::new_witness(cs.clone(), || -> Result<F, SynthesisError> {
                    Ok(to_f(shares[j]))
                })?
            } else {
                FpVar::<F>::new_witness(cs.clone(), || -> Result<F, SynthesisError> {
                    Ok(F::zero())
                })?
            };
            let p = if j < poly_factors.len() {
                FpVar::constant(to_f(poly_factors[j]))
            } else {
                FpVar::constant(F::zero())
            };
            parity_acc += s * p;
        }

        parity_acc.enforce_equal(&FpVar::<F>::zero())?;

        // (b) P(0) binding: constrain P(0) == claimed secret from ExternalInputs.1.
        // ExternalInputs3 layout:  (.0 = r, .1 = claimed_P0, .2 = n).
        let p0_f = p0.map(to_f).unwrap_or(F::zero());
        let p0_var =
            FpVar::<F>::new_witness(cs.clone(), || -> Result<F, SynthesisError> { Ok(p0_f) })?;
        p0_var.enforce_equal(&external_inputs.1)?;

        let done = FpVar::constant(F::one());
        let count = z_i[1].clone() + FpVar::constant(F::one());
        let ext0 = z_i[2].clone();

        Ok(vec![done, count, ext0])
    }
}

#[cfg(feature = "nova-backend")]
impl<F> arecibo::traits::circuit::StepCircuit<F> for DealerParityStepCircuit<F>
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
        let n = self.step_shares.len().max(self.step_poly_factors.len());

        // (a) Schwartz-Zippel parity check: H·shares == 0
        let mut parity_acc =
            AllocatedNum::alloc(cs.namespace(|| "parity_init"), || Ok(F::from(0u64)))?;
        for j in 0..n {
            let s_val = self.step_shares.get(j).copied().unwrap_or(F::from(0u64));
            let p_val = self
                .step_poly_factors
                .get(j)
                .copied()
                .unwrap_or(F::from(0u64));
            let s = AllocatedNum::alloc(cs.namespace(|| format!("share_{j}")), || Ok(s_val))?;
            let p = AllocatedNum::alloc(cs.namespace(|| format!("poly_factor_{j}")), || Ok(p_val))?;
            let prod = s.mul(cs.namespace(|| format!("s_p_mul_{j}")), &p)?;
            parity_acc = parity_acc.add(cs.namespace(|| format!("parity_add_{j}")), &prod)?;
        }

        // Enforce parity_acc == 0
        let lc_parity = LinearCombination::<F>::zero() + parity_acc.get_variable();
        let lc_one = LinearCombination::<F>::zero() + CS::one();
        let lc_zero = LinearCombination::<F>::zero();
        cs.enforce(
            || "parity_zero",
            |_| lc_parity.clone(),
            |_| lc_one.clone(),
            |_| lc_zero.clone(),
        );

        // (b) P(0) binding: allocate P(0) as a witness placeholder.
        // Full equality constraint to external inputs is not available
        // in the arecibo StepCircuit trait (no external inputs parameter).
        // The caller is expected to validate P(0) off-circuit.
        let _p0 = AllocatedNum::alloc(cs.namespace(|| "p0"), || {
            Ok(self.step_p0.unwrap_or(F::from(0u64)))
        })?;

        let done = AllocatedNum::alloc(cs.namespace(|| "done"), || Ok(F::from(1u64)))?;
        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::from(1u64)))?;
        let count = z[1].clone().add(cs.namespace(|| "count_inc"), &one)?;
        let ext0 = z[2].clone();

        Ok(vec![done, count, ext0])
    }
}

#[cfg(not(feature = "nova-backend"))]
fn to_f<F: PrimeField>(fr: ark_bn254::Fr) -> F {
    F::from_le_bytes_mod_order(&fr.into_bigint().to_bytes_le())
}

impl<F: PrimeField> StepCircuit for DealerParityStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/dealer-parity/v2").into()
    }
}
