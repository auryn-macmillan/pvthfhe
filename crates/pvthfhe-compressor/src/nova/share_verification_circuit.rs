/// ShareVerificationStepCircuit — Verifies RLWE sigma proof equation in Nova IVC.
///
/// Each step verifies `SIGMA_VERIFY_COEFFS` NTT-domain coefficients of the
/// sigma relation `c·z_s + z_e == t + ch·d_i` over 3 RNS limbs, with quotient
/// witnesses for modular reduction and power-basis norm enforcement.
///
/// The circuit folds per-step verification results into a Poseidon accumulator.
/// After all steps, the accumulator serves as `verified_sigma_hash` and is
/// bound into the aggregator_final Noir circuit as a public input.
use super::{sigma_verify_step, ExternalInputs3, ExternalInputs3Var, PoseidonSpongeVar};
use crate::{StepCircuit, StepCircuitDescriptor};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(feature = "legacy-nova")]
use folding_schemes::frontend::FCircuit; // folding (legacy-nova)
use sha3::{Digest, Keccak256};
use std::cell::RefCell;

/// Thread-local for step metadata (step count verification). The actual
/// sigma NTT data lives in `SIGMA_DATA` (mod.rs), accessed by `sigma_verify_step`.
thread_local! {
    pub static SIGMA_VERIFY_META: RefCell<Vec<ark_bn254::Fr>> = RefCell::new(Vec::new());
}

// Backward-compatible aliases used by the compressor prove_steps glue.
thread_local! {
    pub static SHARE_COEFFS_DATA: RefCell<Vec<Vec<ark_bn254::Fr>>> = RefCell::new(Vec::new());
}
thread_local! {
    pub static SHARE_VERIFY_STEP_COUNTER: RefCell<usize> = RefCell::new(0);
}

pub fn set_share_coeffs_data(coeffs: Vec<Vec<ark_bn254::Fr>>) {
    SHARE_COEFFS_DATA.with(|cell| *cell.borrow_mut() = coeffs);
    SHARE_VERIFY_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

pub fn clear_share_coeffs_data() {
    SHARE_COEFFS_DATA.with(|cell| cell.borrow_mut().clear());
    SHARE_VERIFY_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

/// Number of sigma verification steps to expect. Persists across prove/verify.
thread_local! {
    pub static SIGMA_VERIFY_N_STEPS: RefCell<usize> = RefCell::new(0);
}

pub fn set_sigma_verify_meta(domain_tags: Vec<ark_bn254::Fr>, n_steps: usize) {
    SIGMA_VERIFY_META.with(|cell| *cell.borrow_mut() = domain_tags);
    SIGMA_VERIFY_N_STEPS.with(|cell| *cell.borrow_mut() = n_steps);
}

pub fn clear_sigma_verify_meta() {
    SIGMA_VERIFY_META.with(|cell| cell.borrow_mut().clear());
    // SIGMA_VERIFY_N_STEPS persists for Nova verify re-synthesis.
}

#[derive(Clone, Debug, Default)]
pub struct ShareVerificationStepCircuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for ShareVerificationStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn state_len(&self) -> usize {
        2
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
        let n_steps = SIGMA_VERIFY_N_STEPS.with(|cell| *cell.borrow());

        // Run sigma equation verification for this step. On failure, the
        // function enforces `1 == 0` (unsatisfiable constraint).
        let sigma_result = sigma_verify_step(cs.clone(), _i)?;

        // Compute a step commitment hash from the verification result and
        // step metadata for accumulation.
        let domain_tag =
            SIGMA_VERIFY_META.with(|cell| cell.borrow().get(_i).cloned().unwrap_or_default());
        let domain_f = F::from_le_bytes_mod_order(&domain_tag.into_bigint().to_bytes_le());

        let mut hash_sponge = PoseidonSpongeVar::new();
        hash_sponge.absorb(&[FpVar::constant(domain_f), sigma_result])?;
        let step_hash = hash_sponge.squeeze_one()?;

        let acc_hash = z_i[0].clone() + step_hash;
        let step_count = z_i[1].clone() + FpVar::constant(F::one());

        // Enforce we process exactly n_steps.
        if _i + 1 >= n_steps && n_steps > 0 {
            step_count.enforce_equal(&FpVar::constant(F::from(n_steps as u64)))?;
        }

        Ok(vec![acc_hash, step_count])
    }
}

/// Convert ark_bn254::Fr to circuit field F.
fn to_f<F: PrimeField>(fr: ark_bn254::Fr) -> F {
    use ark_ff::BigInteger;
    F::from_le_bytes_mod_order(&fr.into_bigint().to_bytes_le())
}

impl<F: PrimeField> StepCircuit for ShareVerificationStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 2 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/pvss/share-verify-sigma/v1").into()
    }
}
