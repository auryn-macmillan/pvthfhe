use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(not(feature = "nova-backend"))]
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};

use pvthfhe_domain_tags::Tag;

use super::poseidon_gadget::hash256;
use super::{RingEqExternalInputs5, RingEqExternalInputs5Var};
use crate::{StepCircuit, StepCircuitDescriptor};

#[derive(Clone, Debug)]
pub struct RingVerifierCircuit<F: PrimeField> {
    challenge: F,
    ring_coeffs: Vec<F>,
    _field: PhantomData<F>,
}

impl<F: PrimeField> RingVerifierCircuit<F> {
    fn ternary_challenge(c: &F) -> bool {
        *c == F::zero() || *c == F::one() || *c == -F::one()
    }
}

#[cfg(not(feature = "nova-backend"))]
impl<F: PrimeField> FCircuit<F> for RingVerifierCircuit<F> {
    type Params = (F, Vec<F>);
    type ExternalInputs = RingEqExternalInputs5<F>;
    type ExternalInputsVar = RingEqExternalInputs5Var<F>;

    fn new(params: Self::Params) -> Result<Self, folding_schemes::Error> {
        let (challenge, ring_coeffs) = params;
        if ring_coeffs.len() != 1024 {
            return Err(folding_schemes::Error::Other(
                "RingVerifierCircuit: ring_coeffs must have exactly 1024 elements".to_string(),
            ));
        }
        if !Self::ternary_challenge(&challenge) {
            return Err(folding_schemes::Error::Other(
                "RingVerifierCircuit: challenge must be ternary (-1, 0, 1)".to_string(),
            ));
        }
        Ok(Self {
            challenge,
            ring_coeffs,
            _field: PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let n = 256;

        let ring_coeffs = &self.ring_coeffs;
        let ring_witness: Vec<FpVar<F>> = ring_coeffs
            .iter()
            .enumerate()
            .map(|(idx, &v)| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect();

        let zs_hash = hash256(cs.clone(), &ring_witness[0..n])?;
        let ze_hash = hash256(cs.clone(), &ring_witness[n..2 * n])?;
        let t_hash = hash256(cs.clone(), &ring_witness[2 * n..3 * n])?;
        let d_hash = hash256(cs.clone(), &ring_witness[3 * n..4 * n])?;

        external_inputs.0.enforce_equal(&zs_hash)?;
        external_inputs.1.enforce_equal(&ze_hash)?;
        external_inputs.2.enforce_equal(&t_hash)?;
        external_inputs.3.enforce_equal(&d_hash)?;

        external_inputs
            .4
            .enforce_equal(&FpVar::constant(self.challenge))?;

        if self.challenge == F::one() {
            for k in 0..n {
                let lhs = &ring_witness[k] + &ring_witness[n + k];
                let rhs = &ring_witness[2 * n + k] + &ring_witness[3 * n + k];
                lhs.enforce_equal(&rhs)?;
            }
        } else if self.challenge == -F::one() {
            for k in 0..n {
                let lhs = &ring_witness[3 * n + k] + &ring_witness[n + k];
                let rhs = &ring_witness[2 * n + k] + &ring_witness[k];
                lhs.enforce_equal(&rhs)?;
            }
        } else {
            for k in 0..n {
                ring_witness[n + k].enforce_equal(&ring_witness[2 * n + k])?;
            }
        }

        let result = z_i[0].clone() + FpVar::constant(F::one());
        Ok(vec![result])
    }
}

impl<F: PrimeField> StepCircuit for RingVerifierCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 1 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::SonobeRingVerifier.as_bytes()).into()
    }
}
