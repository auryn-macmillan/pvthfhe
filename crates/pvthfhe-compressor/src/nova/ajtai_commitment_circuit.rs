use super::{ExternalInputs6, ExternalInputs6Var, PoseidonSpongeVar};
use crate::{StepCircuit, StepCircuitDescriptor};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(feature = "legacy-nova")]
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;

thread_local! {
    pub static AJTAI_WITNESS_DATA: RefCell<Vec<Vec<ark_bn254::Fr>>> = RefCell::new(Vec::new());
}
thread_local! {
    /// Per-step counter for nova-snark synthesize calls.
    /// Reset to 0 when `set_ajtai_witness_data` is called; incremented by
    /// each `synthesize` invocation to index into `AJTAI_WITNESS_DATA`.
    pub static AJTAI_STEP_COUNTER: RefCell<usize> = RefCell::new(0);
}

pub fn set_ajtai_witness_data(coeffs: Vec<Vec<ark_bn254::Fr>>) {
    AJTAI_WITNESS_DATA.with(|cell| *cell.borrow_mut() = coeffs);
    AJTAI_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

pub fn clear_ajtai_witness_data() {
    AJTAI_WITNESS_DATA.with(|cell| cell.borrow_mut().clear());
    AJTAI_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

#[derive(Clone, Debug, Default)]
pub struct AjtaiCommitmentStepCircuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for AjtaiCommitmentStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs6<F>;
    type ExternalInputsVar = ExternalInputs6Var<F>;
    fn state_len(&self) -> usize {
        2
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
        // Phase 4a: NTT ring multiplication deferred; using Poseidon hash of
        // witness coefficients as placeholder.
        let coeffs =
            AJTAI_WITNESS_DATA.with(|cell| cell.borrow().get(_i).cloned().unwrap_or_default());
        let coeff_vars: Vec<FpVar<F>> = coeffs
            .iter()
            .map(|c| {
                let v = F::from_le_bytes_mod_order(&c.into_bigint().to_bytes_le());
                FpVar::constant(v)
            })
            .collect();
        let mut sponge = PoseidonSpongeVar::new();
        sponge.absorb(&coeff_vars)?;
        let computed_commitment_hash = sponge.squeeze_one()?;

        let acc_hash = z_i[0].clone() + computed_commitment_hash;
        let step_count = z_i[1].clone() + FpVar::constant(F::one());

        let _ = cs.num_constraints();

        Ok(vec![acc_hash, step_count])
    }
}

impl<F: PrimeField> StepCircuit for AjtaiCommitmentStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 2 }
    }
    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/nova/ajtai-commitment/v1").into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    #[test]
    fn clear_and_set_witness_data() {
        let data = vec![vec![ark_bn254::Fr::from(42u64)]];
        set_ajtai_witness_data(data.clone());
        let stored = AJTAI_WITNESS_DATA.with(|c| c.borrow().clone());
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0][0], ark_bn254::Fr::from(42u64));

        clear_ajtai_witness_data();
        let empty = AJTAI_WITNESS_DATA.with(|c| c.borrow().clone());
        assert!(empty.is_empty());
    }

    #[test]
    fn different_witness_different_hash() {
        let circuit = AjtaiCommitmentStepCircuit::<ark_bn254::Fr>::new(()).unwrap();
        let zero = || ark_bn254::Fr::zero();
        let z_i = || vec![FpVar::constant(zero()), FpVar::constant(zero())];
        let ext = || {
            ExternalInputs6Var(
                FpVar::constant(zero()),
                FpVar::constant(zero()),
                FpVar::constant(zero()),
                FpVar::constant(zero()),
                FpVar::constant(zero()),
                FpVar::constant(zero()),
            )
        };

        set_ajtai_witness_data(vec![vec![ark_bn254::Fr::from(1u64)]]);
        let cs1 = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        let out1 = circuit
            .generate_step_constraints(cs1, 0, z_i(), ext())
            .unwrap();
        let h1 = out1[0].value().unwrap();

        set_ajtai_witness_data(vec![vec![ark_bn254::Fr::from(2u64)]]);
        let cs2 = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        let out2 = circuit
            .generate_step_constraints(cs2, 0, z_i(), ext())
            .unwrap();
        let h2 = out2[0].value().unwrap();

        assert_ne!(h1, h2, "different witness must produce different hash");
    }

    #[test]
    fn circuit_hash_is_deterministic() {
        let circuit = AjtaiCommitmentStepCircuit::<ark_bn254::Fr>::default();
        let h1 = circuit.circuit_hash();
        let h2 = circuit.circuit_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn default_witness_produces_valid_output() {
        let circuit = AjtaiCommitmentStepCircuit::<ark_bn254::Fr>::new(()).unwrap();
        clear_ajtai_witness_data();

        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        let z_i = vec![
            FpVar::constant(ark_bn254::Fr::zero()),
            FpVar::constant(ark_bn254::Fr::zero()),
        ];
        let ext = ExternalInputs6Var(
            FpVar::constant(ark_bn254::Fr::zero()),
            FpVar::constant(ark_bn254::Fr::zero()),
            FpVar::constant(ark_bn254::Fr::zero()),
            FpVar::constant(ark_bn254::Fr::zero()),
            FpVar::constant(ark_bn254::Fr::zero()),
            FpVar::constant(ark_bn254::Fr::zero()),
        );

        let out = circuit
            .generate_step_constraints(cs.clone(), 0, z_i, ext)
            .unwrap();
        assert_eq!(out.len(), 2);
        // step_count should be 1 when starting from 0
        assert_eq!(out[1].value().unwrap(), ark_bn254::Fr::one());
    }
}
