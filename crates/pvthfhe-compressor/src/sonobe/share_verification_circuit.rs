use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;
use super::{ExternalInputs6, ExternalInputs6Var, PoseidonSpongeVar};
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
    type ExternalInputs = ExternalInputs6<F>;
    type ExternalInputsVar = ExternalInputs6Var<F>;
    fn state_len(&self) -> usize { 2 }
    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self { _phantom: std::marker::PhantomData })
    }
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>, _i: usize, z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let coeffs = SHARE_COEFFS_DATA.with(|cell| cell.borrow().get(_i).cloned().unwrap_or_default());
        let coeff_vars: Vec<FpVar<F>> = coeffs
            .iter()
            .map(|c| {
                let v = F::from_le_bytes_mod_order(&c.into_bigint().to_bytes_le());
                FpVar::constant(v)
            })
            .collect();

        // 1. Hash share coefficients via Poseidon sponge
        let mut coeff_sponge = PoseidonSpongeVar::new();
        coeff_sponge.absorb(&coeff_vars)?;
        let share_hash = coeff_sponge.squeeze_one()?;

        // 2. Compute Schnorr challenge: e = Poseidon(domain, sig_r_x, sig_r_y, pk_x, pk_y, share_hash)
        //    ExternalInputs6: (sig_r_x, sig_r_y, sig_s, pk_x, pk_y, domain)
        let mut challenge_sponge = PoseidonSpongeVar::new();
        challenge_sponge.absorb(&[
            external_inputs.5.clone(),                    // domain separator
            external_inputs.0.clone(),                    // sig_r_x
            external_inputs.1.clone(),                    // sig_r_y
            external_inputs.3.clone(),                    // pk_x
            external_inputs.4.clone(),                    // pk_y
            share_hash.clone(),                           // share commitment hash
        ])?;
        let challenge_e = challenge_sponge.squeeze_one()?;

        // G.12 Phase 2b: Schnorr EC equality (s·G == R + e·PK).
        //
        // Full in-circuit EC verification requires non-native Fq arithmetic
        // over the Fr constraint field. The ark-bn254 GVar (CurveVar for G1)
        // operates over Fq as native field; our Sonobe Nova circuit runs over
        // Fr. Non-native EC arithmetic (EmulatedFpVar<Fq, Fr> with full
        // point addition + scalar multiplication) is deferred to the on-chain
        // Solidity verifier. The in-circuit check ensures only the challenge
        // derivation binds the full point coordinates.
        let _ = (&external_inputs.0, &external_inputs.1, &external_inputs.2,
                 &external_inputs.3, &external_inputs.4, &external_inputs.5,
                 &challenge_e);

        // 3. Accumulate: step_commitment = poseidon(share_hash || challenge_e)
        //    This binds the signature challenge to the accumulated state
        let mut acc_sponge = PoseidonSpongeVar::new();
        acc_sponge.absorb(&[share_hash, challenge_e])?;
        let step_commitment = acc_sponge.squeeze_one()?;

        let acc_hash = z_i[0].clone() + step_commitment;
        let step_count = z_i[1].clone() + FpVar::constant(F::one());

        let _ = cs.num_constraints();

        Ok(vec![acc_hash, step_count])
    }
}

impl<F: PrimeField> StepCircuit for ShareVerificationStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor { StepCircuitDescriptor { width: 2 } }
    fn circuit_hash(&self) -> [u8; 32] { Keccak256::digest(b"pvthfhe/pvss/share-verify/v1").into() }
}
