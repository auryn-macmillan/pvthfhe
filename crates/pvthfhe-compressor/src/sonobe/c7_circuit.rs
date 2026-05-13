//! C7 decryption aggregation step circuit for Sonobe Nova IVC.
//!
//! Each step folds one participant's decryption share contribution into
//! the Nova accumulator. After t steps:
//!   - accumulated_eval   = Σ λ_i · d_i(r)  (plaintext evaluation at challenge point r)
//!   - lagrange_sum       = Σ λ_i            (should equal 1)
//!   - step_count         = t                (number of participants folded)

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};

use pvthfhe_domain_tags::Tag;

use super::{ExternalInputs3, ExternalInputs3Var, SonobeCompressor};
use crate::{CompressedProof, CompressorError, StepCircuit, StepCircuitDescriptor};
use crate::witness::C7WitnessSet;

/// Step circuit for C7 decryption aggregation.
///
/// State (3 elements):
///   z[0] = accumulated share evaluation    Σ λ_i · d_i(r)
///   z[1] = accumulated Lagrange sum        Σ λ_i
///   z[2] = step count                      number of participants folded
///
/// Per-step external inputs:
///   ext.0 = participant share evaluation   d_i(r)
///   ext.1 = Lagrange coefficient           λ_i
///   ext.2 = participant hash               commitment to the share
#[derive(Clone, Copy, Debug)]
pub struct C7DecryptAggregationCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for C7DecryptAggregationCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _field: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // z'[0] = z[0] + ext.1 * ext.0   (acc_eval += λ_i · d_i(r))
        let acc_eval = z_i[0].clone() + external_inputs.1.clone() * external_inputs.0;

        // z'[1] = z[1] + ext.1            (lagrange_sum += λ_i)
        let lagrange_sum = z_i[1].clone() + external_inputs.1;

        // z'[2] = z[2] + 1                (step_count += 1)
        let step_count = z_i[2].clone() + FpVar::constant(F::from(1u64));

        Ok(vec![acc_eval, lagrange_sum, step_count])
    }
}

impl<F: PrimeField> StepCircuit for C7DecryptAggregationCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::PvssC7DecryptAggregation.as_bytes()).into()
    }
}

/// Fold a set of C7 witnesses through Nova IVC using per-step external inputs.
///
/// This function:
/// 1. Verifies all Merkle proofs off-circuit (SECURITY: must pass!)
/// 2. Builds initial Nova state `[0, 0, 0]`
/// 3. Creates per-step `ExternalInputs3` from `(share_eval, lagrange_coeff, merkle_root)`
/// 4. Calls `compressor.prove_steps()` with the per-step inputs
/// 5. Returns the compressed proof
pub fn c7_fold_witnesses(
    compressor: &SonobeCompressor<C7DecryptAggregationCircuit<ark_bn254::Fr>>,
    witnesses: &C7WitnessSet,
    acc: &[u8],
) -> Result<CompressedProof, CompressorError> {
    use ark_bn254::Fr;

    if !witnesses.verify_merkle_proofs() {
        return Err(CompressorError::InvalidProof);
    }

    let steps: Vec<ExternalInputs3<Fr>> = witnesses
        .participants
        .iter()
        .map(|w| ExternalInputs3(w.share_eval, w.lagrange_coeff, w.merkle_root))
        .collect();

    compressor.prove_steps(acc, &steps)
}
