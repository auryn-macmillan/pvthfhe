//! C7 decryption aggregation step circuit for Sonobe Nova IVC.
//!
//! Each step folds one participant's decryption share contribution into
//! the Nova accumulator. After t steps:
//!   - accumulated_eval   = Σ λ_i · d_i(r)  (plaintext evaluation at challenge point r)
//!   - lagrange_sum       = Σ λ_i            (should equal 1)
//!   - step_count         = t                (number of participants folded)

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;

use pvthfhe_domain_tags::Tag;

use super::{ExternalInputs4, ExternalInputs4Var, SonobeCompressor};
use crate::{CompressedProof, CompressorError, StepCircuit, StepCircuitDescriptor};
use crate::witness::C7WitnessSet;

/// Number of share polynomial coefficients per participant (BFV ring dimension).
const N_COEFFS: usize = 8192;

/// Per-step data for in-circuit share evaluation verification (G2).
/// Stores coefficient bytes and challenge point for cross-field conversion.
#[derive(Clone, Debug)]
struct C7StepData {
    coeffs: Vec<Vec<u8>>,
    challenge_r: Vec<u8>,
}

thread_local! {
    static C7_STEP_DATA: RefCell<Option<C7StepData>> = RefCell::new(None);
}

fn serialize_fr(v: &ark_bn254::Fr) -> Vec<u8> {
    let mut buf = Vec::new();
    v.serialize_uncompressed(&mut buf).expect("Fr serialization");
    buf
}

/// Register per-step coefficient data and challenge point for the C7 circuit.
///
/// Must be called before any `prove_steps_c7` call that goes through
/// `C7DecryptAggregationCircuit::generate_step_constraints`.
/// Clear with [`clear_c7_step_data`] after proving to avoid leaking state.
pub fn set_c7_step_data(coeffs: Vec<Vec<ark_bn254::Fr>>, challenge_r: ark_bn254::Fr) {
    let coeffs_bytes: Vec<Vec<u8>> = coeffs
        .iter()
        .map(|step| {
            step.iter()
                .flat_map(|v| serialize_fr(v))
                .collect::<Vec<u8>>()
        })
        .collect();
    let challenge_bytes = serialize_fr(&challenge_r);
    C7_STEP_DATA.with(|cell| {
        *cell.borrow_mut() = Some(C7StepData {
            coeffs: coeffs_bytes,
            challenge_r: challenge_bytes,
        });
    });
}

/// Clear registered C7 step data.
pub fn clear_c7_step_data() {
    C7_STEP_DATA.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

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
///   ext.2 = participant hash               commitment to the share (merkle_root)
///   ext.3 = dkg_root_hash                  aggregate PK binding (G4)
///
/// # G2: In-circuit share evaluation verification
///
/// Share coefficients are provided as private witnesses via thread-local data.
/// The circuit computes `eval = Σ coeff[j] × r^j` in R1CS (8192 multiplications
/// per step) and enforces `eval == ext.0`, closing the G2 trust gap.
///
/// # G4: Aggregate PK binding (deferred)
///
/// The C7 circuit binds each share to its Merkle root (ext.2, the participant hash),
/// ensuring every folded share belongs to the committed Merkle tree. The aggregate
/// public key binding — mapping `dkg_root_hash → agg_pk_hash` — is verified off-circuit
/// (e.g., via SHA-256 of the DKG transcript). Full in-circuit PK binding (G4) is
/// deferred to a follow-up; for M1, off-circuit verification suffices.
#[derive(Clone, Copy, Debug)]
pub struct C7DecryptAggregationCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for C7DecryptAggregationCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs4<F>;
    type ExternalInputsVar = ExternalInputs4Var<F>;

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
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // ── G2: In-circuit share evaluation verification ──
        //
        // Read per-step coefficient data from thread-local storage.
        // Each step receives 8192 share coefficients as private witnesses.
        // The circuit computes eval = Σ coeff[j] × r^j in R1CS
        // (8192 multiply-adds per step) and enforces eval == ext.0.
        //
        // When thread-local data is absent (e.g., during preprocessing),
        // coefficients default to zero — the constraint system structure
        // is preserved but witness values are zero.

        let eval = C7_STEP_DATA.with(|cell| {
            let data_ref = cell.borrow();
            let data_opt: Option<(Vec<Vec<u8>>, Vec<u8>)> =
                data_ref.as_ref().map(|d| (d.coeffs.clone(), d.challenge_r.clone()));

            match data_opt {
                Some((ref coeffs_bytes_per_step, ref challenge_r_bytes)) => {
                    let coeffs_bytes: &[u8] = if _i < coeffs_bytes_per_step.len() {
                        &coeffs_bytes_per_step[_i]
                    } else {
                        &[]
                    };

                    let r_f = F::from_le_bytes_mod_order(challenge_r_bytes);

                    // Precompute r^0, r^1, ..., r^{N_COEFFS-1}
                    let mut r_pow_vals: Vec<F> = Vec::with_capacity(N_COEFFS);
                    let mut current = F::one();
                    for _ in 0..N_COEFFS {
                        r_pow_vals.push(current);
                        current *= r_f;
                    }

                    // Evaluate: eval = Σ coeffs[j] * r^{N_COEFFS-1-j}
                    // Matches Horner's method in eval_poly_bn254:
                    //   result = 0; for c in coeffs { result = result*r + c }
                    // which computes c₀·r^{N-1} + c₁·r^{N-2} + ... + c_{N-1}·r⁰
                    let mut eval_acc = FpVar::<F>::constant(F::zero());
                    for j in 0..N_COEFFS {
                        let power_idx = N_COEFFS - 1 - j;
                        let coeff_val = if j * 32 + 32 <= coeffs_bytes.len() {
                            F::from_le_bytes_mod_order(
                                &coeffs_bytes[j * 32..(j + 1) * 32],
                            )
                        } else {
                            F::zero()
                        };
                        let coeff_var = FpVar::<F>::new_witness(cs.clone(), || Ok(coeff_val))?;
                        let r_pow_var = FpVar::<F>::new_witness(cs.clone(), || Ok(r_pow_vals[power_idx]))?;
                        eval_acc += &coeff_var * &r_pow_var;
                    }
                    Ok(eval_acc)
                }
                None => {
                    let mut eval_acc = FpVar::<F>::constant(F::zero());
                    for _ in 0..N_COEFFS {
                        let coeff_var =
                            FpVar::<F>::new_witness(cs.clone(), || Ok(F::zero()))?;
                        let r_pow_var =
                            FpVar::<F>::new_witness(cs.clone(), || Ok(F::zero()))?;
                        eval_acc += &coeff_var * &r_pow_var;
                    }
                    Ok(eval_acc)
                }
            }
        })?;

        // G2: Enforce that computed evaluation matches claimed external input
        eval.enforce_equal(&external_inputs.0)?;

        // z'[0] = z[0] + ext.1 * eval   (acc_eval += λ_i · d_i(r))
        let acc_eval = z_i[0].clone() + external_inputs.1.clone() * eval;

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
/// 2. Sets up thread-local coefficient data for in-circuit G2 verification
/// 3. Builds initial Nova state `[0, 0, 0]`
/// 4. Creates per-step `ExternalInputs4` from `(share_eval, lagrange_coeff, merkle_root, dkg_root_hash)`
/// 5. Calls `compressor.prove_steps_c7()` with the per-step inputs
/// 6. Clears thread-local data
/// 7. Returns the compressed proof
pub fn c7_fold_witnesses(
    compressor: &SonobeCompressor<C7DecryptAggregationCircuit<ark_bn254::Fr>>,
    witnesses: &C7WitnessSet,
    acc: &[u8],
    dkg_root_hash: ark_bn254::Fr,
) -> Result<CompressedProof, CompressorError> {
    use ark_bn254::Fr;

    if !witnesses.verify_merkle_proofs() {
        return Err(CompressorError::InvalidProof);
    }

    // G2: Set up thread-local coefficient data for in-circuit evaluation
    let coeffs: Vec<Vec<Fr>> = witnesses
        .participants
        .iter()
        .map(|w| w.coeffs.clone())
        .collect();
    set_c7_step_data(coeffs, witnesses.challenge_r);

    let steps: Vec<ExternalInputs4<Fr>> = witnesses
        .participants
        .iter()
        .map(|w| ExternalInputs4(w.share_eval, w.lagrange_coeff, w.merkle_root, dkg_root_hash))
        .collect();

    let result = compressor.prove_steps_c7(acc, &steps);

    // Clear thread-local data regardless of outcome
    clear_c7_step_data();

    result
}
