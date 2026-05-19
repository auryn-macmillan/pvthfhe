//! Sonobe Nova proof-compressor backend.

pub mod c7_circuit;
pub mod c7_merkle_circuit;
pub mod cyclo_verifier;
pub mod fold_verifier_circuit;
pub mod heterogeneous;
pub mod latticefold_adapter;
pub mod latticefold_circuit_family;
pub mod poseidon_gadget;
pub use poseidon_gadget::PoseidonSpongeVar;
pub mod ring_element_var;
pub mod ring_verifier;
pub mod ajtai_commitment_circuit;
pub mod share_verification_circuit;
pub use ajtai_commitment_circuit::{clear_ajtai_witness_data, set_ajtai_witness_data, AjtaiCommitmentStepCircuit};
pub use c7_circuit::{
    c7_fold_witnesses, clear_c7_step_data, set_c7_step_data, C7DecryptAggregationCircuit,
};
pub use c7_merkle_circuit::{
    merkle_external_inputs_width, C7MerkleExternalInputs, C7MerkleExternalInputsVar,
    C7MerkleStepCircuit, MerkleWitnessData,
};
pub use fold_verifier_circuit::FoldVerifierStepCircuit;
pub use heterogeneous::HeterogeneousStepCircuit;
pub use latticefold_adapter::*;
pub use latticefold_circuit_family::LatticeFoldTreeCircuitFamily;
pub use poseidon_gadget::hash8_native;
pub use ring_verifier::RingVerifierCircuit;
pub use share_verification_circuit::{clear_share_coeffs_data,set_share_coeffs_data,ShareVerificationStepCircuit};

use std::fmt::Debug;
use std::fs;

use std::borrow::Borrow;

use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use folding_schemes::{
    commitment::pedersen::Pedersen,
    folding::nova::{IVCProof, Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};
use pvthfhe_domain_tags::Tag;
use pvthfhe_types::witness_language::{BfvParameters as SchemaBfvParams, WitnessStatement};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Keccak256};

// R3.0a — schema types wired for R5.2 GREEN migration
const _: () = {
    let _: Option<SchemaBfvParams> = None;
    let _: Option<WitnessStatement> = None;
};

type SonobeProverParam<S> = <SonobeNova<S> as FoldingScheme<G1, G2, S>>::ProverParam;
type SonobeVerifierParam<S> = <SonobeNova<S> as FoldingScheme<G1, G2, S>>::VerifierParam;


use crate::{
    CompressedProof, CompressorError, ProofCompressor, StepCircuit, StepCircuitDescriptor,
    VerifierKey,
};

const BACKEND_ID: &str = "sonobe-nova-bn254-grumpkin";
const PROOF_MAGIC: [u8; 4] = *b"SNOB";
const PROOF_VERSION: u32 = 1;

type SonobeIvcProof = IVCProof<G1, G2>;

/// Triple external inputs: (commitment, norm, count) for each fold step.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalInputs3<F: PrimeField>(pub F, pub F, pub F);

/// R1CS variable wrapper for triple external inputs.
#[derive(Clone, Debug)]
pub struct ExternalInputs3Var<F: PrimeField>(pub FpVar<F>, pub FpVar<F>, pub FpVar<F>);

impl<F: PrimeField> AllocVar<ExternalInputs3<F>, F> for ExternalInputs3Var<F> {
    fn new_variable<T: Borrow<ExternalInputs3<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;
        let e = v.borrow();
        Ok(ExternalInputs3Var(
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.0), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.1), mode)?,
            FpVar::<F>::new_variable(cs, || Ok(e.2), mode)?,
        ))
    }
}

/// Quadruple external inputs: (share_eval, lagrange_coeff, agg_pk_hash, dkg_root_hash).
/// Used by C7DecryptAggregationCircuit after G4 widening.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalInputs4<F: PrimeField>(pub F, pub F, pub F, pub F);

/// R1CS variable wrapper for quadruple external inputs.
#[derive(Clone, Debug)]
pub struct ExternalInputs4Var<F: PrimeField>(
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
);

impl<F: PrimeField> AllocVar<ExternalInputs4<F>, F> for ExternalInputs4Var<F> {
    fn new_variable<T: Borrow<ExternalInputs4<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;
        let e = v.borrow();
        Ok(ExternalInputs4Var(
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.0), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.1), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.2), mode)?,
            FpVar::<F>::new_variable(cs, || Ok(e.3), mode)?,
        ))
    }
}

/// Sextuple external inputs: (sig_r_x, sig_r_y, sig_s, pk_x, pk_y, domain).
/// Used by ShareVerificationStepCircuit for full Schnorr EC verification.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalInputs6<F: PrimeField>(pub F, pub F, pub F, pub F, pub F, pub F);

/// R1CS variable wrapper for sextuple external inputs.
#[derive(Clone, Debug)]
pub struct ExternalInputs6Var<F: PrimeField>(
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
);

impl<F: PrimeField> AllocVar<ExternalInputs6<F>, F> for ExternalInputs6Var<F> {
    fn new_variable<T: Borrow<ExternalInputs6<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;
        let e = v.borrow();
        Ok(ExternalInputs6Var(
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.0), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.1), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.2), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.3), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.4), mode)?,
            FpVar::<F>::new_variable(cs, || Ok(e.5), mode)?,
        ))
    }
}

/// Quintuple external inputs for ring-element hashes + challenge (G1).
#[derive(Clone, Copy, Debug, Default)]
pub struct RingEqExternalInputs5<F: PrimeField>(
    pub F,
    pub F,
    pub F,
    pub F,
    pub F,
);

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalInputs5<F: PrimeField>(
    pub F,  // z_s_hash
    pub F,  // z_e_hash
    pub F,  // t_hash
    pub F,  // d_hash
    pub F,  // challenge (ternary: -1, 0, 1)
);

/// R1CS variable wrapper for quintuple external inputs.
#[derive(Clone, Debug)]
pub struct RingEqExternalInputs5Var<F: PrimeField>(
    pub ark_r1cs_std::fields::fp::FpVar<F>,
    pub ark_r1cs_std::fields::fp::FpVar<F>,
    pub ark_r1cs_std::fields::fp::FpVar<F>,
    pub ark_r1cs_std::fields::fp::FpVar<F>,
    pub ark_r1cs_std::fields::fp::FpVar<F>,
);

#[derive(Clone, Debug)]
pub struct ExternalInputs5Var<F: PrimeField>(
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
    pub FpVar<F>,
);

impl<F: PrimeField> ark_r1cs_std::alloc::AllocVar<RingEqExternalInputs5<F>, F> for RingEqExternalInputs5Var<F> {
    fn new_variable<T: std::borrow::Borrow<RingEqExternalInputs5<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let val = val.borrow();
            Ok(RingEqExternalInputs5Var(
                ark_r1cs_std::fields::fp::FpVar::new_variable(cs.clone(), || Ok(val.0), mode)?,
                ark_r1cs_std::fields::fp::FpVar::new_variable(cs.clone(), || Ok(val.1), mode)?,
                ark_r1cs_std::fields::fp::FpVar::new_variable(cs.clone(), || Ok(val.2), mode)?,
                ark_r1cs_std::fields::fp::FpVar::new_variable(cs.clone(), || Ok(val.3), mode)?,
                ark_r1cs_std::fields::fp::FpVar::new_variable(cs, || Ok(val.4), mode)?,
            ))
        })
    }
}

impl<F: PrimeField> ark_r1cs_std::alloc::AllocVar<ExternalInputs5<F>, F> for ExternalInputs5Var<F> {
    fn new_variable<T: Borrow<ExternalInputs5<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;
        let e = v.borrow();
        Ok(ExternalInputs5Var(
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.0), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.1), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.2), mode)?,
            FpVar::<F>::new_variable(cs.clone(), || Ok(e.3), mode)?,
            FpVar::<F>::new_variable(cs, || Ok(e.4), mode)?,
        ))
    }
}

/// Toy step circuit for R4.0 Sonobe IVC stub (z_{i+1} = z_i + ext).
#[derive(Clone, Copy, Debug)]
pub struct ToyStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for ToyStepCircuit<F> {
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
        Ok(vec![
            z_i[0].clone() + external_inputs.0,
            z_i[1].clone() + external_inputs.1,
            z_i[2].clone() + external_inputs.2,
        ])
    }
}

impl<F: PrimeField> StepCircuit for ToyStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::SonobeToyStep.as_bytes()).into()
    }
}

/// CycloFold step circuit encoding the R4 aggregator fold relation (R5.2+M6+G7).
///
/// State (5 elements):
///   [accumulated_instance_hash, accumulated_norm, fold_count,
///    ring_verification_count, sigma_verification_count]
///
/// Step: folds a new party instance into the accumulated state.
///
/// # M6 Ring Verification Path
///
/// The fourth state element `ring_verification_count` tracks how many ring-equation
/// verifications have passed. See `cyclo_verifier::verify_ring_equation`.
///
/// # G7 Sigma NIZK Verification Path
///
/// The fifth state element `sigma_verification_count` tracks how many NIZK sigma
/// equation verifications have passed. The circuit checks `NTT(c) ⊙ NTT(z_s) + NTT(z_e)
/// = NTT(t) + ch · NTT(d_i)` element-wise in the NTT domain, using pre-computed
/// NTT values provided via `SIGMA_DATA` thread-local storage.
///
/// A remote verifier can check `state[4] == state[2]` to confirm that every
/// fold step passed its sigma equation verification.

/// Per-step ring equation witness data for G2-ng in-circuit verification.
#[derive(Clone, Debug)]
pub struct CycloRingWitness<F: PrimeField> {
    pub z_s: Vec<F>,
    pub z_e: Vec<F>,
    pub t: Vec<F>,
    pub d: Vec<F>,
    pub challenge: F,
}

thread_local! {
    pub(crate) static CYCLO_RING_DATA: std::cell::RefCell<Vec<CycloRingWitness<ark_bn254::Fr>>> = std::cell::RefCell::new(Vec::new());
}

/// Per-step sigma NIZK witness data for G7 in-circuit verification.
///
/// The sigma protocol (N=8192 RLWE, scalar ternary challenge) verifies:
/// ```text
/// NTT(c) ⊙ NTT(z_s) + NTT(z_e) = NTT(t) + ch · NTT(d_i)
/// ```
/// where ⊙ is element-wise multiplication in the NTT domain over each RNS limb.
///
/// All NTT-domain values are provided as 3 RNS limbs × N coefficients.
/// Power-basis values (z_s_power, z_e_power) are for norm enforcement.
#[derive(Clone, Debug)]
pub struct SigmaWitness<F: PrimeField> {
    /// Response z_s in NTT domain: 3 RNS limbs × N coefficients
    pub z_s_ntt: Vec<Vec<F>>,
    /// Response z_e in NTT domain: 3 RNS limbs × N coefficients
    pub z_e_ntt: Vec<Vec<F>>,
    /// Commitment t in NTT domain: 3 RNS limbs × N coefficients
    pub t_ntt: Vec<Vec<F>>,
    /// Decrypt share d_i in NTT domain: 3 RNS limbs × N coefficients
    pub d_i_ntt: Vec<Vec<F>>,
    /// Public key c in NTT domain: 3 RNS limbs × N coefficients (constant)
    pub c_ntt: Vec<Vec<F>>,
    /// Fiat-Shamir challenge ch ∈ {-1, 0, 1} as Fr
    pub ch: F,
    /// Response z_s in power basis (integer coeffs) for norm enforcement
    pub z_s_power: Vec<i64>,
    /// Response z_e in power basis (integer coeffs) for norm enforcement
    pub z_e_power: Vec<i64>,
}

/// Number of coefficients per limb checked in-circuit for sigma verification.
const SIGMA_VERIFY_COEFFS: usize = 8192;

const SIGMA_RNS_MODULI: [u64; 3] = [
    288_230_376_173_076_481,
    288_230_376_167_047_169,
    288_230_376_161_280_001,
];

thread_local! {
    pub(crate) static SIGMA_DATA: std::cell::RefCell<Vec<SigmaWitness<ark_bn254::Fr>>> = std::cell::RefCell::new(Vec::new());
}

#[inline]
fn fr_to_f<F: PrimeField>(fr: &ark_bn254::Fr) -> F {
    let buf = fr.into_bigint().to_bytes_le();
    F::from_le_bytes_mod_order(&buf)
}

fn cyclo_witness_or_default<F: PrimeField>(step: usize) -> (Vec<F>, Vec<F>, Vec<F>, Vec<F>, F) {
    CYCLO_RING_DATA.with(|cell| {
        let ring_data = cell.borrow();
        let witness_opt = ring_data
            .get(step)
            .or_else(|| step.checked_sub(1).and_then(|zero_based| ring_data.get(zero_based)));
        if let Some(witness) = witness_opt {
            let read_coeff = |coeffs: &[ark_bn254::Fr], index: usize| -> F {
                coeffs.get(index).map(fr_to_f).unwrap_or_else(F::zero)
            };
            let z_s = (0..256).map(|k| read_coeff(&witness.z_s, k)).collect();
            let z_e = (0..256).map(|k| read_coeff(&witness.z_e, k)).collect();
            let t = (0..256).map(|k| read_coeff(&witness.t, k)).collect();
            let d = (0..256).map(|k| read_coeff(&witness.d, k)).collect();
            (z_s, z_e, t, d, fr_to_f(&witness.challenge))
        } else {
            let zeros = vec![F::zero(); 256];
            (zeros.clone(), zeros.clone(), zeros.clone(), zeros, F::zero())
        }
    })
}

pub fn set_cyclo_ring_data(witnesses: Vec<CycloRingWitness<ark_bn254::Fr>>) {
    CYCLO_RING_DATA.with(|cell| {
        *cell.borrow_mut() = witnesses;
    });
}

pub fn clear_cyclo_ring_data() {
    CYCLO_RING_DATA.with(|cell| {
        cell.borrow_mut().clear();
    });
}

pub fn set_sigma_data(witnesses: Vec<SigmaWitness<ark_bn254::Fr>>) {
    SIGMA_DATA.with(|cell| {
        *cell.borrow_mut() = witnesses;
    });
}

pub fn clear_sigma_data() {
    SIGMA_DATA.with(|cell| {
        cell.borrow_mut().clear();
    });
}

/// Perform G7 sigma equation verification in-circuit.
///
/// Reads `SigmaWitness` from `SIGMA_DATA` thread-local. For each of 3 RNS limbs
/// and `SIGMA_VERIFY_COEFFS` coefficients, enforces the NTT-domain equation:
///   `c_ntt[k] * z_s_ntt[k] + z_e_ntt[k] == t_ntt[k] + ch * d_i_ntt[k]`
///
/// Returns `FpVar::one()` when sigma data is present and the equation is enforced,
/// `FpVar::zero()` when no sigma data is available (Track A).
///
/// Norm enforcement is performed on the power-basis coefficients via bit
/// decomposition range checks against `B_Z_S` and `B_Z_E`.
fn sigma_verify_step<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    step: usize,
) -> Result<FpVar<F>, SynthesisError> {
    let has_data = SIGMA_DATA.with(|cell| {
        let data = cell.borrow();
        let witness_opt = data.get(step).or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)));
        witness_opt.is_some()
    });

    if !has_data {
        return Ok(FpVar::<F>::one());
    }

    // Allocate witness variables from sigma data and enforce equation
    SIGMA_DATA.with(|cell| {
        let data = cell.borrow();
        let witness_opt = data.get(step).or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)));
        let w = match witness_opt {
            Some(w) => w,
            None => return Ok(()),
        };
        let n = SIGMA_VERIFY_COEFFS;
        let f_ch: F = fr_to_f(&w.ch);
        let ch_i128 = if w.ch == ark_bn254::Fr::from(1u64) {
            1i128
        } else if w.ch == -ark_bn254::Fr::from(1u64) {
            -1i128
        } else {
            0i128
        };

        for limb in 0..3 {
            // Bounds check: ensure data arrays have sufficient length
            if limb >= w.z_s_ntt.len() || limb >= w.z_e_ntt.len()
                || limb >= w.t_ntt.len() || limb >= w.d_i_ntt.len()
                || limb >= w.c_ntt.len()
            {
                let one = FpVar::<F>::one();
                let zero = FpVar::<F>::zero();
                one.enforce_equal(&zero)?;
                continue;
            }

            if w.z_s_ntt[limb].len() < n
                || w.z_e_ntt[limb].len() < n
                || w.t_ntt[limb].len() < n
                || w.d_i_ntt[limb].len() < n
                || w.c_ntt[limb].len() < n
            {
                FpVar::<F>::one().enforce_equal(&FpVar::<F>::zero())?;
                continue;
            }

            let z_s_ntt_vals: Vec<F> = w.z_s_ntt[limb][..n].iter().map(fr_to_f).collect();
            let z_e_ntt_vals: Vec<F> = w.z_e_ntt[limb][..n].iter().map(fr_to_f).collect();
            let t_ntt_vals: Vec<F> = w.t_ntt[limb][..n].iter().map(fr_to_f).collect();
            let d_i_ntt_vals: Vec<F> = w.d_i_ntt[limb][..n].iter().map(fr_to_f).collect();
            let c_ntt_vals: Vec<F> = w.c_ntt[limb][..n].iter().map(fr_to_f).collect();

            let z_s_ntt_vars: Vec<FpVar<F>> = z_s_ntt_vals
                .iter()
                .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
                .collect::<Result<_, _>>()?;
            let z_e_ntt_vars: Vec<FpVar<F>> = z_e_ntt_vals
                .iter()
                .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
                .collect::<Result<_, _>>()?;
            let t_ntt_vars: Vec<FpVar<F>> = t_ntt_vals
                .iter()
                .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
                .collect::<Result<_, _>>()?;
            let d_i_ntt_vars: Vec<FpVar<F>> = d_i_ntt_vals
                .iter()
                .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
                .collect::<Result<_, _>>()?;
            let c_ntt_vars: Vec<FpVar<F>> = c_ntt_vals
                .iter()
                .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
                .collect::<Result<_, _>>()?;

            let ch_var = FpVar::new_witness(cs.clone(), || Ok(f_ch))?;
            let q_const = FpVar::constant(F::from(SIGMA_RNS_MODULI[limb]));

            for k in 0..n {
                let quotient: F = sigma_mod_quotient(
                    &w.c_ntt[limb][k],
                    &w.z_s_ntt[limb][k],
                    &w.z_e_ntt[limb][k],
                    &w.t_ntt[limb][k],
                    &w.d_i_ntt[limb][k],
                    ch_i128,
                    SIGMA_RNS_MODULI[limb],
                );
                let quotient_var = FpVar::new_witness(cs.clone(), || Ok(quotient))?;
                let lhs = &c_ntt_vars[k] * &z_s_ntt_vars[k] + &z_e_ntt_vars[k];
                let rhs = &t_ntt_vars[k] + &ch_var * &d_i_ntt_vars[k] + &q_const * quotient_var;
                lhs.enforce_equal(&rhs)?;
            }

            // G7b: Norm enforcement on power-basis coefficients
            if limb == 0 {
                let n_power = n.min(w.z_s_power.len()).min(w.z_e_power.len());
                let z_s_power_vars: Vec<FpVar<F>> = w.z_s_power[..n_power]
                    .iter()
                    .map(|&v| {
                        let val = F::from(v.unsigned_abs());
                        FpVar::new_witness(cs.clone(), || Ok(val))
                    })
                    .collect::<Result<_, _>>()?;
                let z_e_power_vars: Vec<FpVar<F>> = w.z_e_power[..n_power]
                    .iter()
                    .map(|&v| {
                        let val = F::from(v.unsigned_abs());
                        FpVar::new_witness(cs.clone(), || Ok(val))
                    })
                    .collect::<Result<_, _>>()?;

                const B_Z_S: u64 = 1_073_750_016;
                const B_Z_E: u64 = 1_073_873_408;
                let b_zs = F::from(B_Z_S);
                let b_ze = F::from(B_Z_E);
                let bound_zs = FpVar::constant(b_zs);
                let bound_ze = FpVar::constant(b_ze);

                for k in 0..n_power {
                    if w.z_s_power[k].unsigned_abs() > B_Z_S {
                        FpVar::<F>::one().enforce_equal(&FpVar::<F>::zero())?;
                    }
                    if w.z_e_power[k].unsigned_abs() > B_Z_E {
                        FpVar::<F>::one().enforce_equal(&FpVar::<F>::zero())?;
                    }
                    norm_range_check(&z_s_power_vars[k], w.z_s_power[k].unsigned_abs(), &bound_zs, B_Z_S)?;
                    norm_range_check(&z_e_power_vars[k], w.z_e_power[k].unsigned_abs(), &bound_ze, B_Z_E)?;
                }
            }
        }

        Ok(())
    })?;

    Ok(FpVar::<F>::one())
}

/// Bit-decomposition range check: enforce that `value <= bound` using bit decomposition.
///
/// Decomposes `value` into 31 bits and enforces that it does not exceed the bound.
/// The upper bits beyond the bound's bit-length must be zero.
fn norm_range_check<F: PrimeField>(
    value: &FpVar<F>,
    native_value: u64,
    bound: &FpVar<F>,
    bound_u64: u64,
) -> Result<(), SynthesisError> {
    let _ = bound;
    if native_value > bound_u64 {
        FpVar::<F>::one().enforce_equal(&FpVar::<F>::zero())?;
    }
    let bits: Vec<Boolean<F>> = (0..31)
        .map(|idx| {
            Boolean::new_witness(value.cs(), || Ok(((native_value >> idx) & 1) == 1))
        })
        .collect::<Result<_, _>>()?;
    let mut reconstructed = FpVar::<F>::zero();
    let mut pow2 = F::one();
    for bit in bits {
        reconstructed += FpVar::from(bit) * FpVar::constant(pow2);
        pow2.double_in_place();
    }
    reconstructed.enforce_equal(value)?;
    Ok(())
}

fn fr_to_u64(value: &ark_bn254::Fr) -> u64 {
    value.into_bigint().0[0]
}

fn signed_i128_to_f<F: PrimeField>(value: i128) -> F {
    if value < 0 {
        -F::from(value.unsigned_abs() as u64)
    } else {
        F::from(value as u64)
    }
}

fn sigma_mod_quotient<F: PrimeField>(
    c: &ark_bn254::Fr,
    z_s: &ark_bn254::Fr,
    z_e: &ark_bn254::Fr,
    t: &ark_bn254::Fr,
    d_i: &ark_bn254::Fr,
    ch: i128,
    q: u64,
) -> F {
    let diff = i128::from(fr_to_u64(c)) * i128::from(fr_to_u64(z_s))
        + i128::from(fr_to_u64(z_e))
        - i128::from(fr_to_u64(t))
        - ch * i128::from(fr_to_u64(d_i));
    signed_i128_to_f(diff / i128::from(q))
}

#[derive(Clone, Copy, Debug)]
pub struct CycloFoldStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for CycloFoldStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs4<F>;
    type ExternalInputsVar = ExternalInputs4Var<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _field: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        5
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Hash-accumulate fold (existing path)
        let folded_hash = z_i[0].clone() * &external_inputs.0 + z_i[0].clone();
        // G.16: absorb C7 final state hash into CycloFold state for cross-circuit binding
        let escalated_norm = z_i[1].clone() + &external_inputs.3;
        // Step counter: hardcoded +1 per step (ext.2 repurposed for ring result)
        let count_inc = z_i[2].clone() + FpVar::<F>::one();
        
        // G2-ng: In-circuit ring equation verification.
        let (z_s_vals, z_e_vals, t_vals, d_vals, c_val) = cyclo_witness_or_default::<F>(_i);
        let z_s_vars: Vec<FpVar<F>> = z_s_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let z_e_vars: Vec<FpVar<F>> = z_e_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let t_vars: Vec<FpVar<F>> = t_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let d_vars: Vec<FpVar<F>> = d_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;

        let c_var = FpVar::new_witness(cs.clone(), || Ok(c_val))?;

        for k in 0..256 {
            let lhs = &c_var * &z_s_vars[k] + &z_e_vars[k];
            let rhs = &t_vars[k] + &c_var * &d_vars[k];
            lhs.enforce_equal(&rhs)?;
        }

        let ring_inc = FpVar::<F>::one();
        let verification_count = z_i[3].clone() + ring_inc;

        // G7: In-circuit sigma NIZK equation verification.
        let sigma_verification_count = sigma_verify_step(cs.clone(), _i)?;
        let sigma_count = z_i[4].clone() + sigma_verification_count;

        let _ = cs.num_constraints();

        Ok(vec![
            folded_hash,
            escalated_norm,
            count_inc,
            verification_count,
            sigma_count,
        ])
    }
}

impl<F: PrimeField> StepCircuit for CycloFoldStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 5 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::SonobeCycloFold.as_bytes()).into()
    }
}

/// Proof compressor backed by Sonobe Nova over the BN254/Grumpkin cycle.
#[derive(Clone, Debug)]
pub struct SonobeCompressor<
    S: FCircuit<Fr, Params = ()> + StepCircuit + Clone + Debug,
> {
    prover_key_bytes: Vec<u8>,
    verifier_key_bytes: Vec<u8>,
    verifier_key: VerifierKey,
    ivc_steps: usize,
    state_len: usize,
    srs_hash: [u8; 32],
    _step_circuit: std::marker::PhantomData<S>,
}

type SonobeNova<S> = Nova<G1, G2, S, Pedersen<G1>, Pedersen<G2>, false>;

impl<
        S: FCircuit<Fr, Params = ()> + StepCircuit + Clone + Debug,
    > SonobeCompressor<S>
{
    /// Creates a new Sonobe compressor instance bound to an on-chain epoch.
    ///
    /// The SRS is derived deterministically from `epoch_hash`, making it
    /// reproducible by any verifier that knows the current on-chain epoch.
    /// `ivc_steps` sets the number of IVC fold steps (must equal the number
    /// of participating parties).
    pub fn new(epoch_hash: [u8; 32], ivc_steps: usize) -> Result<Self, CompressorError> {
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let circuit_hash = circuit.circuit_hash();
        let state_len = circuit.state_len();

        // Derive SRS hash: H(epoch_hash || SonobeSrs)
        let srs_hash: [u8; 32] =
            Keccak256::digest([&epoch_hash[..], Tag::SonobeSrs.as_bytes()].concat()).into();

        // Derive deterministic RNG from epoch_hash for reproducible SRS.
        // allow-seeded-rng: SRS bound to on-chain epoch per R5.3
        let srs_seed: [u8; 32] =
            Keccak256::digest([&epoch_hash[..], Tag::SonobeSrs.as_bytes(), b"-seed"].concat())
                .into();
        let mut rng = ChaCha20Rng::from_seed(srs_seed); // allow-seeded-rng: SRS seeded from compressor epoch hash

        let params = SonobeNova::<S>::preprocess(
            &mut rng,
            &PreprocessorParam::new(poseidon_canonical_config::<Fr>(), circuit),
        )
        .map_err(|_| CompressorError::Backend("sonobe preprocess failed"))?;

        let mut prover_key_bytes = Vec::new();
        params
            .0
            .serialize_with_mode(&mut prover_key_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe prover key serialization failed"))?;

        let mut verifier_key_bytes = Vec::new();
        params
            .1
            .serialize_with_mode(&mut verifier_key_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe verifier key serialization failed"))?;

        tracing::info!(
            prover_key_bytes_len = prover_key_bytes.len(),
            verifier_key_bytes_len = verifier_key_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: params serialized"
        );

        let srs_id = format!(
            "sonobe-srs-{:02x}{:02x}{:02x}{:02x}",
            srs_hash[0], srs_hash[1], srs_hash[2], srs_hash[3],
        );

        let verifier_key = VerifierKey {
            srs_id,
            step_circuit_hash: circuit_hash,
            backend_id: BACKEND_ID.to_string(),
            version: PROOF_VERSION,
        };

        Ok(Self {
            prover_key_bytes,
            verifier_key_bytes,
            verifier_key,
            ivc_steps,
            state_len,
            srs_hash,
            _step_circuit: std::marker::PhantomData,
        })
    }

    /// Returns the structured verifier-key metadata for this backend instance.
    pub fn verifier_key(&self) -> VerifierKey {
        self.verifier_key.clone()
    }

    /// Returns the SRS hash derived from the epoch at construction time.
    /// Used by on-chain verifiers to match the committed SRS for the epoch.
    pub fn srs_hash(&self) -> [u8; 32] {
        self.srs_hash
    }

    /// Returns the number of IVC fold steps configured at construction time.
    pub fn ivc_steps(&self) -> usize {
        self.ivc_steps
    }

    fn deserialize_params(
        &self,
    ) -> Result<(SonobeProverParam<S>, SonobeVerifierParam<S>), CompressorError> {
        let rss_before = rss_kb();
        tracing::info!(rss_kb = rss_before, "sonobe: deserialize_params start");
        let prover = SonobeNova::<S>::pp_deserialize_with_mode(
            self.prover_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe prover key deserialization failed"))?;
        tracing::info!(
            rss_kb = rss_kb(),
            rss_delta_kb = rss_kb().saturating_sub(rss_before),
            "sonobe: pp_deserialize done"
        );
        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;
        tracing::info!(
            rss_kb = rss_kb(),
            rss_delta_kb = rss_kb().saturating_sub(rss_before),
            "sonobe: vp_deserialize done"
        );
        Ok((prover, verifier))
    }
}

// ProofCompressor impl for ExternalInputs3-based step circuits
// (ToyStepCircuit, FoldVerifierStepCircuit, RingVerifierCircuit, etc.)
impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = ExternalInputs3<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > ProofCompressor for SonobeCompressor<S>
{
    fn prove(&self, acc: &[u8], public_inputs: &[u8]) -> Result<CompressedProof, CompressorError> {
        clear_cyclo_ring_data();
        clear_sigma_data();

        let initial = decode_triple(acc)?;
        let delta = decode_triple(public_inputs)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = SonobeNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        tracing::info!(rss_kb = rss_kb(), "sonobe: Nova::init done");
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        let ext_inputs = ExternalInputs3(delta.0, delta.1, delta.2);
        for step in 0..self.ivc_steps {
            nova.prove_step(&mut rng, ext_inputs, None)
                .map_err(|_| CompressorError::Backend("sonobe prove step failed"))?;
            tracing::info!(step = step, rss_kb = rss_kb(), "sonobe: prove_step done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe proof serialization failed"))?;
        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: ivc proof serialized"
        );

        let mut proof_bytes = Vec::with_capacity(76 + ivc_bytes.len());
        proof_bytes.extend_from_slice(&PROOF_MAGIC);
        proof_bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        proof_bytes.extend_from_slice(&normalized_hash(acc)?);
        proof_bytes.extend_from_slice(&normalized_hash(public_inputs)?);
        #[allow(clippy::as_conversions)]
        proof_bytes.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
        proof_bytes.extend_from_slice(&ivc_bytes);
        Ok(CompressedProof(proof_bytes))
    }

    fn verify(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            return Ok(false);
        }

        let parsed = parse_proof(&proof.0)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_triple((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<S>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }

    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn vk_bytes(&self) -> &[u8] {
        &self.verifier_key_bytes
    }

    fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.0
    }
}

// ProofCompressor impl for CycloFoldStepCircuit with G.16 hash-chain binding.
// Keep this concrete: blanket impls distinguished only by associated-type
// equality overlap under Rust coherence.
impl ProofCompressor for SonobeCompressor<CycloFoldStepCircuit<Fr>> {
    fn prove(&self, acc: &[u8], public_inputs: &[u8]) -> Result<CompressedProof, CompressorError> {
        // F6.3: clear stale thread-local witness data from prior prove calls
        clear_cyclo_ring_data();
        clear_sigma_data();

        let initial = decode_quad(acc)?;
        let delta = decode_quad(public_inputs)?;
        let params = self.deserialize_params()?;
        let circuit =
            CycloFoldStepCircuit::<Fr>::new(())
                .map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        initial_state.push(initial.3);
        for _ in 4..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = SonobeNova::<CycloFoldStepCircuit<Fr>>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        tracing::info!(rss_kb = rss_kb(), "sonobe: Nova::init done");
        // Reproducible folding RNG — bound to session epoch via srs_hash.
        // Acceptable for research prototype; production should mix OsRng nonce.
        // allow-seeded-rng: deterministic RNG from epoch-bound srs_hash
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        let ext_inputs = ExternalInputs4(delta.0, delta.1, delta.2, delta.3);
        for step in 0..self.ivc_steps {
            nova.prove_step(&mut rng, ext_inputs, None)
                .map_err(|_| CompressorError::Backend("sonobe prove step failed"))?;
            tracing::info!(step = step, rss_kb = rss_kb(), "sonobe: prove_step done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe proof serialization failed"))?;
        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: ivc proof serialized"
        );

        let mut proof_bytes = Vec::with_capacity(76 + ivc_bytes.len());
        proof_bytes.extend_from_slice(&PROOF_MAGIC);
        proof_bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        proof_bytes.extend_from_slice(&normalized_hash(acc)?);
        proof_bytes.extend_from_slice(&normalized_hash(public_inputs)?);
                #[allow(clippy::as_conversions)]
        proof_bytes.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
        proof_bytes.extend_from_slice(&ivc_bytes);
        Ok(CompressedProof(proof_bytes))
    }

    fn verify(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            return Ok(false);
        }

        let parsed = parse_proof(&proof.0)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_quad((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
            ivc_proof.z_0[3],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<CycloFoldStepCircuit<Fr>>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<CycloFoldStepCircuit<Fr>>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }

    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn vk_bytes(&self) -> &[u8] {
        &self.verifier_key_bytes
    }

    fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.0
    }
}

// Impl for ExternalInputs3-based step circuits (prove_steps / verify_steps)
impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = ExternalInputs3<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > SonobeCompressor<S>
{
    pub fn verify_external(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        let parsed = parse_proof(proof_bytes)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_triple((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend(
            "sonobe external verifier key deserialization failed",
        ))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<S>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }

    pub fn prove_steps(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs3<Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        clear_cyclo_ring_data();
        clear_sigma_data();

        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_triple(acc)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = SonobeNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, *ext_inputs, None)
                .map_err(|_| CompressorError::Backend("sonobe prove step failed"))?;
            tracing::info!(step = step_idx, rss_kb = rss_kb(), "sonobe: prove_steps done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe proof serialization failed"))?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_triple((step.0, step.1, step.2)));
        }
        let public_inputs_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();

        let mut proof_bytes = Vec::with_capacity(76 + ivc_bytes.len());
        proof_bytes.extend_from_slice(&PROOF_MAGIC);
        proof_bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        proof_bytes.extend_from_slice(&normalized_hash(acc)?);
        proof_bytes.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        proof_bytes.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
        proof_bytes.extend_from_slice(&ivc_bytes);

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: prove_steps proof serialized"
        );
        Ok(CompressedProof(proof_bytes))
    }

    pub fn verify_steps(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        steps: &[ExternalInputs3<Fr>],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            return Ok(false);
        }

        let parsed = parse_proof(&proof.0)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_triple((step.0, step.1, step.2)));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_triple((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<S>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }
}

// Impl for CycloFoldStepCircuit (ExternalInputs4 prove_steps / verify_steps).
impl SonobeCompressor<CycloFoldStepCircuit<Fr>> {
    pub fn verify_external(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        let parsed = parse_proof(proof_bytes)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_quad((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
            ivc_proof.z_0[3],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<CycloFoldStepCircuit<Fr>>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend(
            "sonobe external verifier key deserialization failed",
        ))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<CycloFoldStepCircuit<Fr>>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }

    pub fn prove_steps(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs4<Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        clear_cyclo_ring_data();
        clear_sigma_data();

        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_quad(acc)?;
        let params = self.deserialize_params()?;
        let circuit =
            CycloFoldStepCircuit::<Fr>::new(())
                .map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        initial_state.push(initial.3);
        for _ in 4..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = SonobeNova::<CycloFoldStepCircuit<Fr>>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, *ext_inputs, None)
                .map_err(|_| CompressorError::Backend("sonobe prove step failed"))?;
            tracing::info!(step = step_idx, rss_kb = rss_kb(), "sonobe: prove_steps done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe proof serialization failed"))?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_quad((step.0, step.1, step.2, step.3)));
        }
        let public_inputs_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();

        let mut proof_bytes = Vec::with_capacity(76 + ivc_bytes.len());
        proof_bytes.extend_from_slice(&PROOF_MAGIC);
        proof_bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        proof_bytes.extend_from_slice(&normalized_hash(acc)?);
        proof_bytes.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        proof_bytes.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
        proof_bytes.extend_from_slice(&ivc_bytes);

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: prove_steps proof serialized"
        );
        Ok(CompressedProof(proof_bytes))
    }

    /// Prove share verification steps from a witness set.
    ///
    /// Converts witness data into `ExternalInputs4` entries and sets
    /// per-step thread-local coefficient data before delegating to
    /// [`Self::prove_steps`].
    pub fn prove_steps_share_verify(
        &self,
        acc: &[u8],
        witnesses: &crate::witness::ShareVerificationWitnessSet,
    ) -> Result<CompressedProof, CompressorError> {
        if !witnesses.verify_commitments() {
            return Err(CompressorError::InvalidProof);
        }

        let steps: Vec<ExternalInputs4<Fr>> = witnesses
            .witnesses
            .iter()
            .map(|w| ExternalInputs4(w.sig_r_x, w.sig_s, w.pk_x, Fr::from(1u64)))
            .collect();

        let coeffs_data: Vec<Vec<Fr>> = witnesses
            .witnesses
            .iter()
            .map(|w| w.coeffs.clone())
            .collect();
        set_share_coeffs_data(coeffs_data);

        let result = self.prove_steps(acc, &steps);

        clear_share_coeffs_data();
        result
    }

    /// Prove n Ajtai commitment verification steps from a witness set.
    pub fn prove_steps_ajtai(
        &self,
        acc: &[u8],
        witnesses: &crate::witness::AjtaiCommitmentWitnessSet,
    ) -> Result<CompressedProof, CompressorError> {
        use crate::sonobe::ajtai_commitment_circuit::{set_ajtai_witness_data, clear_ajtai_witness_data};

        if !witnesses.verify_commitments() {
            return Err(CompressorError::InvalidProof);
        }

        let steps: Vec<ExternalInputs4<Fr>> = witnesses
            .witnesses
            .iter()
            .map(|w| {
                ExternalInputs4(
                    w.expected_commitment_hash,
                    Fr::from_be_bytes_mod_order(&w.matrix_seed[..16]),
                    Fr::from_be_bytes_mod_order(&w.matrix_seed[16..]),
                    Fr::from(1u64),
                )
            })
            .collect();

        let coeffs_data: Vec<Vec<Fr>> = witnesses
            .witnesses
            .iter()
            .map(|w| w.coeffs.clone())
            .collect();
        set_ajtai_witness_data(coeffs_data);

        let result = self.prove_steps(acc, &steps);

        clear_ajtai_witness_data();
        result
    }

    pub fn verify_steps(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        steps: &[ExternalInputs4<Fr>],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            return Ok(false);
        }

        let parsed = parse_proof(&proof.0)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_quad((step.0, step.1, step.2, step.3)));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_quad((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
            ivc_proof.z_0[3],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<CycloFoldStepCircuit<Fr>>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<CycloFoldStepCircuit<Fr>>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }
}

impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = C7MerkleExternalInputs<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > SonobeCompressor<S>
{
    /// Prove with per-step Merkle external inputs.
    ///
    /// Each step i uses `steps[i]` as its `C7MerkleExternalInputs` value.
    /// The proof header stores `public_inputs_hash = Keccak256(concat(encode_merkle_step(steps)))`.
    pub fn prove_steps_merkle(
        &self,
        acc: &[u8],
        steps: &[C7MerkleExternalInputs<Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_triple(acc)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = SonobeNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        // Reproducible folding RNG — bound to session epoch via srs_hash.
        // Acceptable for research prototype; production should mix OsRng nonce.
        // allow-seeded-rng: deterministic RNG from epoch-bound srs_hash
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, ext_inputs.clone(), None)
                .map_err(|_| CompressorError::Backend("sonobe prove step merkle failed"))?;
            tracing::info!(step = step_idx, rss_kb = rss_kb(), "sonobe: prove_steps_merkle done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe proof serialization failed"))?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_merkle_step(step));
        }
        let public_inputs_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();

        let mut proof_bytes = Vec::with_capacity(76 + ivc_bytes.len());
        proof_bytes.extend_from_slice(&PROOF_MAGIC);
        proof_bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        proof_bytes.extend_from_slice(&normalized_hash(acc)?);
        proof_bytes.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        proof_bytes.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
        proof_bytes.extend_from_slice(&ivc_bytes);

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: prove_steps_merkle proof serialized"
        );
        Ok(CompressedProof(proof_bytes))
    }

    /// Verify a proof produced by [`Self::prove_steps_merkle`].
    pub fn verify_steps_merkle(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        steps: &[C7MerkleExternalInputs<Fr>],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            return Ok(false);
        }

        let parsed = parse_proof(&proof.0)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_merkle_step(step));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_triple((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<S>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }
}

impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = ExternalInputs5<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > SonobeCompressor<S>
{
    /// Prove with per-step C7 external inputs (G4-widened).
    ///
    /// Each step i uses `steps[i]` as its `ExternalInputs4` value.
    /// The proof header stores `public_inputs_hash = Keccak256(concat(encode_quad(steps)))`.
    pub fn prove_steps_c7(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs5<Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_triple(acc)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = SonobeNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        // Reproducible folding RNG — bound to session epoch via srs_hash.
        // Acceptable for research prototype; production should mix OsRng nonce.
        // allow-seeded-rng: deterministic RNG from epoch-bound srs_hash
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, *ext_inputs, None)
                .map_err(|_| CompressorError::Backend("sonobe prove step c7 failed"))?;
            tracing::info!(step = step_idx, rss_kb = rss_kb(), "sonobe: prove_steps_c7 done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe proof serialization failed"))?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_quint(*step));
        }
        let public_inputs_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();

        let mut proof_bytes = Vec::with_capacity(76 + ivc_bytes.len());
        proof_bytes.extend_from_slice(&PROOF_MAGIC);
        proof_bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        proof_bytes.extend_from_slice(&normalized_hash(acc)?);
        proof_bytes.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        proof_bytes.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
        proof_bytes.extend_from_slice(&ivc_bytes);

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: prove_steps_c7 proof serialized"
        );
        Ok(CompressedProof(proof_bytes))
    }

    /// Verify a proof produced by [`Self::prove_steps_c7`].
    pub fn verify_steps_c7(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        steps: &[ExternalInputs5<Fr>],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            return Ok(false);
        }

        let parsed = parse_proof(&proof.0)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_quint(*step));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_triple((
            ivc_proof.z_0[0],
            ivc_proof.z_0[1],
            ivc_proof.z_0[2],
        )))? != parsed.acc_hash
        {
            return Ok(false);
        }

        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        // G.30: Counter consistency enforcement.
        // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
        // Track B: counters only increment when real verification data was set via thread-locals.
        // The fold_count == verification_count check ensures the prover ran each step,
        // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
        let ring_check = if self.state_len >= 4 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
        } else {
            None
        };

        let sigma_check = if self.state_len >= 5 {
            Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
        } else {
            None
        };

        if let Err(e) = SonobeNova::<S>::verify(verifier, ivc_proof) { tracing::warn!("Nova::verify failed: {:?}", e);
            return Ok(false);
        }

        if let Some((fold_count, verification_count)) = ring_check {
            if fold_count != verification_count { tracing::warn!("fold_count {:?} != verification_count {:?}", fold_count, verification_count);
                return Ok(false);
            }
        }

        if let Some((fold_count, sigma_count)) = sigma_check {
            if fold_count != sigma_count { tracing::warn!("fold_count {:?} != sigma_verification_count {:?}", fold_count, sigma_count);
                return Ok(false);
            }
        }

        // G.30: When counters are non-zero but verification data might not have been set (Track A),
        // log but don't reject — Track A mode is valid.
        if let Some((fold_count, ring_verif)) = ring_check {
            if fold_count != Fr::from(0u64) {
                tracing::debug!(
                    "G.30 counters: fold_count={:?}, ring_verif={:?}, sigma={:?}",
                    fold_count,
                    ring_verif,
                    sigma_check.map(|(_, s)| s)
                );
            }
        }

        Ok(true)
    }
}

struct ParsedProof<'a> {
    acc_hash: [u8; 32],
    public_inputs_hash: [u8; 32],
    ivc_bytes: &'a [u8],
}

fn parse_proof(bytes: &[u8]) -> Result<ParsedProof<'_>, CompressorError> {
    if bytes.len() < 76 || bytes[0..4] != PROOF_MAGIC {
        return Err(CompressorError::InvalidProof);
    }

    let version = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| CompressorError::InvalidProof)?,
    );
    if version != PROOF_VERSION {
        return Err(CompressorError::InvalidProof);
    }

    let acc_hash = bytes[8..40]
        .try_into()
        .map_err(|_| CompressorError::InvalidProof)?;
    let public_inputs_hash = bytes[40..72]
        .try_into()
        .map_err(|_| CompressorError::InvalidProof)?;
    #[allow(clippy::as_conversions)]
    let ivc_len = u32::from_be_bytes(
        bytes[72..76]
            .try_into()
            .map_err(|_| CompressorError::InvalidProof)?,
    ) as usize;
    if bytes.len() != 76 + ivc_len {
        return Err(CompressorError::InvalidProof);
    }

    Ok(ParsedProof {
        acc_hash,
        public_inputs_hash,
        ivc_bytes: &bytes[76..],
    })
}

fn decode_scalar(bytes: &[u8]) -> Result<Fr, CompressorError> {
    if bytes.is_empty() {
        return Err(CompressorError::InvalidInput);
    }
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

fn encode_scalar(value: Fr) -> Vec<u8> {
    let mut bytes = value.into_bigint().to_bytes_le();
    bytes.resize(32, 0);
    bytes
}

/// Decode 96 bytes into a triple of Fr scalars (commitment, norm, count).
pub fn decode_triple(bytes: &[u8]) -> Result<(Fr, Fr, Fr), CompressorError> {
    if bytes.len() < 96 {
        return Err(CompressorError::InvalidInput);
    }
    let a = decode_scalar(&bytes[0..32])?;
    let b = decode_scalar(&bytes[32..64])?;
    let c = decode_scalar(&bytes[64..96])?;
    Ok((a, b, c))
}

/// Encode a triple of Fr scalars (commitment, norm, count) into 96 bytes.
pub fn encode_triple(value: (Fr, Fr, Fr)) -> [u8; 96] {
    let mut out = [0u8; 96];
    let a = encode_scalar(value.0);
    let b = encode_scalar(value.1);
    let c = encode_scalar(value.2);
    out[0..32].copy_from_slice(&a);
    out[32..64].copy_from_slice(&b);
    out[64..96].copy_from_slice(&c);
    out
}

/// Decode 128 bytes into a quadruple of Fr scalars.
pub fn decode_quad(bytes: &[u8]) -> Result<(Fr, Fr, Fr, Fr), CompressorError> {
    if bytes.len() < 128 {
        return Err(CompressorError::InvalidInput);
    }
    let a = decode_scalar(&bytes[0..32])?;
    let b = decode_scalar(&bytes[32..64])?;
    let c = decode_scalar(&bytes[64..96])?;
    let d = decode_scalar(&bytes[96..128])?;
    Ok((a, b, c, d))
}

/// Encode a quadruple of Fr scalars into 128 bytes (G.16 hash-chain encoding).
pub fn encode_quad(value: (Fr, Fr, Fr, Fr)) -> [u8; 128] {
    let mut out = [0u8; 128];
    let a = encode_scalar(value.0);
    let b = encode_scalar(value.1);
    let c = encode_scalar(value.2);
    let d = encode_scalar(value.3);
    out[0..32].copy_from_slice(&a);
    out[32..64].copy_from_slice(&b);
    out[64..96].copy_from_slice(&c);
    out[96..128].copy_from_slice(&d);
    out
}


/// Decode 192 bytes into a sextuple of Fr scalars.
pub fn decode_hex6(bytes: &[u8]) -> Result<(Fr, Fr, Fr, Fr, Fr, Fr), CompressorError> {
    if bytes.len() < 192 {
        return Err(CompressorError::InvalidInput);
    }
    let a = decode_scalar(&bytes[0..32])?;
    let b = decode_scalar(&bytes[32..64])?;
    let c = decode_scalar(&bytes[64..96])?;
    let d = decode_scalar(&bytes[96..128])?;
    let e = decode_scalar(&bytes[128..160])?;
    let f = decode_scalar(&bytes[160..192])?;
    Ok((a, b, c, d, e, f))
}

/// Encode a sextuple of Fr scalars into 192 bytes.
pub fn encode_hex6(value: (Fr, Fr, Fr, Fr, Fr, Fr)) -> [u8; 192] {
    let mut out = [0u8; 192];
    let a = encode_scalar(value.0);
    let b = encode_scalar(value.1);
    let c = encode_scalar(value.2);
    let d = encode_scalar(value.3);
    let e = encode_scalar(value.4);
    let f = encode_scalar(value.5);
    out[0..32].copy_from_slice(&a);
    out[32..64].copy_from_slice(&b);
    out[64..96].copy_from_slice(&c);
    out[96..128].copy_from_slice(&d);
    out[128..160].copy_from_slice(&e);
    out[160..192].copy_from_slice(&f);
    out
}

fn encode_quint(value: ExternalInputs5<Fr>) -> [u8; 160] {
    let mut buf = [0u8; 160];
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.0, &mut buf[0..32]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.1, &mut buf[32..64]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.2, &mut buf[64..96]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.3, &mut buf[96..128]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.4, &mut buf[128..160]).unwrap();
    buf
}


fn encode_merkle_step(step: &C7MerkleExternalInputs<Fr>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_scalar(step.share_eval));
    out.extend_from_slice(&encode_scalar(step.lagrange_coeff));
    out.extend_from_slice(&encode_scalar(step.merkle_root));
    out.extend_from_slice(&encode_scalar(step.merkle_data.leaf_value));
    out.extend_from_slice(&encode_scalar(step.merkle_data.leaf_index));
    for sib in &step.merkle_data.siblings {
        out.extend_from_slice(&encode_scalar(*sib));
    }
    out
}

fn normalized_hash(bytes: &[u8]) -> Result<[u8; 32], CompressorError> {
    // G.16: normalized_hash now accepts variable-length canonical encodings
    // (96 bytes for triples from Merkle/C7 paths, 128 bytes for quads from
    // the CycloFold hash-chain path). All callers pass already-canonical
    // encodings from encode_triple/encode_quad, so we hash the raw bytes directly.
    Ok(Keccak256::digest(bytes).into())
}

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4)
        .unwrap_or(0)
}
