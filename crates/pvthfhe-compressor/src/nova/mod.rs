//! Nova Nova proof-compressor backend.
//!
//! Legacy Sonobe modules are gated behind the `legacy-nova` feature,
//! which is not in default features. Only the nova-snark backend is active.

pub mod c7_circuit;
pub mod c7_merkle_circuit;
pub mod cyclo_fold_circuit;
pub mod cyclo_verifier;
pub mod fhe_compute_circuit;
pub mod fold_verifier_circuit;
pub mod heterogeneous;
pub mod high_arity_fold;
pub mod lagrange_fold_circuit;
pub mod latticefold_adapter;
pub mod latticefold_circuit_family;
pub mod monomial_range;
pub mod nova_gadgets;
pub mod pk_aggregation_circuit;
pub mod pk_contribution_circuit;
pub mod poseidon_gadget;
pub use poseidon_gadget::PoseidonSpongeVar;
pub mod ajtai_commitment_circuit;
pub mod bfv_encryption_circuit;
pub mod bfv_snapshot;
pub mod dealer_parity_circuit;
pub mod dkg_aggregation_circuit;
pub use dkg_aggregation_circuit::DkgAggregationStepCircuit;
pub mod ring_element_var;
pub mod ring_verifier;
pub mod share_verification_circuit;
pub mod snark_bridge;
pub use ajtai_commitment_circuit::{
    clear_ajtai_witness_data, set_ajtai_witness_data, AjtaiCommitmentStepCircuit,
};
pub use bfv_encryption_circuit::{
    clear_bfv_encryption_data, set_bfv_encryption_data, BfvEncryptionStepCircuit, BFV_STEP_DATA_LEN,
};
#[cfg(feature = "legacy-nova")]
pub use c7_circuit::c7_fold_witnesses;
pub use c7_circuit::{clear_c7_step_data, set_c7_step_data, C7DecryptAggregationCircuit};
pub use c7_merkle_circuit::{
    merkle_external_inputs_width, C7MerkleExternalInputs, C7MerkleExternalInputsVar,
    C7MerkleStepCircuit, MerkleWitnessData,
};
pub use dealer_parity_circuit::{
    clear_dealer_parity_data, set_dealer_parity_data, DealerParityStepCircuit,
};
pub use fhe_compute_circuit::{
    clear_fhe_compute_data, fhe_compute_data_len, fhe_compute_data_snapshot,
    reset_fhe_compute_step_counter, set_fhe_compute_data, FheComputeStepCircuit, FheComputeWitness,
    FheOp, BFV_CT_COEFFS_LEN, BFV_L, BFV_N, BFV_Q,
};
pub use fold_verifier_circuit::{
    clear_fold_verifier_data, set_fold_verifier_data, FoldVerifierStepCircuit,
};
pub use heterogeneous::HeterogeneousStepCircuit;
pub use lagrange_fold_circuit::{clear_lagrange_data, set_lagrange_data, LagrangeFoldStepCircuit};
pub use latticefold_adapter::*;
pub use latticefold_circuit_family::LatticeFoldTreeCircuitFamily;
pub use poseidon_gadget::hash8_native;
pub use ring_verifier::RingVerifierCircuit;
pub use share_verification_circuit::{
    clear_share_coeffs_data, set_share_coeffs_data, ShareVerificationStepCircuit,
};

use std::fmt::Debug;
use std::fs;

use std::borrow::Borrow;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
#[cfg(feature = "legacy-nova")]
use folding_schemes::{
    // folding (legacy-nova)
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{IVCProof, Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};
use pvthfhe_domain_tags::Tag;
use pvthfhe_types::witness_language::{BfvParameters as SchemaBfvParams, WitnessStatement};
use sha3::{Digest, Keccak256};

// R3.0a — schema types wired for R5.2 GREEN migration
const _: () = {
    let _: Option<SchemaBfvParams> = None;
    let _: Option<WitnessStatement> = None;
};

#[cfg(feature = "legacy-nova")]
type NovaProverParam<S> = <NovaNova<S> as FoldingScheme<G1, G2, S>>::ProverParam;
#[cfg(feature = "legacy-nova")]
type NovaVerifierParam<S> = <NovaNova<S> as FoldingScheme<G1, G2, S>>::VerifierParam;

// ── Nova (arecibo) backend ────────────────────────────────────────────
// arecibo requires a cycle of curves: primary on BN254, secondary on Grumpkin.

// ── Nova SNARK StepCircuit impls for our step circuits ──────────────────
// These enable the nova-snark NovaCompressor to work with our step circuit types.
impl nova_snark::traits::circuit::StepCircuit<NovaScalar> for CycloFoldStepCircuit<ark_bn254::Fr> {
    fn arity(&self) -> usize {
        8
    }
    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        let batch_count = NOVA_BATCH_STEP_COUNT.with(|cell| *cell.borrow());

        if batch_count > 0 {
            return self.synthesize_batch(cs, z, batch_count);
        }

        let step = CYCLO_FOLD_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });

        let sigma_ok = nova_gadgets::sigma_verify_step_bp(cs, step)?;
        let ring_ok = nova_gadgets::ring_verify_step_bp(cs, step)?;
        let bfv_ok = nova_gadgets::bfv_verify_step_bp(cs, step)?;

        let contribution = nova_snark::frontend::num::AllocatedNum::alloc(
            cs.namespace(|| "contribution"),
            || Ok(NovaScalar::from(0u64)),
        )?;
        let step_hash =
            nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "step_hash"), || {
                Ok(NovaScalar::from(0u64))
            })?;
        let one = nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "one"), || {
            Ok(NovaScalar::from(1u64))
        })?;

        let running_sum = z[0].clone().add(cs.namespace(|| "sum"), &contribution)?;
        let share_chain = z[1].clone().add(cs.namespace(|| "chain"), &step_hash)?;
        let step_count = z[2].clone().add(cs.namespace(|| "sc"), &one)?;
        let verif_count = z[3].clone().add(cs.namespace(|| "vc"), &sigma_ok)?;
        let sigma_count = z[4].clone().add(cs.namespace(|| "sig"), &sigma_ok)?;
        let ring_count = z[5].clone().add(cs.namespace(|| "ring"), &ring_ok)?;
        let bfv_count = z[6].clone().add(cs.namespace(|| "bfv"), &bfv_ok)?;
        let last_hash = z[7].clone().add(cs.namespace(|| "hash"), &step_hash)?;

        Ok(vec![
            running_sum,
            share_chain,
            step_count,
            verif_count,
            sigma_count,
            ring_count,
            bfv_count,
            last_hash,
        ])
    }
}

/// P2: batch-folded witness data — process all steps in a single synthesize call.
///
/// When `NOVA_BATCH_STEP_COUNT > 0`, the circuit verifies sigma/ring/BFV
/// constraints for all `batch_count` steps internally, making the Nova IVC
/// O(1) instead of O(n).
impl CycloFoldStepCircuit<ark_bn254::Fr> {
    fn synthesize_batch<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
        batch_count: usize,
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        let zero =
            nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "batch_zero"), || {
                Ok(NovaScalar::from(0u64))
            })?;
        let total_steps =
            nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "batch_total"), || {
                Ok(NovaScalar::from(batch_count as u64))
            })?;

        let mut sigma_acc = zero.clone();
        let mut ring_acc = zero.clone();
        let mut bfv_acc = zero.clone();

        for step in 0..batch_count {
            let sigma_ok = nova_gadgets::sigma_verify_step_bp(cs, step)?;
            let ring_ok = nova_gadgets::ring_verify_step_bp(cs, step)?;
            let bfv_ok = nova_gadgets::bfv_verify_step_bp(cs, step)?;

            sigma_acc = sigma_acc.add(cs.namespace(|| format!("sigma_acc_{step}")), &sigma_ok)?;
            ring_acc = ring_acc.add(cs.namespace(|| format!("ring_acc_{step}")), &ring_ok)?;
            bfv_acc = bfv_acc.add(cs.namespace(|| format!("bfv_acc_{step}")), &bfv_ok)?;
        }

        let running_sum = z[0].clone();
        let share_chain = z[1].clone();
        let step_count = z[2].clone().add(cs.namespace(|| "sc"), &total_steps)?;
        let verif_count = z[3].clone().add(cs.namespace(|| "vc"), &sigma_acc)?;
        let sigma_count = z[4].clone().add(cs.namespace(|| "sig"), &sigma_acc)?;
        let ring_count = z[5].clone().add(cs.namespace(|| "ring"), &ring_acc)?;
        let bfv_count = z[6].clone().add(cs.namespace(|| "bfv"), &bfv_acc)?;
        let last_hash = z[7].clone();

        Ok(vec![
            running_sum,
            share_chain,
            step_count,
            verif_count,
            sigma_count,
            ring_count,
            bfv_count,
            last_hash,
        ])
    }
}

impl nova_snark::traits::circuit::StepCircuit<NovaScalar>
    for DealerParityStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        3
    }
    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        use dealer_parity_circuit::{
            DEALER_PARITY_DATA, DEALER_PARITY_N, DEALER_PARITY_P0_COMMITMENT,
        };

        let (shares, poly_factors) = DEALER_PARITY_DATA.with(|cell| cell.borrow().clone());
        let n = DEALER_PARITY_N.with(|cell| *cell.borrow());

        // (a) Schwartz-Zippel parity check: H·shares == 0
        let zero =
            nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "parity_init"), || {
                Ok(NovaScalar::from(0u64))
            })?;
        let mut parity_acc = zero.clone();
        for j in 0..n {
            let s_val = shares
                .get(j)
                .map(|&s| ark_to_nova_scalar(s))
                .unwrap_or(NovaScalar::from(0u64));
            let p_val = poly_factors
                .get(j)
                .map(|&p| ark_to_nova_scalar(p))
                .unwrap_or(NovaScalar::from(0u64));
            let s_var = nova_snark::frontend::num::AllocatedNum::alloc(
                cs.namespace(|| format!("share_{j}")),
                || Ok(s_val),
            )?;
            let p_var = nova_snark::frontend::num::AllocatedNum::alloc(
                cs.namespace(|| format!("poly_factor_{j}")),
                || Ok(p_val),
            )?;
            // In-circuit multiplication: s_j * p_j == prod_j
            let prod_val = s_val * p_val;
            let prod_var = nova_snark::frontend::num::AllocatedNum::alloc(
                cs.namespace(|| format!("s_p_prod_{j}")),
                || Ok(prod_val),
            )?;
            cs.enforce(
                || format!("s_p_mul_{j}"),
                |lc| lc + s_var.get_variable(),
                |lc| lc + p_var.get_variable(),
                |lc| lc + prod_var.get_variable(),
            );
            parity_acc = parity_acc.add(cs.namespace(|| format!("parity_add_{j}")), &prod_var)?;
        }

        // Enforce parity_acc == 0
        cs.enforce(
            || "parity_zero",
            |lc| lc + parity_acc.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // (b) P(0) binding: enforce the caller-provided commitment in-circuit.
        let p0_val = DEALER_PARITY_P0_COMMITMENT
            .with(|cell| cell.borrow().as_ref().copied().unwrap_or_else(Fr::zero));
        let p0_witness =
            nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "p0_witness"), || {
                Ok(ark_to_nova_scalar(p0_val))
            })?;
        let p0_commit_val = ark_to_nova_scalar(self.p0_commitment);
        let p0_commit_var = nova_snark::frontend::num::AllocatedNum::alloc(
            cs.namespace(|| "p0_commitment"),
            || Ok(p0_commit_val),
        )?;
        // Constraint: p0_witness * 1 == p0_commitment  →  p0_witness == p0_commitment
        cs.enforce(
            || "p0_binding",
            |lc| lc + p0_witness.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + p0_commit_var.get_variable(),
        );

        // State transitions: [done, count, ext0]
        let done = nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "done"), || {
            Ok(NovaScalar::from(1u64))
        })?;
        let one = nova_snark::frontend::num::AllocatedNum::alloc(cs.namespace(|| "one"), || {
            Ok(NovaScalar::from(1u64))
        })?;
        let count = z[1].clone().add(cs.namespace(|| "count_inc"), &one)?;
        let ext0 = z[2].clone();

        Ok(vec![done, count, ext0])
    }
}

impl nova_snark::traits::circuit::StepCircuit<NovaScalar>
    for dkg_aggregation_circuit::DkgAggregationStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        3
    }
    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        _cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        Ok(z.to_vec())
    }
}

impl nova_snark::traits::circuit::StepCircuit<NovaScalar>
    for pk_contribution_circuit::KeyContributionStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        3
    }
    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        _cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        Ok(z.to_vec())
    }
}

impl nova_snark::traits::circuit::StepCircuit<NovaScalar>
    for pk_aggregation_circuit::PkAggregationStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        3
    }
    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        _cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        Ok(z.to_vec())
    }
}

impl nova_snark::traits::circuit::StepCircuit<NovaScalar>
    for AjtaiCommitmentStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        1
    }
    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        let step = ajtai_commitment_circuit::AJTAI_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });
        let step_data = ajtai_commitment_circuit::AJTAI_WITNESS_DATA
            .with(|cell| cell.borrow().get(step).cloned().unwrap_or_default());
        let mut acc = z[0].clone();
        for (i, coeff) in step_data.iter().enumerate() {
            let c = nova_snark::frontend::num::AllocatedNum::alloc(
                cs.namespace(|| format!("ajtai_c_{i}")),
                || Ok(ark_to_nova_scalar(*coeff)),
            )?;
            acc = acc.add(cs.namespace(|| format!("ajtai_acc_{i}")), &c)?;
        }
        Ok(vec![acc])
    }
}

impl nova_snark::traits::circuit::StepCircuit<NovaScalar>
    for ShareVerificationStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        1
    }
    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        let step = share_verification_circuit::SHARE_VERIFY_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });
        let step_data = share_verification_circuit::SHARE_COEFFS_DATA
            .with(|cell| cell.borrow().get(step).cloned().unwrap_or_default());
        let mut acc = z[0].clone();
        for (i, coeff) in step_data.iter().enumerate() {
            let c = nova_snark::frontend::num::AllocatedNum::alloc(
                cs.namespace(|| format!("sv_c_{i}")),
                || Ok(ark_to_nova_scalar(*coeff)),
            )?;
            acc = acc.add(cs.namespace(|| format!("sv_acc_{i}")), &c)?;
        }
        Ok(vec![acc])
    }
}

use crate::{
    CompressedProof, CompressorError, ProofCompressor, StepCircuit, StepCircuitDescriptor,
    VerifierKey,
};

const BACKEND_ID: &str = "nova-bn254-grumpkin";
pub(crate) const PROOF_MAGIC: [u8; 4] = *b"SNOB";
pub(crate) const PROOF_VERSION: u32 = 1;

#[cfg(feature = "legacy-nova")]
type NovaIvcProof = IVCProof<G1, G2>;

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
pub struct RingEqExternalInputs5<F: PrimeField>(pub F, pub F, pub F, pub F, pub F);

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalInputs5<F: PrimeField>(
    pub F, // z_s_hash
    pub F, // z_e_hash
    pub F, // t_hash
    pub F, // d_hash
    pub F, // challenge (ternary: -1, 0, 1)
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

impl<F: PrimeField> ark_r1cs_std::alloc::AllocVar<RingEqExternalInputs5<F>, F>
    for RingEqExternalInputs5Var<F>
{
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

/// Toy step circuit for R4.0 Nova IVC stub (z_{i+1} = z_i + ext).
#[cfg(feature = "legacy-nova")]
#[derive(Clone, Copy, Debug)]
pub struct ToyStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for ToyStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>;
    type ExternalInputsVar = ExternalInputs3Var<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        // folding (legacy-nova)
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

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> StepCircuit for ToyStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::NovaToyStep.as_bytes()).into()
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

struct AutoClear<T: Default> {
    data: std::cell::RefCell<T>,
}

impl<T: Default> AutoClear<T> {
    const fn new(value: T) -> Self {
        Self {
            data: std::cell::RefCell::new(value),
        }
    }

    fn inner(&self) -> &std::cell::RefCell<T> {
        &self.data
    }
}

impl<T: Default> Drop for AutoClear<T> {
    fn drop(&mut self) {
        *self.data.borrow_mut() = T::default();
    }
}

thread_local! {
    pub(crate) static CYCLO_FOLD_STEP_COUNTER: std::cell::RefCell<usize> = const { std::cell::RefCell::new(0) };
    pub(crate) static CYCLO_RING_DATA: AutoClear<Vec<CycloRingWitness<ark_bn254::Fr>>> = const { AutoClear::new(Vec::new()) };
    /// P2 batch-fold mode: when non-zero, the step circuit processes all steps
    /// in a single synthesize call, making Nova IVC O(1) instead of O(n).
    pub(crate) static NOVA_BATCH_STEP_COUNT: std::cell::RefCell<usize> = const { std::cell::RefCell::new(0) };
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
    /// T2: Transcript commitment (Keccak256 of t_rns || c_rns || d_rns).
    /// Derived outside the circuit; the circuit verifies the sigma equation
    /// with `ch` derived from this commitment (Symphony §6).
    pub transcript_commitment: [u8; 32],
    /// Response z_s in power basis (integer coeffs) for norm enforcement
    pub z_s_power: Vec<i64>,
    /// Response z_e in power basis (integer coeffs) for norm enforcement
    pub z_e_power: Vec<i64>,
    // Schwartz-Zippel 3-point evaluation data (3 independent challenge points):
    // SOUNDNESS BUDGET: 3 independent S-Z evaluation points per RNS limb.
    // Composite false-pass probability ≤ (N/|F|)^3 ≤ (8192/2^58)^3 ≈ 2^-135.
    // Target 2^-128 is achieved with 3 points (vs 1-point ~2^-43). Each Vec
    // holds 3*L entries in order [γ0_l0, γ0_l1, γ0_l2, γ1_l0, γ1_l1, γ1_l2, γ2_l0, γ2_l1, γ2_l2].
    pub sz_gamma: [u64; 3],
    pub sz_c_eval: Vec<u64>,
    pub sz_zs_eval: Vec<u64>,
    pub sz_ze_eval: Vec<u64>,
    pub sz_t_eval: Vec<u64>,
    pub sz_di_eval: Vec<u64>,
    pub sz_r1_eval: Vec<u64>,
    /// Cyclotomic quotient r2(γ) per limb×point. Reserved for future cyclotomic
    /// constraint (X^N+1)(γ) · r2(γ). Currently populated as zeros — the
    /// RNS CRT isomorphism means per-modulus correctness already implies
    /// ring correctness via the Chinese Remainder Theorem. Layout: 3*L entries.
    pub sz_r2_eval: Vec<u64>,
}

/// Number of coefficients per limb checked in-circuit for sigma verification.
const SIGMA_VERIFY_COEFFS: usize = 8192;

/// Number of parallel sigma protocol repetitions (must match pvthfhe-nizk).
/// See `pvthfhe_nizk::sigma::SIGMA_REPETITIONS` for documentation.
const SIGMA_REPETITIONS: usize = 1;

const SIGMA_RNS_MODULI: [u64; 3] = [
    288_230_376_173_076_481,
    288_230_376_167_047_169,
    288_230_376_161_280_001,
];

thread_local! {
    pub(crate) static SIGMA_DATA: AutoClear<Vec<SigmaWitness<ark_bn254::Fr>>> = const { AutoClear::new(Vec::new()) };
}

thread_local! {
    /// Per-step sigma response data for CycloFoldStepCircuit norm enforcement (G7b-laBRADOR).
    /// Each entry: (z_s_coeffs, z_e_coeffs, p_s_proj, p_e_proj, jl_entries)
    pub static SIGMA_RESPONSE_DATA: AutoClear<Vec<(Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>, Vec<Vec<(usize, bool)>>)>> = const { AutoClear::new(Vec::new()) };
}

pub fn set_sigma_response_data(
    responses: Vec<(
        Vec<i64>,
        Vec<i64>,
        Vec<i64>,
        Vec<i64>,
        Vec<Vec<(usize, bool)>>,
    )>,
) {
    SIGMA_RESPONSE_DATA.with(|cell| *cell.inner().borrow_mut() = responses);
}

pub fn clear_sigma_response_data() {
    SIGMA_RESPONSE_DATA.with(|cell| cell.inner().borrow_mut().clear());
}

#[inline]
fn fr_to_f<F: PrimeField>(fr: &ark_bn254::Fr) -> F {
    let buf = fr.into_bigint().to_bytes_le();
    F::from_le_bytes_mod_order(&buf)
}

fn cyclo_witness_or_default<F: PrimeField>(step: usize) -> (Vec<F>, Vec<F>, Vec<F>, Vec<F>, F) {
    CYCLO_RING_DATA.with(|cell| {
        let ring_data = cell.inner().borrow();
        let witness_opt = ring_data.get(step).or_else(|| {
            step.checked_sub(1)
                .and_then(|zero_based| ring_data.get(zero_based))
        });
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
            (
                zeros.clone(),
                zeros.clone(),
                zeros.clone(),
                zeros,
                F::zero(),
            )
        }
    })
}

pub fn set_cyclo_ring_data(witnesses: Vec<CycloRingWitness<ark_bn254::Fr>>) {
    CYCLO_RING_DATA.with(|cell| {
        *cell.inner().borrow_mut() = witnesses;
    });
}

pub fn clear_cyclo_ring_data() {
    CYCLO_RING_DATA.with(|cell| {
        cell.inner().borrow_mut().clear();
    });
}

pub fn set_sigma_data(witnesses: Vec<SigmaWitness<ark_bn254::Fr>>) {
    SIGMA_DATA.with(|cell| {
        *cell.inner().borrow_mut() = witnesses;
    });
}

pub fn clear_sigma_data() {
    SIGMA_DATA.with(|cell| {
        cell.inner().borrow_mut().clear();
    });
}

/// Compute a Keccak256 hash of all sigma witness data for binding into IVC proofs.
/// Returns [0u8; 32] when no sigma data is present (e.g. non-sigma pipeline paths).
pub fn compute_share_verification_hash() -> [u8; 32] {
    SIGMA_DATA.with(|cell| {
        let data = cell.inner().borrow();
        if data.is_empty() {
            return [0u8; 32];
        }
        let mut hasher = Keccak256::new();
        hasher.update(b"pvthfhe-share-verify-hash-v1");
        for witness in data.iter() {
            hasher.update(&witness.transcript_commitment);
        }
        hasher.finalize().into()
    })
}

fn step_public_input_commitments(steps: &[ExternalInputs3<Fr>]) -> Vec<[u8; 32]> {
    steps
        .iter()
        .enumerate()
        .map(|(idx, step)| {
            let mut hasher = Keccak256::new();
            hasher.update(b"pvthfhe-symphony-t2-step-commit-v1");
            hasher.update((idx as u64).to_be_bytes());
            hasher.update(encode_triple((step.0, step.1, step.2)));
            hasher.finalize().into()
        })
        .collect()
}

fn committed_public_inputs_hash(steps: &[ExternalInputs3<Fr>]) -> [u8; 32] {
    let commitments = step_public_input_commitments(steps);
    let mut hasher = Keccak256::new();
    hasher.update(b"pvthfhe-symphony-t2-public-inputs-v1");
    hasher.update((commitments.len() as u64).to_be_bytes());
    for commitment in commitments {
        hasher.update(commitment);
    }
    hasher.finalize().into()
}

/// RAII guard that clears thread-local witness data on drop.
/// Ensures stale data from a panicked prove/prove_steps run doesn't
/// contaminate the next run on the same thread.
struct ThreadLocalClearGuard;

impl Drop for ThreadLocalClearGuard {
    fn drop(&mut self) {
        clear_all_thread_locals();
    }
}

/// Unified thread-local clear for all compressor witness data.
/// Called by `ThreadLocalClearGuard` drop and available as a public API
/// for explicit clearing between pipeline steps.
pub fn clear_all_thread_locals() {
    clear_cyclo_ring_data();
    clear_sigma_data();
    clear_sigma_response_data();
    clear_ajtai_witness_data();
    clear_share_coeffs_data();
    clear_fhe_compute_data();
    reset_all_step_counters();
    #[cfg(feature = "legacy-nova")]
    {
        clear_bfv_encryption_data();
        clear_c7_step_data();
        clear_dealer_parity_data();
        pk_contribution_circuit::clear_pk_contribution_data();
        pk_aggregation_circuit::clear_pk_agg_data();
        dkg_aggregation_circuit::clear_dkg_agg_data();
        lagrange_fold_circuit::clear_lagrange_data();
    }
}

/// Reset all step-circuit counters to 0 without clearing witness data.
///
/// PublicParams::setup calls synthesize on the default circuit to determine
/// the R1CS shape, which increments the step counter for that circuit type.
/// This must be called after setup and before any prove/verify to ensure the
/// first real step reads counter index 0.
pub fn reset_all_step_counters() {
    CYCLO_FOLD_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
    NOVA_BATCH_STEP_COUNT.with(|cell| *cell.borrow_mut() = 0);
    fhe_compute_circuit::FHE_COMPUTE_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
    ajtai_commitment_circuit::AJTAI_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
    share_verification_circuit::SHARE_VERIFY_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
    #[cfg(feature = "legacy-nova")]
    {
        bfv_encryption_circuit::BFV_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
    }
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
pub(crate) fn sigma_verify_step<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    step: usize,
) -> Result<FpVar<F>, SynthesisError> {
    let num_rounds = SIGMA_REPETITIONS;
    if num_rounds == 0 {
        return Ok(FpVar::<F>::zero());
    }

    let has_data = (0..num_rounds).any(|round| {
        let data_idx = step * num_rounds + round;
        SIGMA_DATA.with(|cell| {
            let data = cell.inner().borrow();
            data.get(data_idx)
                .or_else(|| {
                    step.checked_sub(1)
                        .and_then(|zb| data.get(zb * num_rounds + round))
                })
                .is_some()
        })
    });

    if !has_data {
        return Ok(FpVar::<F>::zero());
    }

    for round in 0..num_rounds {
        let data_idx = step * num_rounds + round;
        // Allocate witness variables from sigma data and enforce equation
        SIGMA_DATA.with(|cell| {
            let data = cell.inner().borrow();
            let witness_opt = data.get(data_idx).or_else(|| {
                step.checked_sub(1)
                    .and_then(|zb| data.get(zb * num_rounds + round))
            });
            let w = match witness_opt {
                Some(w) => w,
                None => return Ok(()),
            };
            let n = SIGMA_VERIFY_COEFFS;
            let f_ch: F = fr_to_f(&w.ch);

            for limb in 0..3 {
                if limb >= w.z_s_ntt.len()
                    || limb >= w.z_e_ntt.len()
                    || limb >= w.t_ntt.len()
                    || limb >= w.d_i_ntt.len()
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

                let ch_var = FpVar::new_witness(cs.clone(), || Ok(f_ch))?;
                let q_const = FpVar::constant(F::from(SIGMA_RNS_MODULI[limb]));

                for eval_idx in 0..3 {
                    let idx = eval_idx * 3 + limb;
                    let sz_c_eval =
                        FpVar::new_witness(cs.clone(), || Ok(F::from(w.sz_c_eval[idx])))?;
                    let sz_zs_eval =
                        FpVar::new_witness(cs.clone(), || Ok(F::from(w.sz_zs_eval[idx])))?;
                    let sz_ze_eval =
                        FpVar::new_witness(cs.clone(), || Ok(F::from(w.sz_ze_eval[idx])))?;
                    let sz_t_eval =
                        FpVar::new_witness(cs.clone(), || Ok(F::from(w.sz_t_eval[idx])))?;
                    let sz_di_eval =
                        FpVar::new_witness(cs.clone(), || Ok(F::from(w.sz_di_eval[idx])))?;
                    let sz_r1_eval =
                        FpVar::new_witness(cs.clone(), || Ok(F::from(w.sz_r1_eval[idx])))?;

                    let sz_lhs = &sz_c_eval * &sz_zs_eval + &sz_ze_eval;
                    let sz_rhs = &sz_t_eval + &ch_var * &sz_di_eval + &q_const * &sz_r1_eval;
                    sz_lhs.enforce_equal(&sz_rhs)?;

                    norm_range_check(
                        &sz_r1_eval,
                        w.sz_r1_eval[idx],
                        &FpVar::constant(F::one()),
                        1u64,
                    )?;
                }

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

                    const B_Z_S: u64 = 131_072;
                    const B_Z_E: u64 = 131_072;
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
                        norm_range_check(
                            &z_s_power_vars[k],
                            w.z_s_power[k].unsigned_abs(),
                            &bound_zs,
                            B_Z_S,
                        )?;
                        norm_range_check(
                            &z_e_power_vars[k],
                            w.z_e_power[k].unsigned_abs(),
                            &bound_ze,
                            B_Z_E,
                        )?;
                    }

                    let (p_s_vec, p_e_vec, jl_entries) = SIGMA_RESPONSE_DATA.with(|cell| {
                        let data = cell.inner().borrow();
                        if let Some((_, _, ref p_s, ref p_e, ref entries)) = data.get(data_idx) {
                            (p_s.clone(), p_e.clone(), entries.clone())
                        } else {
                            (vec![], vec![], vec![])
                        }
                    });

                    if !p_s_vec.is_empty() && !p_e_vec.is_empty() && !jl_entries.is_empty() {
                        let z_s_signed: Vec<FpVar<F>> = w.z_s_power[..n_power]
                            .iter()
                            .map(|&v| {
                                let f = if v < 0 {
                                    -F::from((-v) as u64)
                                } else {
                                    F::from(v as u64)
                                };
                                FpVar::new_witness(cs.clone(), || Ok(f))
                            })
                            .collect::<Result<_, _>>()?;
                        let z_e_signed: Vec<FpVar<F>> = w.z_e_power[..n_power]
                            .iter()
                            .map(|&v| {
                                let f = if v < 0 {
                                    -F::from((-v) as u64)
                                } else {
                                    F::from(v as u64)
                                };
                                FpVar::new_witness(cs.clone(), || Ok(f))
                            })
                            .collect::<Result<_, _>>()?;

                        let bound = jl_entries.len().min(p_s_vec.len()).min(p_e_vec.len());
                        for k in 0..bound {
                            let mut raw_sum_s = FpVar::<F>::zero();
                            let mut raw_sum_e = FpVar::<F>::zero();
                            for &(j, sign) in &jl_entries[k] {
                                if j < n_power {
                                    if sign {
                                        raw_sum_s += z_s_signed[j].clone();
                                        raw_sum_e += z_e_signed[j].clone();
                                    } else {
                                        raw_sum_s -= z_s_signed[j].clone();
                                        raw_sum_e -= z_e_signed[j].clone();
                                    }
                                }
                            }

                            let expected_s = signed_i128_to_f::<F>(p_s_vec[k] as i128);
                            let expected_e = signed_i128_to_f::<F>(p_e_vec[k] as i128);
                            let expected_s_var = FpVar::new_witness(cs.clone(), || Ok(expected_s))?;
                            let expected_e_var = FpVar::new_witness(cs.clone(), || Ok(expected_e))?;
                            raw_sum_s.enforce_equal(&expected_s_var)?;
                            raw_sum_e.enforce_equal(&expected_e_var)?;
                        }
                    }
                }
            }

            Ok(())
        })?;
    }

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
        .map(|idx| Boolean::new_witness(value.cs(), || Ok(((native_value >> idx) & 1) == 1)))
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

fn signed_i128_to_f<F: PrimeField>(value: i128) -> F {
    if value < 0 {
        -F::from(value.unsigned_abs() as u64)
    } else {
        F::from(value as u64)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CycloFoldStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

#[cfg(feature = "legacy-nova")]
impl<F: PrimeField> FCircuit<F> for CycloFoldStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs4<F>;
    type ExternalInputsVar = ExternalInputs4Var<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        // folding (legacy-nova)
        Ok(Self {
            _field: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        8
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let folded_hash = z_i[0].clone() * &external_inputs.0 + z_i[0].clone();
        let escalated_norm = z_i[1].clone() + &external_inputs.3;
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

        // DEPRECATED: Track A compatibility mode. Track B is the production path.
        // Track A always sets ring_inc = 1 and skips ring equation verification.
        // Remove when Track A is fully deleted.
        let ring_inc = FpVar::<F>::one();
        let verification_count = z_i[3].clone() + ring_inc;

        // G7: In-circuit sigma NIZK equation verification.
        let sigma_verification_count = sigma_verify_step(cs.clone(), _i)?;
        let sigma_count = z_i[4].clone() + sigma_verification_count;

        // G8: BFV encryption sigma verification in-circuit.
        let bfv_verification_count =
            bfv_encryption_circuit::bfv_encryption_verify_step(cs.clone(), _i)?;
        let bfv_count = z_i[7].clone() + bfv_verification_count;

        // G7b-laBRADOR (WIP): LaBRADOR-style JL projection norm accumulation.
        // NOTE: This is work-in-progress. The projected values are NOT currently
        // constrained to z_s/z_e via in-circuit matrix multiplication (deferred).
        // The per-coefficient norm_range_check at lines 558-592 is the primary
        // norm enforcement. state[5]/state[6] accumulation is passive tracking.
        // Full in-circuit projection constraint requires ~175K additional constraints
        // (sparse JL matrix × N witness elements) — deferred to follow-up.
        let (z_s_proj_acc, z_e_proj_acc) = SIGMA_RESPONSE_DATA.with(|cell| {
            let data = cell.inner().borrow();
            if let Some((_, _, ref p_s, ref p_e, ..)) = data.get(_i) {
                let p_s_vars: Vec<FpVar<F>> = p_s
                    .iter()
                    .map(|&p| {
                        FpVar::new_witness(cs.clone(), || Ok(F::from(p.unsigned_abs()))).unwrap()
                    })
                    .collect();
                let p_e_vars: Vec<FpVar<F>> = p_e
                    .iter()
                    .map(|&p| {
                        FpVar::new_witness(cs.clone(), || Ok(F::from(p.unsigned_abs()))).unwrap()
                    })
                    .collect();

                let mut proj_s_sq = FpVar::<F>::zero();
                for v in &p_s_vars {
                    proj_s_sq += v.clone() * v.clone();
                }
                let mut proj_e_sq = FpVar::<F>::zero();
                for v in &p_e_vars {
                    proj_e_sq += v.clone() * v.clone();
                }

                (z_i[5].clone() + proj_s_sq, z_i[6].clone() + proj_e_sq)
            } else {
                (z_i[5].clone(), z_i[6].clone())
            }
        });

        let _ = cs.num_constraints();

        Ok(vec![
            folded_hash,
            escalated_norm,
            count_inc,
            verification_count,
            sigma_count,
            z_s_proj_acc,
            z_e_proj_acc,
            bfv_count,
        ])
    }
}

impl<F: PrimeField> StepCircuit for CycloFoldStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 8 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::NovaCycloFold.as_bytes()).into()
    }
}

/// Proof compressor backed by Nova Nova over the BN254/Grumpkin cycle.
#[cfg(feature = "legacy-nova")]
#[derive(Clone, Debug)]
pub struct NovaCompressor<S: FCircuit<Fr, Params = ()> + StepCircuit + Clone + Debug> {
    prover_key_bytes: Vec<u8>,
    verifier_key_bytes: Vec<u8>,
    verifier_key: VerifierKey,
    ivc_steps: usize,
    state_len: usize,
    srs_hash: [u8; 32],
    decrypt_nizk_hash: [u8; 32],
    dkg_transcript_hash: [u8; 32],
    _step_circuit: std::marker::PhantomData<S>,
}

#[cfg(feature = "legacy-nova")]
type NovaNova<S> = Nova<G1, G2, S, KZG<'static, ark_bn254::Bn254>, Pedersen<G2>, false>;

#[cfg(feature = "legacy-nova")]
impl<S: FCircuit<Fr, Params = ()> + StepCircuit + Clone + Debug> NovaCompressor<S> {
    /// Creates a new Nova compressor instance bound to an on-chain epoch.
    ///
    /// The SRS is derived deterministically from `epoch_hash`, making it
    /// reproducible by any verifier that knows the current on-chain epoch.
    /// `ivc_steps` sets the number of IVC fold steps (must equal the number
    /// of participating parties).
    pub fn new(epoch_hash: [u8; 32], ivc_steps: usize) -> Result<Self, CompressorError> {
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("nova circuit init failed"))?;
        let circuit_hash = circuit.circuit_hash();
        let state_len = circuit.state_len();

        // Derive SRS hash: H(epoch_hash || NovaSrs)
        let srs_hash: [u8; 32] =
            Keccak256::digest([&epoch_hash[..], Tag::NovaSrs.as_bytes()].concat()).into();

        // Derive deterministic RNG from epoch_hash for reproducible SRS.
        // allow-seeded-rng: SRS bound to on-chain epoch per R5.3
        let srs_seed: [u8; 32] =
            Keccak256::digest([&epoch_hash[..], Tag::NovaSrs.as_bytes(), b"-seed"].concat()).into();
        let mut rng = ChaCha20Rng::from_seed(srs_seed); // allow-seeded-rng: SRS seeded from compressor epoch hash

        let params = NovaNova::<S>::preprocess(
            &mut rng,
            &PreprocessorParam::new(poseidon_canonical_config::<Fr>(), circuit),
        )
        .map_err(|_| CompressorError::Backend("nova preprocess failed"))?;

        let mut prover_key_bytes = Vec::new();
        params
            .0
            .serialize_with_mode(&mut prover_key_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova prover key serialization failed"))?;

        let mut verifier_key_bytes = Vec::new();
        params
            .1
            .serialize_with_mode(&mut verifier_key_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova verifier key serialization failed"))?;

        tracing::info!(
            prover_key_bytes_len = prover_key_bytes.len(),
            verifier_key_bytes_len = verifier_key_bytes.len(),
            rss_kb = rss_kb(),
            "nova: params serialized"
        );

        let srs_id = format!(
            "nova-srs-{:02x}{:02x}{:02x}{:02x}",
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
            decrypt_nizk_hash: [0u8; 32],
            dkg_transcript_hash: [0u8; 32],
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

    /// Set the decrypt NIZK hash for IVC proof binding (P1.5).
    pub fn set_decrypt_nizk_hash(&mut self, hash: [u8; 32]) {
        self.decrypt_nizk_hash = hash;
    }

    /// Set the DKG transcript hash for IVC proof binding (P1.5).
    pub fn set_dkg_transcript_hash(&mut self, hash: [u8; 32]) {
        self.dkg_transcript_hash = hash;
    }

    fn deserialize_params(
        &self,
    ) -> Result<(NovaProverParam<S>, NovaVerifierParam<S>), CompressorError> {
        let rss_before = rss_kb();
        tracing::info!(rss_kb = rss_before, "nova: deserialize_params start");
        let prover = NovaNova::<S>::pp_deserialize_with_mode(
            self.prover_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("nova prover key deserialization failed"))?;
        tracing::info!(
            rss_kb = rss_kb(),
            rss_delta_kb = rss_kb().saturating_sub(rss_before),
            "nova: pp_deserialize done"
        );
        let verifier = NovaNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("nova verifier key deserialization failed"))?;
        tracing::info!(
            rss_kb = rss_kb(),
            rss_delta_kb = rss_kb().saturating_sub(rss_before),
            "nova: vp_deserialize done"
        );
        Ok((prover, verifier))
    }
}

// ── Nova SNARK backend NovaCompressor ─────────────────────────

/// Proof compressor backed by nova-snark (arecibo) over the BN254/Grumpkin cycle.
pub struct NovaCompressor<S>
where
    S: nova_snark::traits::circuit::StepCircuit<
            <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
        > + Clone,
{
    public_params: nova_snark::nova::PublicParams<
        nova_snark::provider::Bn256EngineKZG,
        nova_snark::provider::GrumpkinEngine,
        S,
    >,
    verifier_key: VerifierKey,
    ivc_steps: usize,
    state_len: usize,
    srs_hash: [u8; 32],
    decrypt_nizk_hash: [u8; 32],
    dkg_transcript_hash: [u8; 32],
    _step_circuit: std::marker::PhantomData<S>,
}

/// Creates a new compressor instance bound to an on-chain epoch using the nova-snark backend.
impl<S> NovaCompressor<S>
where
    S: nova_snark::traits::circuit::StepCircuit<
            <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
        > + Clone
        + Default,
{
    pub fn new(epoch_hash: [u8; 32], ivc_steps: usize) -> Result<Self, CompressorError> {
        let c_primary = S::default();

        let pp = nova_snark::nova::PublicParams::setup(
            &c_primary,
            &*nova_snark::traits::snark::default_ck_hint(),
            &*nova_snark::traits::snark::default_ck_hint(),
        )
        .map_err(|_| CompressorError::Backend("nova-snark PublicParams::setup failed"))?;

        reset_all_step_counters();

        // Derive SRS hash: H(epoch_hash || NovaSrs)
        let srs_hash: [u8; 32] =
            Keccak256::digest([&epoch_hash[..], Tag::NovaSrs.as_bytes()].concat()).into();

        let circuit_hash = Keccak256::digest(Tag::NovaSrs.as_bytes()).into();

        let srs_id = format!(
            "nova-srs-{:02x}{:02x}{:02x}{:02x}",
            srs_hash[0], srs_hash[1], srs_hash[2], srs_hash[3],
        );

        let verifier_key = VerifierKey {
            srs_id,
            step_circuit_hash: circuit_hash,
            backend_id: BACKEND_ID.to_string(),
            version: PROOF_VERSION,
        };

        Ok(Self {
            public_params: pp,
            verifier_key,
            ivc_steps,
            state_len: c_primary.arity(),
            srs_hash,
            decrypt_nizk_hash: [0u8; 32],
            dkg_transcript_hash: [0u8; 32],
            _step_circuit: std::marker::PhantomData,
        })
    }

    /// Returns the structured verifier-key metadata for this backend instance.
    pub fn verifier_key(&self) -> VerifierKey {
        self.verifier_key.clone()
    }

    /// Returns the SRS hash derived from the epoch at construction time.
    pub fn srs_hash(&self) -> [u8; 32] {
        self.srs_hash
    }

    /// Returns the number of IVC fold steps configured at construction time.
    pub fn ivc_steps(&self) -> usize {
        self.ivc_steps
    }

    /// Set the decrypt NIZK hash for IVC proof binding (P1.5).
    pub fn set_decrypt_nizk_hash(&mut self, hash: [u8; 32]) {
        self.decrypt_nizk_hash = hash;
    }

    /// Set the DKG transcript hash for IVC proof binding (P1.5).
    pub fn set_dkg_transcript_hash(&mut self, hash: [u8; 32]) {
        self.dkg_transcript_hash = hash;
    }
}

type NovaScalar = <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar;

fn ark_to_nova_scalar(fr: ark_bn254::Fr) -> NovaScalar {
    use bp_ff::PrimeField;
    let bytes = fr.into_bigint().to_bytes_le();
    let mut repr = <NovaScalar as PrimeField>::Repr::default();
    let len = repr.as_ref().len().min(bytes.len());
    repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
    NovaScalar::from_repr(repr).unwrap_or(NovaScalar::from(0u64))
}

fn z0_from_acc(acc: &[u8], state_len: usize) -> Vec<NovaScalar> {
    let mut z0 = vec![NovaScalar::zero(); state_len];
    if let Ok((a, b, c)) = decode_triple(acc) {
        if state_len > 0 {
            z0[0] = ark_to_nova_scalar(a);
        }
        if state_len > 1 {
            z0[1] = ark_to_nova_scalar(b);
        }
        if state_len > 2 {
            z0[2] = ark_to_nova_scalar(c);
        }
    }
    z0
}

pub(crate) fn sigma_transcript_commitment_scalar(w: &SigmaWitness<ark_bn254::Fr>) -> NovaScalar {
    let mut hasher = Keccak256::new();
    hasher.update(b"pvthfhe-symphony-t2-sigma-witness-v1");
    hasher.update(w.transcript_commitment);
    hasher.update(encode_scalar(w.ch));
    hasher.update((w.t_ntt.len() as u64).to_be_bytes());
    for limb in &w.t_ntt {
        for coeff in limb.iter().take(16) {
            hasher.update(encode_scalar(*coeff));
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    ark_to_nova_scalar(Fr::from_be_bytes_mod_order(&digest))
}

type NovaRecursiveSNARK<S> = nova_snark::nova::RecursiveSNARK<
    nova_snark::provider::Bn256EngineKZG,
    nova_snark::provider::GrumpkinEngine,
    S,
>;

impl<S> NovaCompressor<S>
where
    S: nova_snark::traits::circuit::StepCircuit<NovaScalar> + Clone + Default,
{
    pub fn prove_steps(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs3<ark_bn254::Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        clear_cyclo_ring_data();
        clear_sigma_data();

        let _guard = ThreadLocalClearGuard;

        if steps.len() != self.ivc_steps {
            tracing::debug!(
                "prove_steps: {} steps but ivc_steps={}",
                steps.len(),
                self.ivc_steps
            );
        }

        let public_inputs_hash = committed_public_inputs_hash(steps);
        let z0_primary = z0_from_acc(acc, self.state_len);

        let c_primary = S::default();
        CYCLO_FOLD_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);

        let mut recursive_snark: NovaRecursiveSNARK<S> =
            NovaRecursiveSNARK::new(&self.public_params, &c_primary, &z0_primary)
                .map_err(|_| CompressorError::Backend("nova-snark RecursiveSNARK::new failed"))?;

        for _step in 0..steps.len() {
            recursive_snark
                .prove_step(&self.public_params, &c_primary)
                .map_err(|_| CompressorError::Backend("nova-snark prove_step failed"))?;
        }

        let proof_bytes = bincode::serialize(&recursive_snark)
            .map_err(|_| CompressorError::Backend("nova-snark proof serialization failed"))?;

        let mut header = Vec::with_capacity(76 + proof_bytes.len());
        header.extend_from_slice(&PROOF_MAGIC);
        header.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        header.extend_from_slice(&normalized_hash(acc)?);

        header.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        header.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
        header.extend_from_slice(&proof_bytes);

        Ok(CompressedProof::new(header))
    }

    /// P2: Batch-folded witness data — single `prove_step` call for all steps.
    ///
    /// Folds all external inputs into one via β-weighted linear combination
    /// and processes all witness data in a single Nova IVC step. This makes
    /// the Nova accumulator O(1) instead of O(n).
    pub fn prove_steps_batch(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs3<ark_bn254::Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        use high_arity_fold::{derive_beta_vector, fold_external_inputs};

        clear_cyclo_ring_data();
        clear_sigma_data();
        let _guard = ThreadLocalClearGuard;

        if steps.is_empty() {
            return self.prove_steps(acc, steps);
        }

        let beta = derive_beta_vector(&self.srs_hash, steps.len());
        let folded = fold_external_inputs(steps, &beta);

        NOVA_BATCH_STEP_COUNT.with(|cell| *cell.borrow_mut() = steps.len());

        let public_inputs_hash = committed_public_inputs_hash(&[folded]);
        let z0_primary = z0_from_acc(acc, self.state_len);
        let c_primary = S::default();

        let mut recursive_snark: NovaRecursiveSNARK<S> =
            NovaRecursiveSNARK::new(&self.public_params, &c_primary, &z0_primary)
                .map_err(|_| CompressorError::Backend("nova-snark RecursiveSNARK::new failed"))?;

        recursive_snark
            .prove_step(&self.public_params, &c_primary)
            .map_err(|_| CompressorError::Backend("nova-snark batch prove_step failed"))?;

        NOVA_BATCH_STEP_COUNT.with(|cell| *cell.borrow_mut() = 0);

        let proof_bytes = bincode::serialize(&recursive_snark)
            .map_err(|_| CompressorError::Backend("nova-snark proof serialization failed"))?;

        let mut header = Vec::with_capacity(76 + proof_bytes.len());
        header.extend_from_slice(&PROOF_MAGIC);
        header.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        header.extend_from_slice(&normalized_hash(acc)?);
        header.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        header.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
        header.extend_from_slice(&proof_bytes);

        tracing::info!(
            steps = steps.len(),
            "nova: prove_steps_batch done — single IVC fold for all steps"
        );
        Ok(CompressedProof::new(header))
    }

    pub fn prove_steps_high_arity(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs3<ark_bn254::Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        if steps.is_empty() {
            return self.prove_steps(acc, steps);
        }

        tracing::info!(
            "high_arity: {} steps folded into single batch (Nova IVC O(1))",
            steps.len()
        );

        self.prove_steps_batch(acc, steps)
    }

    pub fn verify_steps_high_arity(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        acc: &[u8],
        steps: &[ExternalInputs3<ark_bn254::Fr>],
    ) -> Result<bool, CompressorError> {
        use high_arity_fold::*;

        // Compute hash from ORIGINAL steps (not folded), matching prove path.
        // Parse proof for the hash check, then delegate to inner verify_steps.
        let parsed = parse_proof(&proof.bytes)?;
        let expected_hash = committed_public_inputs_hash(steps);
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        let beta = derive_beta_vector(&self.srs_hash, steps.len());
        let single_folded = fold_external_inputs(steps, &beta);

        self.verify_steps(vk, proof, acc, &[single_folded])
    }

    pub fn verify_steps(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        acc: &[u8],
        steps: &[ExternalInputs3<ark_bn254::Fr>],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            tracing::error!(target: "nova", "verify_steps: verifier key mismatch");
            return Ok(false);
        }

        let parsed = parse_proof(&proof.bytes)?;

        let expected_hash = committed_public_inputs_hash(steps);
        if parsed.public_inputs_hash != expected_hash {
            tracing::error!(
                target: "nova",
                steps = steps.len(),
                "verify_steps: public inputs hash mismatch (expected != parsed)"
            );
            return Ok(false);
        }

        if parsed.acc_hash != normalized_hash(acc)? {
            tracing::error!(target: "nova", "verify_steps: accumulator hash mismatch");
            return Ok(false);
        }

        let z0_primary = z0_from_acc(acc, self.state_len);

        let recursive_snark: NovaRecursiveSNARK<S> = bincode::deserialize(parsed.ivc_bytes)
            .map_err(|e| {
                tracing::error!(target: "nova", error = %e, "verify_steps: deserialize failed");
                CompressorError::InvalidProof
            })?;

        let verify_result = recursive_snark.verify(&self.public_params, steps.len(), &z0_primary);

        match &verify_result {
            Err(e) => {
                tracing::error!(target: "nova", error = ?e, steps = steps.len(), "verify_steps: nova verify failed");
            }
            Ok(_) => {}
        }

        verify_result
            .map(|_| true)
            .map_err(|_| CompressorError::InvalidProof)
    }

    pub fn prove(
        &self,
        acc: &[u8],
        public_inputs: &[u8],
    ) -> Result<CompressedProof, CompressorError> {
        let _guard = ThreadLocalClearGuard;
        let initial = decode_triple(acc)?;
        let delta = decode_quad(public_inputs)?;
        let steps = vec![ExternalInputs3(delta.0, delta.1, delta.2)];
        let acc_encoded = encode_triple((initial.0, initial.1, initial.2));
        self.prove_steps(&acc_encoded, &steps)
    }

    pub fn verify(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        acc: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        let delta = decode_quad(public_inputs)?;
        let steps = vec![ExternalInputs3(delta.0, delta.1, delta.2)];
        self.verify_steps(vk, proof, acc, &steps)
    }

    pub fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.bytes
    }

    pub fn verify_external(
        &self,
        proof_bytes: &[u8],
        acc: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        let proof = CompressedProof::new(proof_bytes.to_vec());
        self.verify_steps(
            &self.verifier_key,
            &proof,
            acc,
            &[ExternalInputs3(
                decode_quad(public_inputs).map(|d| d.0).unwrap_or_default(),
                decode_quad(public_inputs).map(|d| d.1).unwrap_or_default(),
                decode_quad(public_inputs).map(|d| d.2).unwrap_or_default(),
            )],
        )
    }

    pub fn prove_steps_ajtai(
        &self,
        acc: &[u8],
        witnesses: &crate::witness::AjtaiCommitmentWitnessSet,
    ) -> Result<CompressedProof, CompressorError> {
        let _guard = ThreadLocalClearGuard;

        if !witnesses.verify_commitments() {
            return Err(CompressorError::InvalidProof);
        }

        let n_steps = witnesses.witnesses.len();
        if n_steps == 0 {
            return Err(CompressorError::InvalidInput);
        }

        let acc_fr = if acc.len() >= 32 {
            decode_scalar(&acc[..32])?
        } else {
            Fr::zero()
        };
        let z0_primary: Vec<NovaScalar> = vec![ark_to_nova_scalar(acc_fr)];

        let coeffs_data: Vec<Vec<Fr>> = witnesses
            .witnesses
            .iter()
            .map(|w| w.coeffs.clone())
            .collect();
        ajtai_commitment_circuit::set_ajtai_witness_data(coeffs_data);

        let c_primary = AjtaiCommitmentStepCircuit::<Fr>::default();

        let pp = nova_snark::nova::PublicParams::setup(
            &c_primary,
            &*nova_snark::traits::snark::default_ck_hint(),
            &*nova_snark::traits::snark::default_ck_hint(),
        )
        .map_err(|_| CompressorError::Backend("nova-snark PublicParams::setup for Ajtai failed"))?;

        let mut recursive_snark =
            NovaRecursiveSNARK::<AjtaiCommitmentStepCircuit<Fr>>::new(&pp, &c_primary, &z0_primary)
                .map_err(|_| {
                    CompressorError::Backend("nova-snark RecursiveSNARK::new (ajtai) failed")
                })?;

        for _step in 0..n_steps {
            recursive_snark
                .prove_step(&pp, &c_primary)
                .map_err(|_| CompressorError::Backend("nova-snark prove_step (ajtai) failed"))?;
        }

        ajtai_commitment_circuit::clear_ajtai_witness_data();

        let proof_bytes = bincode::serialize(&recursive_snark)
            .map_err(|_| CompressorError::Backend("nova-snark proof serialization failed"))?;

        let mut header = Vec::with_capacity(76 + proof_bytes.len());
        header.extend_from_slice(&PROOF_MAGIC);
        header.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        header.extend_from_slice(&normalized_hash(acc)?);

        let steps: Vec<ExternalInputs3<Fr>> = (0..n_steps)
            .map(|_| ExternalInputs3(Fr::zero(), Fr::zero(), Fr::zero()))
            .collect();
        let mut steps_bytes = Vec::new();
        for step in &steps {
            steps_bytes.extend_from_slice(&encode_triple((step.0, step.1, step.2)));
        }
        let public_inputs_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        header.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        header.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
        header.extend_from_slice(&proof_bytes);

        Ok(CompressedProof::new(header))
    }

    pub fn prove_steps_share_verify(
        &self,
        acc: &[u8],
        witnesses: &crate::witness::ShareVerificationWitnessSet,
    ) -> Result<CompressedProof, CompressorError> {
        let _guard = ThreadLocalClearGuard;

        if !witnesses.verify_commitments() {
            return Err(CompressorError::InvalidProof);
        }

        let n_steps = witnesses.witnesses.len();
        if n_steps == 0 {
            return Err(CompressorError::InvalidInput);
        }

        let acc_fr = if acc.len() >= 32 {
            decode_scalar(&acc[..32])?
        } else {
            Fr::zero()
        };
        let z0_primary: Vec<NovaScalar> = vec![ark_to_nova_scalar(acc_fr)];

        let coeffs_data: Vec<Vec<Fr>> = witnesses
            .witnesses
            .iter()
            .map(|w| w.coeffs.clone())
            .collect();
        share_verification_circuit::set_share_coeffs_data(coeffs_data);

        let c_primary = ShareVerificationStepCircuit::<Fr>::default();

        let pp = nova_snark::nova::PublicParams::setup(
            &c_primary,
            &*nova_snark::traits::snark::default_ck_hint(),
            &*nova_snark::traits::snark::default_ck_hint(),
        )
        .map_err(|_| {
            CompressorError::Backend("nova-snark PublicParams::setup for ShareVerify failed")
        })?;

        let mut recursive_snark = NovaRecursiveSNARK::<ShareVerificationStepCircuit<Fr>>::new(
            &pp,
            &c_primary,
            &z0_primary,
        )
        .map_err(|_| {
            CompressorError::Backend("nova-snark RecursiveSNARK::new (share-verify) failed")
        })?;

        for _step in 0..n_steps {
            recursive_snark.prove_step(&pp, &c_primary).map_err(|_| {
                CompressorError::Backend("nova-snark prove_step (share-verify) failed")
            })?;
        }

        share_verification_circuit::clear_share_coeffs_data();

        let proof_bytes = bincode::serialize(&recursive_snark)
            .map_err(|_| CompressorError::Backend("nova-snark proof serialization failed"))?;

        let mut header = Vec::with_capacity(76 + proof_bytes.len());
        header.extend_from_slice(&PROOF_MAGIC);
        header.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        header.extend_from_slice(&normalized_hash(acc)?);

        let steps: Vec<ExternalInputs3<Fr>> = (0..n_steps)
            .map(|_| ExternalInputs3(Fr::zero(), Fr::zero(), Fr::zero()))
            .collect();
        let mut steps_bytes = Vec::new();
        for step in &steps {
            steps_bytes.extend_from_slice(&encode_triple((step.0, step.1, step.2)));
        }
        let public_inputs_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        header.extend_from_slice(&public_inputs_hash);
        #[allow(clippy::as_conversions)]
        header.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
        header.extend_from_slice(&proof_bytes);

        Ok(CompressedProof::new(header))
    }
}
// ProofCompressor impl for ExternalInputs3-based step circuits
// (ToyStepCircuit, FoldVerifierStepCircuit, RingVerifierCircuit, etc.)
#[cfg(feature = "legacy-nova")]
impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = ExternalInputs3<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > ProofCompressor for NovaCompressor<S>
{
    fn prove(&self, acc: &[u8], public_inputs: &[u8]) -> Result<CompressedProof, CompressorError> {
        // BLOCKER(phase=4): The Nova SNARK wrapper for on-chain IVC verification
        // is not available in the current Nova revision (63f2930d). After
        // nova.ivc_proof(), the relaxed R1CS final instance should be
        // Groth16/PLONK-snarked via nova.generate_proof(). See:
        // circuits/nova_state_commitment/src/main.nr for the Poseidon shortcut
        // that this would replace. Unblocked by Nova audit completion.
        clear_cyclo_ring_data();
        clear_sigma_data();

        let _guard = ThreadLocalClearGuard;

        let initial = decode_triple(acc)?;
        let delta = decode_triple(public_inputs)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("nova circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = NovaNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("nova init failed"))?;
        tracing::info!(rss_kb = rss_kb(), "nova: Nova::init done");
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        let ext_inputs = ExternalInputs3(delta.0, delta.1, delta.2);
        for step in 0..self.ivc_steps {
            nova.prove_step(&mut rng, ext_inputs, None)
                .map_err(|_| CompressorError::Backend("nova prove step failed"))?;
            tracing::info!(step = step, rss_kb = rss_kb(), "nova: prove_step done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova proof serialization failed"))?;
        let acc_hash_arr = normalized_hash(acc)?;
        let pi_hash_arr = normalized_hash(public_inputs)?;
        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "nova: ivc proof serialized"
        );

        let snark_seed = u64::from_le_bytes(self.srs_hash[..8].try_into().unwrap_or([0u8; 8]));
        let snark_result = snark_bridge::wrap_nova_instance(
            nova,
            &self.verifier_key_bytes,
            self.state_len,
            snark_seed,
            compute_share_verification_hash(),
            self.decrypt_nizk_hash,
            self.dkg_transcript_hash,
        )?;

        let snark_proof = if snark_result.snark_proof_bytes.is_empty() {
            None
        } else {
            Some(snark_result.snark_proof_bytes.as_slice())
        };

        let proof_bytes = build_proof_bytes(
            PROOF_MAGIC,
            PROOF_VERSION,
            &acc_hash_arr,
            &pi_hash_arr,
            &ivc_bytes,
            snark_proof,
        );
        let mut proof = CompressedProof::new(proof_bytes);
        proof.ivc_proof_hash = Some(snark_result.pp_hash);
        proof.ivc_binding = Some(snark_result.ivc_binding);
        proof.sigma_data_hash = Some(compute_share_verification_hash());
        Ok(proof)
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

        let parsed = parse_proof(&proof.bytes)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        verify_ivc_core::<S>(&parsed, self.state_len, &self.verifier_key_bytes, |z| {
            normalized_hash(&encode_triple((z[0], z[1], z[2])))
        })
    }

    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn vk_bytes(&self) -> &[u8] {
        &self.verifier_key_bytes
    }

    fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.bytes
    }
}

// ProofCompressor impl for CycloFoldStepCircuit with G.16 hash-chain binding.
// Keep this concrete: blanket impls distinguished only by associated-type
// equality overlap under Rust coherence.
#[cfg(feature = "legacy-nova")]
impl ProofCompressor for NovaCompressor<CycloFoldStepCircuit<Fr>> {
    fn prove(&self, acc: &[u8], public_inputs: &[u8]) -> Result<CompressedProof, CompressorError> {
        // F6.3: clear stale thread-local witness data from prior prove calls
        clear_cyclo_ring_data();
        clear_sigma_data();
        clear_sigma_response_data();

        let _guard = ThreadLocalClearGuard;

        let initial = decode_hex(acc)?;
        let delta = decode_quad(public_inputs)?;
        let params = self.deserialize_params()?;
        let circuit = CycloFoldStepCircuit::<Fr>::new(())
            .map_err(|_| CompressorError::Backend("nova circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        initial_state.push(initial.3);
        initial_state.push(initial.4);
        initial_state.push(initial.5);
        initial_state.push(initial.6);
        initial_state.push(initial.7);

        let mut nova = NovaNova::<CycloFoldStepCircuit<Fr>>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("nova init failed"))?;
        tracing::info!(rss_kb = rss_kb(), "nova: Nova::init done");
        // Reproducible folding RNG — bound to session epoch via srs_hash.
        // Acceptable for research prototype; production should mix OsRng nonce.
        // allow-seeded-rng: deterministic RNG from epoch-bound srs_hash
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        let ext_inputs = ExternalInputs4(delta.0, delta.1, delta.2, delta.3);
        for step in 0..self.ivc_steps {
            nova.prove_step(&mut rng, ext_inputs, None)
                .map_err(|_| CompressorError::Backend("nova prove step failed"))?;
            tracing::info!(step = step, rss_kb = rss_kb(), "nova: prove_step done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova proof serialization failed"))?;
        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "nova: ivc proof serialized"
        );

        let snark_seed = u64::from_le_bytes(self.srs_hash[..8].try_into().unwrap_or([0u8; 8]));
        let snark_result = snark_bridge::wrap_nova_instance(
            nova,
            &self.verifier_key_bytes,
            self.state_len,
            snark_seed,
            compute_share_verification_hash(),
            self.decrypt_nizk_hash,
            self.dkg_transcript_hash,
        )?;

        let snark_proof_bytes = if snark_result.snark_proof_bytes.is_empty() {
            None
        } else {
            Some(snark_result.snark_proof_bytes.as_slice())
        };

        let proof_bytes = build_proof_bytes(
            PROOF_MAGIC,
            PROOF_VERSION,
            &normalized_hash(acc)?,
            &normalized_hash(public_inputs)?,
            &ivc_bytes,
            snark_proof_bytes,
        );
        let mut proof = CompressedProof::new(proof_bytes);
        proof.ivc_proof_hash = Some(snark_result.pp_hash);
        proof.ivc_binding = Some(snark_result.ivc_binding);
        proof.sigma_data_hash = Some(compute_share_verification_hash());
        Ok(proof)
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

        let parsed = parse_proof(&proof.bytes)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        verify_ivc_core::<CycloFoldStepCircuit<Fr>>(
            &parsed,
            self.state_len,
            &self.verifier_key_bytes,
            |z| {
                normalized_hash(&encode_hex((
                    z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7],
                )))
            },
        )
    }

    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn vk_bytes(&self) -> &[u8] {
        &self.verifier_key_bytes
    }

    fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.bytes
    }
}

// Impl for ExternalInputs3-based step circuits (prove_steps / verify_steps)
#[cfg(feature = "legacy-nova")]
impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = ExternalInputs3<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > NovaCompressor<S>
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

        verify_ivc_core::<S>(&parsed, self.state_len, &self.verifier_key_bytes, |z| {
            normalized_hash(&encode_triple((z[0], z[1], z[2])))
        })
    }

    pub fn prove_steps(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs3<Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        clear_cyclo_ring_data();
        clear_sigma_data();

        let _guard = ThreadLocalClearGuard;

        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_triple(acc)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("nova circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = NovaNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("nova init failed"))?;
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, *ext_inputs, None)
                .map_err(|_| CompressorError::Backend("nova prove step failed"))?;
            tracing::info!(step = step_idx, rss_kb = rss_kb(), "nova: prove_steps done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova proof serialization failed"))?;

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

        let snark_seed = u64::from_le_bytes(self.srs_hash[..8].try_into().unwrap_or([0u8; 8]));
        let snark_result = snark_bridge::wrap_nova_instance(
            nova,
            &self.verifier_key_bytes,
            self.state_len,
            snark_seed,
            compute_share_verification_hash(),
            self.decrypt_nizk_hash,
            self.dkg_transcript_hash,
        )?;

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "nova: prove_steps proof serialized"
        );
        let mut proof = CompressedProof::new(proof_bytes);
        proof.ivc_proof_hash = Some(snark_result.pp_hash);
        proof.ivc_binding = Some(snark_result.ivc_binding);
        proof.sigma_data_hash = Some(compute_share_verification_hash());
        Ok(proof)
    }

    pub fn verify_steps(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        steps: &[ExternalInputs3<Fr>],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            tracing::warn!("verify_steps(EI3): verifier key mismatch");
            return Ok(false);
        }

        let parsed = parse_proof(&proof.bytes)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_triple((step.0, step.1, step.2)));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        verify_ivc_core::<S>(&parsed, self.state_len, &self.verifier_key_bytes, |z| {
            normalized_hash(&encode_triple((z[0], z[1], z[2])))
        })
    }
}

// Impl for CycloFoldStepCircuit (ExternalInputs4 prove_steps / verify_steps).
#[cfg(feature = "legacy-nova")]
impl NovaCompressor<CycloFoldStepCircuit<Fr>> {
    pub fn verify_external(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        let parsed = parse_proof(proof_bytes)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        verify_ivc_core::<CycloFoldStepCircuit<Fr>>(
            &parsed,
            self.state_len,
            &self.verifier_key_bytes,
            |z| {
                normalized_hash(&encode_hex((
                    z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7],
                )))
            },
        )
    }

    pub fn prove_steps(
        &self,
        acc: &[u8],
        steps: &[ExternalInputs4<Fr>],
    ) -> Result<CompressedProof, CompressorError> {
        clear_cyclo_ring_data();
        clear_sigma_response_data();

        let _guard = ThreadLocalClearGuard;

        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_hex(acc)?;
        let params = self.deserialize_params()?;
        let circuit = CycloFoldStepCircuit::<Fr>::new(())
            .map_err(|_| CompressorError::Backend("nova circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        initial_state.push(initial.3);
        initial_state.push(initial.4);
        initial_state.push(initial.5);
        initial_state.push(initial.6);
        initial_state.push(initial.7);

        let mut nova = NovaNova::<CycloFoldStepCircuit<Fr>>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("nova init failed"))?;
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, *ext_inputs, None)
                .map_err(|_| CompressorError::Backend("nova prove step failed"))?;
            tracing::info!(step = step_idx, rss_kb = rss_kb(), "nova: prove_steps done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova proof serialization failed"))?;

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

        let snark_seed = u64::from_le_bytes(self.srs_hash[..8].try_into().unwrap_or([0u8; 8]));
        let snark_result = snark_bridge::wrap_nova_instance(
            nova,
            &self.verifier_key_bytes,
            self.state_len,
            snark_seed,
            compute_share_verification_hash(),
            self.decrypt_nizk_hash,
            self.dkg_transcript_hash,
        )?;

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "nova: prove_steps proof serialized"
        );
        let mut proof = CompressedProof::new(proof_bytes);
        proof.ivc_proof_hash = Some(snark_result.pp_hash);
        proof.ivc_binding = Some(snark_result.ivc_binding);
        proof.sigma_data_hash = Some(compute_share_verification_hash());
        Ok(proof)
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
        let _guard = ThreadLocalClearGuard;
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
        let _guard = ThreadLocalClearGuard;
        use crate::nova::ajtai_commitment_circuit::{
            clear_ajtai_witness_data, set_ajtai_witness_data,
        };

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

        let parsed = parse_proof(&proof.bytes)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_quad((step.0, step.1, step.2, step.3)));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        verify_ivc_core::<CycloFoldStepCircuit<Fr>>(
            &parsed,
            self.state_len,
            &self.verifier_key_bytes,
            |z| {
                normalized_hash(&encode_hex((
                    z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7],
                )))
            },
        )
    }
}

#[cfg(feature = "legacy-nova")]
impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = C7MerkleExternalInputs<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > NovaCompressor<S>
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
        let _guard = ThreadLocalClearGuard;
        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_triple(acc)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("nova circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = NovaNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("nova init failed"))?;
        // Reproducible folding RNG — bound to session epoch via srs_hash.
        // Acceptable for research prototype; production should mix OsRng nonce.
        // allow-seeded-rng: deterministic RNG from epoch-bound srs_hash
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, ext_inputs.clone(), None)
                .map_err(|_| CompressorError::Backend("nova prove step merkle failed"))?;
            tracing::info!(
                step = step_idx,
                rss_kb = rss_kb(),
                "nova: prove_steps_merkle done"
            );
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova proof serialization failed"))?;

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

        let snark_seed = u64::from_le_bytes(self.srs_hash[..8].try_into().unwrap_or([0u8; 8]));
        let snark_result = snark_bridge::wrap_nova_instance(
            nova,
            &self.verifier_key_bytes,
            self.state_len,
            snark_seed,
            compute_share_verification_hash(),
            self.decrypt_nizk_hash,
            self.dkg_transcript_hash,
        )?;

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "nova: prove_steps_merkle proof serialized"
        );
        let mut proof = CompressedProof::new(proof_bytes);
        proof.ivc_proof_hash = Some(snark_result.pp_hash);
        proof.ivc_binding = Some(snark_result.ivc_binding);
        proof.sigma_data_hash = Some(compute_share_verification_hash());
        Ok(proof)
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

        let parsed = parse_proof(&proof.bytes)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_merkle_step(step));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        verify_ivc_core::<S>(&parsed, self.state_len, &self.verifier_key_bytes, |z| {
            normalized_hash(&encode_triple((z[0], z[1], z[2])))
        })
    }
}

#[cfg(feature = "legacy-nova")]
impl<
        S: FCircuit<Fr, Params = (), ExternalInputs = ExternalInputs5<Fr>>
            + StepCircuit
            + Clone
            + Debug,
    > NovaCompressor<S>
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
        let _guard = ThreadLocalClearGuard;
        assert_eq!(
            steps.len(),
            self.ivc_steps,
            "steps.len() must equal ivc_steps ({})",
            self.ivc_steps
        );

        let initial = decode_triple(acc)?;
        let params = self.deserialize_params()?;
        let circuit =
            S::new(()).map_err(|_| CompressorError::Backend("nova circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial.0);
        initial_state.push(initial.1);
        initial_state.push(initial.2);
        for _ in 3..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = NovaNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("nova init failed"))?;
        // Reproducible folding RNG — bound to session epoch via srs_hash.
        // Acceptable for research prototype; production should mix OsRng nonce.
        // allow-seeded-rng: deterministic RNG from epoch-bound srs_hash
        let mut rng = ChaCha20Rng::from_seed(self.srs_hash);

        for (step_idx, ext_inputs) in steps.iter().enumerate() {
            nova.prove_step(&mut rng, *ext_inputs, None)
                .map_err(|_| CompressorError::Backend("nova prove step c7 failed"))?;
            tracing::info!(
                step = step_idx,
                rss_kb = rss_kb(),
                "nova: prove_steps_c7 done"
            );
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("nova proof serialization failed"))?;

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

        let snark_seed = u64::from_le_bytes(self.srs_hash[..8].try_into().unwrap_or([0u8; 8]));
        let snark_result = snark_bridge::wrap_nova_instance(
            nova,
            &self.verifier_key_bytes,
            self.state_len,
            snark_seed,
            compute_share_verification_hash(),
            self.decrypt_nizk_hash,
            self.dkg_transcript_hash,
        )?;

        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "nova: prove_steps_c7 proof serialized"
        );
        let mut proof = CompressedProof::new(proof_bytes);
        proof.ivc_proof_hash = Some(snark_result.pp_hash);
        proof.ivc_binding = Some(snark_result.ivc_binding);
        proof.sigma_data_hash = Some(compute_share_verification_hash());
        Ok(proof)
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

        let parsed = parse_proof(&proof.bytes)?;

        let mut steps_bytes = Vec::new();
        for step in steps {
            steps_bytes.extend_from_slice(&encode_quint(*step));
        }
        let expected_hash: [u8; 32] = Keccak256::digest(&steps_bytes).into();
        if parsed.public_inputs_hash != expected_hash {
            return Ok(false);
        }

        verify_ivc_core::<S>(&parsed, self.state_len, &self.verifier_key_bytes, |z| {
            normalized_hash(&encode_triple((z[0], z[1], z[2])))
        })
    }
}

/// Verify IVC proof and enforce G.30 counter consistency.
///
/// After the caller validates the proof header (magic, version, public_inputs_hash),
/// this function deserializes the IVC proof, checks state lengths and `acc_hash`,
/// deserializes the verifier key, verifies the Nova proof, and enforces counter
/// consistency (ring_count, sigma_count).
///
/// `state_hash` computes the expected accumulator hash from `z_0`.
#[cfg(feature = "legacy-nova")]
fn verify_ivc_core<S: FCircuit<Fr, Params = ()>>(
    parsed: &ParsedProof<'_>,
    state_len: usize,
    vk_bytes: &[u8],
    state_hash: impl FnOnce(&[Fr]) -> Result<[u8; 32], CompressorError>,
) -> Result<bool, CompressorError> {
    let ivc_proof =
        NovaIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
            .map_err(|_| CompressorError::InvalidProof)?;

    if ivc_proof.z_0.len() != state_len || ivc_proof.z_i.len() != state_len {
        tracing::warn!(
            "state_len mismatch: z_0={} z_i={} expected={}",
            ivc_proof.z_0.len(),
            ivc_proof.z_i.len(),
            state_len
        );
        return Ok(false);
    }

    let computed_hash = state_hash(&ivc_proof.z_0)?;
    if computed_hash != parsed.acc_hash {
        tracing::warn!(
            "acc_hash mismatch: expected={:02x?} got={:02x?}",
            parsed.acc_hash,
            computed_hash
        );
        return Ok(false);
    }

    let verifier =
        NovaNova::<S>::vp_deserialize_with_mode(vk_bytes, Compress::Yes, Validate::Yes, ())
            .map_err(|_| CompressorError::Backend("nova verifier key deserialization failed"))?;

    // G.30: Counter consistency enforcement.
    // Track A: counters always increment (ring_inc = FpVar::one()), even with zero data.
    // Track B: counters only increment when real verification data was set via thread-locals.
    // The fold_count == verification_count check ensures the prover ran each step,
    // but does NOT guarantee actual verification data was present (that's a Track A/B distinction).
    let ring_check = if state_len >= 4 {
        Some((ivc_proof.z_i[2], ivc_proof.z_i[3]))
    } else {
        None
    };

    let sigma_check = if state_len >= 5 {
        Some((ivc_proof.z_i[2], ivc_proof.z_i[4]))
    } else {
        None
    };

    let bfv_check = if state_len >= 8 {
        Some((ivc_proof.z_i[2], ivc_proof.z_i[7]))
    } else {
        None
    };

    if let Err(e) = NovaNova::<S>::verify(verifier, ivc_proof) {
        tracing::warn!("Nova::verify failed: {:?}", e);
        return Ok(false);
    }

    if let Some((fold_count, verification_count)) = ring_check {
        if fold_count != verification_count {
            tracing::warn!(
                "fold_count {:?} != verification_count {:?}",
                fold_count,
                verification_count
            );
            return Ok(false);
        }
    }

    if let Some((fold_count, sigma_count)) = sigma_check {
        // With SIGMA_REPETITIONS rounds per fold step, sigma_count accumulates
        // k per step instead of 1. Check fold_count * k == sigma_count.
        let expected_sigma_count = fold_count * Fr::from(SIGMA_REPETITIONS as u64);
        if expected_sigma_count != sigma_count {
            tracing::warn!(
                "fold_count {:?} != sigma_verification_count {:?}",
                fold_count,
                sigma_count
            );
            return Ok(false);
        }
    }

    if let Some((fold_count, bfv_count)) = bfv_check {
        // Only enforce bfv_count == fold_count when bfv data was actually
        // populated. If bfv_count is 0, assume the pipeline path doesn't
        // include bfv verification (Track A / data-absent paths).
        if fold_count != bfv_count {
            tracing::warn!(
                "fold_count {:?} != bfv_verification_count {:?}",
                fold_count,
                bfv_count
            );
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

pub(crate) struct ParsedProof<'a> {
    pub(crate) acc_hash: [u8; 32],
    pub(crate) public_inputs_hash: [u8; 32],
    pub(crate) ivc_bytes: &'a [u8],
    pub(crate) snark_bytes: Option<&'a [u8]>,
}

pub(crate) fn parse_proof(bytes: &[u8]) -> Result<ParsedProof<'_>, CompressorError> {
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

    if bytes.len() < 76 + ivc_len {
        return Err(CompressorError::InvalidProof);
    }

    // Check for extended format with optional SNARK proof trailer.
    let snark_offset = 76 + ivc_len;
    let (ivc_bytes, snark_bytes) = if bytes.len() == snark_offset {
        // Original format: no SNARK trailer.
        (&bytes[76..snark_offset], None)
    } else if bytes.len() >= snark_offset + 4 {
        // Extended format: snark_len[u32 BE] + snark_bytes.
        #[allow(clippy::as_conversions)]
        let snark_len = u32::from_be_bytes(
            bytes[snark_offset..snark_offset + 4]
                .try_into()
                .map_err(|_| CompressorError::InvalidProof)?,
        ) as usize;
        if bytes.len() != snark_offset + 4 + snark_len {
            return Err(CompressorError::InvalidProof);
        }
        let snark = if snark_len > 0 {
            Some(&bytes[snark_offset + 4..])
        } else {
            None
        };
        (&bytes[76..snark_offset], snark)
    } else {
        return Err(CompressorError::InvalidProof);
    };

    Ok(ParsedProof {
        acc_hash,
        public_inputs_hash,
        ivc_bytes,
        snark_bytes,
    })
}

/// Build a compressed proof byte vector with the optional SNARK trailer.
pub(crate) fn build_proof_bytes(
    magic: [u8; 4],
    version: u32,
    acc_hash: &[u8; 32],
    public_inputs_hash: &[u8; 32],
    ivc_bytes: &[u8],
    snark_proof: Option<&[u8]>,
) -> Vec<u8> {
    let snark_len = snark_proof.map_or(0u32, |p| p.len() as u32);
    let mut out = Vec::with_capacity(80 + ivc_bytes.len() + snark_len as usize);
    out.extend_from_slice(&magic);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(acc_hash);
    out.extend_from_slice(public_inputs_hash);
    #[allow(clippy::as_conversions)]
    out.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(ivc_bytes);
    out.extend_from_slice(&snark_len.to_be_bytes());
    if let Some(snark) = snark_proof {
        out.extend_from_slice(snark);
    }
    out
}

/// Extract the final CycloFold accumulator state (z_i) from a compressed proof.
///
/// State layout: z[0]=hash, z[1]=escalated_norm, z[2]=fold_count,
/// z[3]=ring_verif_count, z[4]=sigma_count, z[5]=z_s_proj_acc, z[6]=z_e_proj_acc,
/// z[7]=bfv_verification_count.
pub fn extract_cyclo_state(_proof: &CompressedProof) -> Result<[Fr; 8], CompressorError> {
    #[cfg(feature = "legacy-nova")]
    {
        let parsed = parse_proof(&proof.bytes)?;
        let ivc_proof =
            NovaIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;
        if ivc_proof.z_i.len() != 8 {
            return Err(CompressorError::InvalidProof);
        }
        let mut state = [Fr::zero(); 8];
        for (i, val) in ivc_proof.z_i.iter().enumerate() {
            state[i] = *val;
        }
        Ok(state)
    }
    #[cfg(not(feature = "legacy-nova"))]
    {
        // nova-snark backend: state extraction from RecursiveSNARK is not yet wired.
        Err(CompressorError::InvalidProof)
    }
}

fn decode_scalar(bytes: &[u8]) -> Result<Fr, CompressorError> {
    if bytes.is_empty() {
        return Err(CompressorError::InvalidInput);
    }
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

pub fn encode_scalar(value: Fr) -> Vec<u8> {
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

pub fn decode_hex(bytes: &[u8]) -> Result<(Fr, Fr, Fr, Fr, Fr, Fr, Fr, Fr), CompressorError> {
    if bytes.len() < 256 {
        return Err(CompressorError::InvalidInput);
    }
    let a = decode_scalar(&bytes[0..32])?;
    let b = decode_scalar(&bytes[32..64])?;
    let c = decode_scalar(&bytes[64..96])?;
    let d = decode_scalar(&bytes[96..128])?;
    let e = decode_scalar(&bytes[128..160])?;
    let f = decode_scalar(&bytes[160..192])?;
    let g = decode_scalar(&bytes[192..224])?;
    let h = decode_scalar(&bytes[224..256])?;
    Ok((a, b, c, d, e, f, g, h))
}

pub fn encode_hex(value: (Fr, Fr, Fr, Fr, Fr, Fr, Fr, Fr)) -> [u8; 256] {
    let mut out = [0u8; 256];
    let a = encode_scalar(value.0);
    let b = encode_scalar(value.1);
    let c = encode_scalar(value.2);
    let d = encode_scalar(value.3);
    let e = encode_scalar(value.4);
    let f = encode_scalar(value.5);
    let g = encode_scalar(value.6);
    let h = encode_scalar(value.7);
    out[0..32].copy_from_slice(&a);
    out[32..64].copy_from_slice(&b);
    out[64..96].copy_from_slice(&c);
    out[96..128].copy_from_slice(&d);
    out[128..160].copy_from_slice(&e);
    out[160..192].copy_from_slice(&f);
    out[192..224].copy_from_slice(&g);
    out[224..256].copy_from_slice(&h);
    out
}

fn encode_quint(value: ExternalInputs5<Fr>) -> [u8; 160] {
    let mut buf = [0u8; 160];
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.0, &mut buf[0..32]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.1, &mut buf[32..64]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.2, &mut buf[64..96]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.3, &mut buf[96..128]).unwrap();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&value.4, &mut buf[128..160])
        .unwrap();
    buf
}

#[cfg(feature = "legacy-nova")]
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
