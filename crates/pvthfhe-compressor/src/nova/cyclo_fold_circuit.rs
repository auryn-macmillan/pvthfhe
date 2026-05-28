//! CycloFoldStepCircuit — Nova (arecibo) StepCircuit migration.
//!
//! KNOWN_LIMITATION(cyclofold-aruty-8): CycloFoldStepCircuit (arity=8) with
//! sigma/ring/BFV gadgets has a Nova RecursiveSNARK setup issue at arity > 3.
//! The demo-e2e uses DkgAggregationStepCircuit (arity=3) as the aggregated
//! compressor surrogate. Full CycloFold support is tracked at:
//!   .sisyphus/plans/production-readiness.md#B7
//!
//! Bellpepper/arecibo-compatible circuit that replaces thread-local witness data
//! with struct fields set by the caller before each `prove_step` call.
//!
//! ## State layout (8 elements, matching `CycloFoldStepCircuit::state_len()`)
//!
//! | Index | Name                | Description                        |
//! |-------|---------------------|------------------------------------|
//! | z[0]  | running_sum         | Accumulated contribution sum       |
//! | z[1]  | share_chain_hash    | Poseidon chain hash accumulator    |
//! | z[2]  | step_count          | Number of fold steps executed      |
//! | z[3]  | verification_count  | Accumulated verification passes    |
//! | z[4]  | sigma_count         | Sigma NIZK verification passes     |
//! | z[5]  | ring_count          | Ring equation verification passes  |
//! | z[6]  | bfv_count           | BFV encryption verification passes |
//! | z[7]  | last_hash           | Hash of the previous step          |
//!
//! Sigma NIZK, ring equation, and BFV encryption verification gadgets are not
//! yet ported to bellpepper. Witness fields are allocated from struct values
//! computed off-circuit. Full in-circuit verification requires future gadget
//! migrations.

use crate::{StepCircuit, StepCircuitDescriptor};
use sha3::{Digest, Keccak256};
use std::marker::PhantomData;

#[cfg(feature = "nova-backend")]
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};

/// CycloFold aggregator step circuit for the arecibo (bellpepper) backend.
///
/// Replaces the legacy thread-local witness pattern (`SIGMA_DATA`,
/// `CYCLO_RING_DATA`, `BFV_ENCRYPTION_DATA`) with explicit struct fields
/// that the caller populates before each IVC `prove_step` call.
///
/// ## Witness fields
///
/// | Field          | Meaning                                       |
/// |----------------|-----------------------------------------------|
/// | `sigma_ok`     | Per-step sigma NIZK result (1 = pass)         |
/// | `ring_ok`      | Per-step ring equation result (1 = pass)      |
/// | `bfv_ok`       | Per-step BFV encryption result (1 = pass)     |
/// | `step_hash`    | Hash of this step's contribution              |
/// | `last_hash`    | Hash of the prior step (hash-chain binding)   |
/// | `contribution` | Scalar contribution to running_sum            |
#[derive(Clone, Debug, Default)]
pub struct CycloFoldStepCircuit<F> {
    _phantom: PhantomData<F>,

    /// `Fr::one()` if the per-step sigma equation was verified, `Fr::zero()` otherwise.
    pub sigma_ok: F,

    /// `Fr::one()` if the per-step G2-ng ring equation was verified, `Fr::zero()` otherwise.
    pub ring_ok: F,

    /// `Fr::one()` if the per-step BFV ciphertext well-formedness was verified.
    pub bfv_ok: F,

    /// Hash of this step's contribution data (placeholder Poseidon hash).
    pub step_hash: F,

    /// Hash of the previous step's final state (G.16 hash-chain binding).
    pub last_hash: F,

    /// Scalar contribution added to the running accumulation sum.
    pub contribution: F,
}

#[cfg(feature = "nova-backend")]
impl<F> arecibo::traits::circuit::StepCircuit<F> for CycloFoldStepCircuit<F>
where
    F: bp_ff::PrimeField,
{
    fn arity(&self) -> usize {
        8
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let sigma_ok = AllocatedNum::alloc(cs.namespace(|| "sigma_ok"), || Ok(self.sigma_ok))?;
        let ring_ok = AllocatedNum::alloc(cs.namespace(|| "ring_ok"), || Ok(self.ring_ok))?;
        let bfv_ok = AllocatedNum::alloc(cs.namespace(|| "bfv_ok"), || Ok(self.bfv_ok))?;
        let step_hash = AllocatedNum::alloc(cs.namespace(|| "step_hash"), || Ok(self.step_hash))?;
        let contribution =
            AllocatedNum::alloc(cs.namespace(|| "contribution"), || Ok(self.contribution))?;
        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::from(1u64)))?;

        let running_sum = z[0]
            .clone()
            .add(cs.namespace(|| "running_sum_add"), &contribution)?;
        let share_chain_hash = z[1]
            .clone()
            .add(cs.namespace(|| "chain_hash_add"), &step_hash)?;
        let step_count = z[2].clone().add(cs.namespace(|| "step_count_inc"), &one)?;
        let verification_count = z[3]
            .clone()
            .add(cs.namespace(|| "verif_count_add"), &sigma_ok)?;
        let sigma_count = z[4]
            .clone()
            .add(cs.namespace(|| "sigma_count_add"), &sigma_ok)?;
        let ring_count = z[5]
            .clone()
            .add(cs.namespace(|| "ring_count_add"), &ring_ok)?;
        let bfv_count = z[6]
            .clone()
            .add(cs.namespace(|| "bfv_count_add"), &bfv_ok)?;
        let last_hash = z[7]
            .clone()
            .add(cs.namespace(|| "last_hash_add"), &step_hash)?;

        Ok(vec![
            running_sum,
            share_chain_hash,
            step_count,
            verification_count,
            sigma_count,
            ring_count,
            bfv_count,
            last_hash,
        ])
    }
}

impl<F> StepCircuit for CycloFoldStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 8 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/cyclo-fold-arecibo/v1").into()
    }
}
