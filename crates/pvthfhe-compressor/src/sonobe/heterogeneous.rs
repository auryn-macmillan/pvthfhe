//! Heterogeneous IVC (MicroNova) support for Sonobe Nova.
//!
//! A heterogeneous circuit family allows each IVC step `i` to use a different
//! circuit variant. The [`HeterogeneousCircuitFamily`] trait defines the
//! dispatch interface, and [`HeterogeneousStepCircuit`] implements
//! [`folding_schemes::frontend::FCircuit`] by delegating to the family.
//!
//! This enables MicroNova-style folding where a single Sonobe Nova prover
//! handles multiple circuit variants within one IVC chain.
//!
//! NOTE: Nova preprocessor compiles only ONE circuit variant (the first call to
//! generate_step_constraints during FCircuit::new). For heterogeneous dispatch,
//! ALL circuit variants must produce structurally identical constraint systems
//! (same constraint count and variable shape). This holds for LatticeFoldTreeCircuitFamily
//! where both leaf and internal variants use 3-element state + 3 arithmetic ops.
//! See docs/security-proofs/p3/heterogeneous-ivc.md:96-99 for the verifier key
//! soundness gap and planned per-variant hash check.
//!
//! # Usage
//!
//! ```ignore
//! use pvthfhe_compressor::sonobe::heterogeneous::HeterogeneousStepCircuit;
//! use pvthfhe_compressor::sonobe::latticefold_circuit_family::LatticeFoldTreeCircuitFamily;
//!
//! // Set the family before constructing the compressor:
//! HeterogeneousStepCircuit::<Fr>::set_family(LatticeFoldTreeCircuitFamily { depth: 2 });
//!
//! // Then use SonobeCompressor<HeterogeneousStepCircuit<Fr>> as usual.
//! ```

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(not(feature = "nova-backend"))]
use folding_schemes::frontend::FCircuit;
use sha3::{Digest, Keccak256};
use std::cell::RefCell;
use std::fmt::Debug;

use super::latticefold_circuit_family::LatticeFoldTreeCircuitFamily;
use super::{ExternalInputs3, ExternalInputs3Var};
use crate::{StepCircuit, StepCircuitDescriptor};

/// A family of circuits where each step `i` may use a different circuit variant.
///
/// All circuits in the family must share the same state length and external
/// inputs width. The step index `i` determines which variant is used via
/// [`circuit_index`].
///
/// # Type parameters
///
/// * `F` - The prime field used for constraint variables (e.g., BN254 scalar field).
pub trait HeterogeneousCircuitFamily<F: PrimeField>: Debug {
    /// Number of distinct circuit variants in the family.
    ///
    /// For a LatticeFold+ tree this is typically 2 (leaf verifier + internal
    /// fold verifier). A single-circuit family returns 1.
    fn num_circuits(&self) -> usize;

    /// Which circuit variant handles step `i`.
    ///
    /// Must return a value in `0..num_circuits()`. The mapping must be
    /// deterministic for a given family configuration.
    fn circuit_index(&self, i: usize) -> usize;

    /// Circuit hash for variant `idx`.
    ///
    /// This is used for verifier key tracking and must be a cryptographic
    /// hash that uniquely identifies the circuit variant. Two different
    /// variants MUST produce different hashes.
    fn circuit_hash(&self, idx: usize) -> [u8; 32];

    /// Generate constraints for step `i` using circuit variant `circuit_index(i)`.
    ///
    /// # Parameters
    ///
    /// * `cs` - Constraint system to add constraints to.
    /// * `i` - Step index (0-based).
    /// * `z_i` - Current state variables.
    /// * `external_inputs` - External inputs for this step.
    ///
    /// # Returns
    ///
    /// The next state `z_{i+1}` as a vector of constraint variables.
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: ExternalInputs3Var<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

// ── Thread-local circuit family registry ──────────────────────────────────
//
// SonobeCompressor requires `Params = ()`, so the family cannot be passed
// through `FCircuit::new`. Instead it is registered per-thread before
// compressor construction. This provides test isolation while respecting
// the `Params = ()` constraint.

thread_local! {
    static HET_CIRCUIT_FAMILY: RefCell<Option<LatticeFoldTreeCircuitFamily>> = RefCell::new(None);
}

/// A Nova step circuit that delegates to a [`HeterogeneousCircuitFamily`].
///
/// Each IVC step `i` dispatches to `family.generate_step_constraints(..., i, ...)`
/// using the family variant determined by `family.circuit_index(i)`.
///
/// The circuit family must be set via [`set_family`] before constructing a
/// [`SonobeCompressor`] with this step circuit. If not set, a default
/// family (depth=2) is used.
///
/// # State
///
/// State length is 3: `[accumulated_hash, accumulated_norm, fold_count]`.
/// This matches the existing [`ToyStepCircuit`] and [`CycloFoldStepCircuit`]
/// conventions.
#[derive(Clone, Debug)]
pub struct HeterogeneousStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField> HeterogeneousStepCircuit<F> {
    /// Register the circuit family for the current thread.
    ///
    /// Must be called before [`SonobeCompressor::new`] with this step circuit.
    /// Subsequent calls within the same thread overwrite the previous value.
    pub fn set_family(family: LatticeFoldTreeCircuitFamily) {
        HET_CIRCUIT_FAMILY.with(|cell| {
            *cell.borrow_mut() = Some(family);
        });
    }

    fn family_impl() -> LatticeFoldTreeCircuitFamily {
        HET_CIRCUIT_FAMILY.with(|cell| {
            cell.borrow()
                .clone()
                .unwrap_or_else(LatticeFoldTreeCircuitFamily::default)
        })
    }
}

#[cfg(not(feature = "nova-backend"))]
impl<F: PrimeField> FCircuit<F> for HeterogeneousStepCircuit<F> {
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
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let family = Self::family_impl();
        let result = family.generate_step_constraints(cs, i, z_i, external_inputs)?;
        debug_assert_eq!(
            result.len(),
            self.state_len(),
            "heterogeneous circuit family produced state of length {} != state_len() {}",
            result.len(),
            self.state_len()
        );
        Ok(result)
    }
}

#[cfg(not(feature = "nova-backend"))]
impl<F: PrimeField> StepCircuit for HeterogeneousStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/micronova/heterogeneous-step-circuit/v1").into()
    }
}
