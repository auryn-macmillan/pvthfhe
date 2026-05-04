//! Minimal scaffold for the future MicroNova prover integration.
//!
//! Task M1 only defines the placeholder API surface needed by downstream Phase 3
//! work. No real MicroNova cryptography is implemented here yet.

#![deny(missing_docs)]

pub mod cycle;
pub mod hash_bridge;

use thiserror::Error;

/// Placeholder prover entry point for the future MicroNova backend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MicroNovaProver;

/// Minimal R1CS instance shell for the scaffolded prover API.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct R1csInstance {
    /// Number of constraints in the encoded step circuit.
    pub num_constraints: usize,
    /// Number of variables in the encoded step circuit.
    pub num_variables: usize,
    /// Encoded public inputs bound to the instance.
    pub public_inputs: Vec<u8>,
}

/// Opaque proof container for the future compressed MicroNova proof.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MicroNovaProof {
    /// Serialized proof bytes.
    pub proof_bytes: Vec<u8>,
}

/// Errors returned by the scaffolded MicroNova prover surface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MicroNovaError {
    /// The real MicroNova prover is intentionally deferred to later tasks.
    #[error("MicroNova prover scaffold is not implemented yet")]
    Unimplemented,
}

impl MicroNovaProver {
    /// Attempt to produce a compressed MicroNova proof.
    ///
    /// Task M1 intentionally returns [`MicroNovaError::Unimplemented`] while the
    /// real BN254/Grumpkin IVC backend is still open.
    pub fn prove(_r1cs: &R1csInstance, _witness: &[u8]) -> Result<MicroNovaProof, MicroNovaError> {
        Err(MicroNovaError::Unimplemented)
    }
}
