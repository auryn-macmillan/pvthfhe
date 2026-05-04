//! Minimal scaffold for the future MicroNova prover integration.
//!
//! Task M1 only defines the placeholder API surface needed by downstream Phase 3
//! work. No real MicroNova cryptography is implemented here yet.

#![deny(missing_docs)]

pub mod cycle;
pub mod hash_bridge;
pub mod r1cs_encode;

use pvthfhe_cyclo::CycloAccumulator;
use sha2::{Digest, Sha256};
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
    /// Whether the encoded instance is structurally satisfiable.
    pub satisfiable: bool,
    /// Encoded public inputs bound to the instance.
    pub public_inputs: Vec<u8>,
}

/// Opaque proof container for the future compressed MicroNova proof.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MicroNovaProof {
    /// Serialized proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Constraint count bound into the prototype proof transcript.
    pub r1cs_num_constraints: usize,
}

/// Errors returned by the scaffolded MicroNova prover surface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MicroNovaError {
    /// The real MicroNova prover is intentionally deferred to later tasks.
    #[error("MicroNova prover scaffold is not implemented yet")]
    Unimplemented,
    /// The proof bytes do not match the supplied accumulator and R1CS instance.
    #[error("MicroNova proof is invalid for the supplied accumulator and R1CS instance")]
    InvalidProof,
    /// A platform-dependent integer could not be encoded into the proof transcript.
    #[error("integer overflow while serializing the prototype proof transcript")]
    IntegerOverflow,
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), MicroNovaError> {
    let converted = u64::try_from(value).map_err(|_| MicroNovaError::IntegerOverflow)?;
    push_u64(bytes, converted);
    Ok(())
}

fn push_len_prefixed_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), MicroNovaError> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn push_len_prefixed_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), MicroNovaError> {
    push_len_prefixed_bytes(bytes, value.as_bytes())
}

fn serialize_r1cs(r1cs: &R1csInstance) -> Result<Vec<u8>, MicroNovaError> {
    let mut bytes = Vec::new();
    push_usize(&mut bytes, r1cs.num_constraints)?;
    push_usize(&mut bytes, r1cs.num_variables)?;
    bytes.push(u8::from(r1cs.satisfiable));
    push_len_prefixed_bytes(&mut bytes, &r1cs.public_inputs)?;
    Ok(bytes)
}

fn serialize_accumulator(accumulator: &CycloAccumulator) -> Result<Vec<u8>, MicroNovaError> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, accumulator.fold_depth);
    push_len_prefixed_bytes(&mut bytes, &accumulator.acc_commitment_bytes)?;
    push_len_prefixed_bytes(&mut bytes, &accumulator.acc_public_io_bytes)?;
    push_u64(&mut bytes, accumulator.norm_bound_current);
    push_len_prefixed_string(&mut bytes, &accumulator.session_id)?;
    bytes.extend_from_slice(&accumulator.params_digest);
    Ok(bytes)
}

fn proof_digest(
    r1cs: &R1csInstance,
    accumulator: &CycloAccumulator,
) -> Result<Vec<u8>, MicroNovaError> {
    let mut hasher = Sha256::new();
    hasher.update(serialize_accumulator(accumulator)?);
    hasher.update(serialize_r1cs(r1cs)?);
    Ok(hasher.finalize().to_vec())
}

impl MicroNovaProver {
    /// Attempt to produce a compressed MicroNova proof.
    pub fn prove(
        r1cs: &R1csInstance,
        accumulator: &CycloAccumulator,
    ) -> Result<MicroNovaProof, MicroNovaError> {
        Ok(MicroNovaProof {
            proof_bytes: proof_digest(r1cs, accumulator)?,
            r1cs_num_constraints: r1cs.num_constraints,
        })
    }

    /// Verify a compressed MicroNova proof against the supplied accumulator and
    /// R1CS instance.
    pub fn verify(
        proof: &MicroNovaProof,
        accumulator: &CycloAccumulator,
        r1cs: &R1csInstance,
    ) -> Result<(), MicroNovaError> {
        if proof.r1cs_num_constraints != r1cs.num_constraints {
            return Err(MicroNovaError::InvalidProof);
        }

        if proof.proof_bytes != proof_digest(r1cs, accumulator)? {
            return Err(MicroNovaError::InvalidProof);
        }

        Ok(())
    }
}
