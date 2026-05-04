//! Prototype R1CS encoding for the Cyclo accumulator verifier.

use crate::R1csInstance;
use pvthfhe_cyclo::{fold::verify_fold, CcsPShareInstance, CycloAccumulator, PVTHFHE_CYCLO_PARAMS};

/// Maximum allowed constraint budget for Task M5.
pub const MAX_ALLOWED_CONSTRAINTS: usize = 1 << 21;

/// Witness material for the encoded Cyclo verifier.
pub struct CycloVerifierWitness {
    /// Ordered Cyclo instances folded into the accumulator.
    pub instances: Vec<CcsPShareInstance>,
    /// Session identifier used while folding.
    pub session_id: String,
}

const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_BLOCK_CONSTRAINTS: usize = 384;
const BYTE_COMPARISON_CONSTRAINTS: usize = 1;
const SCALAR_COMPARISON_CONSTRAINTS: usize = 4;

/// Encodes the Cyclo verifier into a placeholder R1CS shell.
#[must_use]
pub fn encode_cyclo_verifier(accumulator: &CycloAccumulator) -> R1csInstance {
    let fold_depth_variables = match usize::try_from(accumulator.fold_depth) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    };
    let num_constraints = verifier_constraint_count(accumulator);
    let public_inputs = accumulator_public_inputs(accumulator);

    R1csInstance {
        num_constraints,
        num_variables: num_constraints + public_inputs.len() + fold_depth_variables + 1,
        satisfiable: structurally_satisfiable(accumulator),
        public_inputs,
    }
}

/// Builds a witness object for the Cyclo verifier relation.
#[must_use]
pub fn cyclo_verifier_witness(
    instances: Vec<CcsPShareInstance>,
    session_id: impl Into<String>,
) -> CycloVerifierWitness {
    CycloVerifierWitness {
        instances,
        session_id: session_id.into(),
    }
}

/// Counts the prototype R1CS constraints needed for the Cyclo verifier.
#[must_use]
pub fn verifier_constraint_count(accumulator: &CycloAccumulator) -> usize {
    let fold_depth = match usize::try_from(accumulator.fold_depth) {
        Ok(value) => value,
        Err(_) => return usize::MAX,
    };

    let init_hash_constraints = sha256_constraints(4 + 32) * 2;
    let per_fold_hash_constraints = sha256_constraints(32)
        + sha256_constraints(32)
        + sha256_constraints(64)
        + sha256_constraints(32)
        + sha256_constraints(32)
        + sha256_constraints(65)
        + sha256_constraints(65);
    let per_fold_comparisons = witness_norm_comparisons(32) + 2 * SCALAR_COMPARISON_CONSTRAINTS;
    let final_checks = 3 * SCALAR_COMPARISON_CONSTRAINTS + 64 * BYTE_COMPARISON_CONSTRAINTS;

    init_hash_constraints
        + fold_depth * (per_fold_hash_constraints + per_fold_comparisons)
        + final_checks
}

fn structurally_satisfiable(accumulator: &CycloAccumulator) -> bool {
    accumulator.fold_depth <= PVTHFHE_CYCLO_PARAMS.sequential_t
        && accumulator.norm_bound_current <= PVTHFHE_CYCLO_PARAMS.beta_at_t
        && accumulator.acc_commitment_bytes.len() == 32
        && accumulator.acc_public_io_bytes.len() == 32
        && verifier_constraint_count(accumulator) <= MAX_ALLOWED_CONSTRAINTS
}

fn sha256_constraints(message_len: usize) -> usize {
    sha256_block_count(message_len) * SHA256_BLOCK_CONSTRAINTS
}

fn sha256_block_count(message_len: usize) -> usize {
    (message_len + 9).div_ceil(SHA256_BLOCK_BYTES)
}

fn witness_norm_comparisons(witness_len: usize) -> usize {
    witness_len.saturating_sub(1) * BYTE_COMPARISON_CONSTRAINTS
}

/// Checks whether the encoded Cyclo verifier relation is satisfied.
#[must_use]
pub fn check_cyclo_verifier_satisfied(
    accumulator: &CycloAccumulator,
    r1cs: &R1csInstance,
    witness: &CycloVerifierWitness,
) -> bool {
    let expected_depth = match usize::try_from(accumulator.fold_depth) {
        Ok(value) => value,
        Err(_) => return false,
    };

    if witness.instances.len() != expected_depth {
        return false;
    }

    if witness.session_id != accumulator.session_id {
        return false;
    }

    if r1cs.public_inputs != accumulator_public_inputs(accumulator) {
        return false;
    }

    if r1cs.num_constraints != verifier_constraint_count(accumulator) {
        return false;
    }

    verify_fold(accumulator, &witness.instances).is_ok()
}

fn accumulator_public_inputs(accumulator: &CycloAccumulator) -> Vec<u8> {
    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&accumulator.fold_depth.to_le_bytes());
    public_inputs.extend_from_slice(&accumulator.norm_bound_current.to_le_bytes());
    public_inputs.extend_from_slice(&accumulator.acc_commitment_bytes);
    public_inputs.extend_from_slice(&accumulator.acc_public_io_bytes);
    public_inputs.extend_from_slice(accumulator.session_id.as_bytes());
    public_inputs.extend_from_slice(&accumulator.params_digest);
    public_inputs
}
