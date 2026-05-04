//! Prototype R1CS encoding for the Cyclo accumulator verifier.

use crate::R1csInstance;
use pvthfhe_cyclo::{CcsPShareInstance, CycloAccumulator};

/// Maximum allowed constraint budget for Task M5.
pub const MAX_ALLOWED_CONSTRAINTS: usize = 1 << 21;

/// Witness material for the encoded Cyclo verifier.
pub struct CycloVerifierWitness {
    /// Ordered Cyclo instances folded into the accumulator.
    pub instances: Vec<CcsPShareInstance>,
    /// Session identifier used while folding.
    pub session_id: String,
}

/// Encodes the Cyclo verifier into a placeholder R1CS shell.
#[must_use]
pub fn encode_cyclo_verifier(accumulator: &CycloAccumulator) -> R1csInstance {
    let fold_depth_variables = match usize::try_from(accumulator.fold_depth) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    };

    R1csInstance {
        num_constraints: usize::MAX,
        num_variables: fold_depth_variables + accumulator.acc_commitment_bytes.len(),
        satisfiable: false,
        public_inputs: accumulator_public_inputs(accumulator),
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

/// Checks whether the encoded Cyclo verifier relation is satisfied.
#[must_use]
pub fn check_cyclo_verifier_satisfied(
    _accumulator: &CycloAccumulator,
    _r1cs: &R1csInstance,
    _witness: &CycloVerifierWitness,
) -> bool {
    false
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
