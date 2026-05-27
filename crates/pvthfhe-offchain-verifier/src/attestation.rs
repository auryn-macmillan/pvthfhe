//! Attestation bundle output for the off-chain verifier.

use serde::{Deserialize, Serialize};

/// Simplified EIP-712-style attestation payload emitted by local verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundle {
    /// Deterministic binding for the Nova final state.
    pub nova_final_state_commitment: String,
    /// Deterministic binding for the Cyclo aggregate commitment.
    pub cyclo_aggregate_commitment: String,
    /// Session identifier represented as a hex string.
    pub session_id: String,
    /// Placeholder local signer address.
    pub signer: String,
    /// Placeholder signature bytes.
    pub signature: String,
}
