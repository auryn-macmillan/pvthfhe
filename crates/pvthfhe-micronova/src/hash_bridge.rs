//! Poseidon↔Keccak bridge helpers for the MicroNova transcript boundary.
//!
//! In the full Construction 1 setting, the recursive verifier remains Poseidon-native
//! inside the circuit while the external verifier checks a Keccak digest on the same
//! public transcript material. This prototype task exposes only the EVM-facing digest
//! step so downstream code has a stable bridge surface.

use sha3::{Digest, Keccak256};

/// Compute the EVM-facing Keccak-256 digest for bridged transcript bytes.
#[must_use]
pub fn poseidon_keccak_bridge(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}
