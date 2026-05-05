//! Hash-family bridge for the MicroNova transcript boundary.
//!
//! ## Domain boundary
//!
//! - **In-circuit (Noir / ZK):** Poseidon (BN254) is the canonical hash primitive. It is
//!   native to the constraint system and keeps proof generation efficient.
//! - **On-chain / EVM:** Keccak-256 is used for all external digest commitments because it
//!   matches the EVM `keccak256` opcode used by the Solidity verifier contracts.
//!
//! This module exposes **only the EVM-facing Keccak-256 step** (`poseidon_keccak_bridge`).
//! The in-circuit Poseidon evaluation lives entirely inside the Noir circuits; the stub
//! `poseidon_hash_bridge` below documents the expected interface for callers that need to
//! reproduce or verify an in-circuit Poseidon digest on the Rust side (e.g. test harnesses).

use sha3::{Digest, Keccak256};

/// Compute the EVM-facing Keccak-256 digest for bridged transcript bytes.
///
/// This is the on-chain side of the hash boundary. The input bytes are the serialised
/// public transcript material produced by the Noir circuit execution.
#[must_use]
pub fn poseidon_keccak_bridge(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Domain-separated stub for the in-circuit Poseidon hash (BN254, up to 5 field elements).
///
/// In production this digest is computed *inside* the Noir circuit using
/// `std::hash::poseidon::bn254::hash_N`. This stub exists so that Rust test harnesses can
/// document the expected interface without duplicating the circuit logic. A full Rust
/// implementation backed by `poseidon-bn254` (or equivalent) will replace this stub when
/// needed for proof pre-computation outside the circuit.
///
/// # Domain separation
/// The leading `0x50_4f53` tag encodes ASCII "POS" to distinguish this digest from the
/// Keccak-256 outputs produced by `poseidon_keccak_bridge`.
#[must_use]
pub fn poseidon_hash_bridge(_fields: &[u64]) -> [u8; 32] {
    // STUB: in-circuit Poseidon is authoritative; this placeholder is for interface
    // documentation only. Replace with a real BN254-Poseidon implementation when
    // out-of-circuit pre-computation is required.
    unimplemented!(
        "poseidon_hash_bridge: out-of-circuit Poseidon not yet implemented — use the Noir circuit"
    )
}
