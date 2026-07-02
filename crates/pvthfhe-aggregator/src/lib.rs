//! pvthfhe-aggregator — aggregation protocol for PVTHFHE threshold decryption.
// Keygen encrypted shares are real BFV ciphertexts (no [0x11,0x22] stubs).
// NIZK proofs use Cyclo lattice-native sigma protocol.
// Accumulator transcripts use the versioned Cyclo codec.
#![allow(
    missing_docs,
    dead_code,
    clippy::too_many_arguments,
    clippy::needless_borrows_for_generic_args,
    clippy::needless_range_loop,
    clippy::collapsible_if,
    clippy::manual_contains,
    clippy::manual_is_multiple_of,
    clippy::cloned_ref_to_slice_refs,
    unused_variables
)]

#[cfg(all(feature = "production-profile", feature = "mock"))]
compile_error!("pvthfhe-aggregator production-profile forbids the mock feature");

use pvthfhe_cyclo::CYCLO_BACKEND_ID;

pub mod decrypt;
pub mod folding;
pub mod keygen;
pub mod leader_election;

pub struct Aggregator {
    pub folding_backend_id: &'static str,
}

impl Default for Aggregator {
    fn default() -> Self {
        Self {
            folding_backend_id: CYCLO_BACKEND_ID,
        }
    }
}
