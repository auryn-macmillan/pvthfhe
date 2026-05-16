//! pvthfhe-aggregator — aggregation protocol for PVTHFHE threshold decryption.
// Allowed: simulator stubs (keygen NIZK, encrypted_shares) and debug-only helpers.
// Remove when real DKG with distributed peers replaces the simulator.
#![allow(missing_docs, dead_code, clippy::too_many_arguments)]

use pvthfhe_cyclo::CYCLO_BACKEND_ID;

pub mod decrypt;
pub mod folding;
pub mod keygen;

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
