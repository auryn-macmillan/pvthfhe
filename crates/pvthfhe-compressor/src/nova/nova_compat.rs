//! Nova (arecibo) compatibility layer.
//!
//! When the `nova-backend` feature is enabled, this module re-exports
//! types from `arecibo` with `folding_schemes`-compatible names.
//! When disabled, it provides empty stubs.
//!
//! Full migration to arecibo's bellpepper constraint system is deferred
//! to a future phase. See `design/nova-migration.md`.

#[cfg(feature = "nova-backend")]
mod compat {
    pub use arecibo::provider::Bn256EngineKZG;
    pub use arecibo::provider::GrumpkinEngine;
    pub use arecibo::traits::circuit::StepCircuit;
    pub use arecibo::traits::Engine;
    pub use arecibo::PublicParams;
    pub use arecibo::RecursiveSNARK;
}

#[cfg(feature = "nova-backend")]
pub use compat::*;
