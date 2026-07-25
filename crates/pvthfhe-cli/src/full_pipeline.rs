//! Shared full-pipeline driver for bench and demo entrypoints.
//!
//! The implementation is split by pipeline stage under [`crate::pipeline`]
//! (keygen/DKG, NIZK proving, encryption, folding, decryption/C7, IVC
//! compression, on-chain Noir verification, plus the orchestrating driver).
//! This module re-exports the complete public surface at its historical
//! `full_pipeline::*` paths.

pub use crate::pipeline::*;
