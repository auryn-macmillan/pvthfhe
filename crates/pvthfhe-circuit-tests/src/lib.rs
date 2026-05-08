//! Circuit-test harness for invoking Noir and Barretenberg tooling.

pub mod bb;
pub mod nargo;
pub mod witness_gen;

use std::path::PathBuf;

/// Artifacts produced by `nargo execute`.
#[derive(Debug, Clone)]
pub struct NargoArtifacts {
    /// Witness generated for the executed package.
    pub witness_path: PathBuf,
    /// Compiled bytecode for the executed package.
    pub bytecode_path: PathBuf,
}

/// Artifacts produced by the canonical Barretenberg flow.
#[derive(Debug, Clone)]
pub struct BbArtifacts {
    /// Verification key written by `bb write_vk`.
    pub vk_path: PathBuf,
    /// Proof written by `bb prove`.
    pub proof_path: PathBuf,
    /// Public inputs consumed by `bb verify`.
    pub public_inputs_path: PathBuf,
}

/// Errors returned by the circuit-test harness.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    /// A shell command exited unsuccessfully.
    #[error("command failed: {0}")]
    CommandFailed(String),
    /// An expected artifact was not created.
    #[error("missing artifact: {0}")]
    MissingArtifact(String),
}

/// Result type used throughout the harness crate.
pub type Result<T> = std::result::Result<T, HarnessError>;
