//! Error types for the FHE backend abstraction layer.
//!
//! All backend errors are mapped to [`FheError`] variants so that no
//! backend-internal types leak through the public API boundary.

use thiserror::Error;

/// Unified error type for all [`crate::FheBackend`] operations.
///
/// Backend-specific error details are captured as strings so that no
/// backend-internal types appear in the public API.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FheError {
    /// The provided parameter TOML is malformed or contains unsupported values.
    #[error("invalid parameters: {reason}")]
    InvalidParams {
        /// Human-readable description of the parameter problem.
        reason: String,
    },

    /// Fewer valid decryption shares were provided than the required threshold.
    #[error("insufficient shares: got {received}, need {threshold}")]
    InsufficientShares {
        /// Number of shares actually provided.
        received: usize,
        /// Minimum number of shares required.
        threshold: usize,
    },

    /// A keygen share is structurally invalid (wrong length, bad encoding, etc.).
    #[error("malformed keygen share from party {party_id}")]
    MalformedKeygenShare {
        /// The party whose share is malformed.
        party_id: u32,
    },

    /// A decryption share is structurally invalid.
    #[error("malformed decrypt share from party {party_id}")]
    MalformedDecryptShare {
        /// The party whose share is malformed.
        party_id: u32,
    },

    /// The ciphertext is structurally invalid.
    #[error("malformed ciphertext")]
    MalformedCiphertext,

    /// The public key is structurally invalid.
    #[error("malformed public key")]
    MalformedPublicKey,

    /// An RNG operation failed.
    #[error("RNG failure")]
    RngFailure,

    /// A backend-internal operation failed.
    #[error("backend error: {reason}")]
    Backend {
        /// Human-readable description of the backend error.
        reason: String,
    },
}
