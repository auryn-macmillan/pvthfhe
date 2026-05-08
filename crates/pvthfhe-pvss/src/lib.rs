//! Frozen trait surface for the P1 PVSS backend boundary.

/// BFV-backed PVSS encryption adapter.
pub mod encrypt;
/// Share-encryption NIZK helpers and proof types.
pub mod nizk_share;
/// Share-decryption NIZK helpers and proof types.
pub mod nizk_decrypt;

pub use encrypt::LatticePvssBfvAdapter;

/// Frozen PVSS context shared across backend implementations.
#[derive(Clone, PartialEq, Eq)]
pub struct PvssContext {
    /// Total number of participants.
    pub n: usize,
    /// Threshold required for recovery.
    pub t: usize,
    /// Session binding bytes. Treat as sensitive session metadata.
    pub session_id: Vec<u8>,
}

/// Encrypted-share bundle emitted by a PVSS dealer.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedShares {
    /// One ciphertext per recipient public key.
    pub ciphertexts: Vec<Vec<u8>>,
    /// Backend-defined proofs for the encrypted shares.
    pub proofs: Vec<Vec<u8>>,
    /// Stable backend identifier recorded in the artifact.
    ///
    /// Implementations should reject share bundles whose embedded backend id
    /// does not match [`PvssAdapter::backend_id`].
    pub backend_id: String,
}

/// A decrypted share plus any backend-defined proof material.
#[derive(Clone, PartialEq, Eq)]
pub struct DecryptedShare {
    /// Zero-based share index.
    pub index: usize,
    /// Serialized share bytes. Treat as sensitive material.
    pub share_bytes: Vec<u8>,
    /// Backend-defined proof of correct decryption.
    pub proof: Vec<u8>,
}

/// Errors returned by PVSS backends.
#[derive(Clone, PartialEq, Eq)]
pub enum PvssError {
    /// Share material failed validation.
    InvalidShare,
    /// Threshold recovery failed.
    RecoveryFailed,
    /// Backend-specific failure surfaced as a string payload.
    BackendError(String),
}

impl core::fmt::Debug for PvssContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PvssContext")
            .field("n", &self.n)
            .field("t", &self.t)
            .field("session_id_len", &self.session_id.len())
            .finish()
    }
}

impl core::fmt::Debug for EncryptedShares {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedShares")
            .field("ciphertext_count", &self.ciphertexts.len())
            .field("proof_count", &self.proofs.len())
            .field("backend_id", &self.backend_id)
            .finish()
    }
}

impl core::fmt::Debug for DecryptedShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptedShare")
            .field("index", &self.index)
            .field("share_len", &self.share_bytes.len())
            .field("proof_len", &self.proof.len())
            .finish()
    }
}

impl core::fmt::Debug for PvssError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidShare => f.write_str("InvalidShare"),
            Self::RecoveryFailed => f.write_str("RecoveryFailed"),
            Self::BackendError(_) => f.write_str("BackendError(<redacted>)"),
        }
    }
}

impl core::fmt::Display for PvssError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidShare => f.write_str("invalid PVSS share"),
            Self::RecoveryFailed => f.write_str("PVSS recovery failed"),
            Self::BackendError(s) => write!(f, "PVSS backend error: {s}"),
        }
    }
}

impl std::error::Error for PvssError {}

/// Frozen backend boundary for private-verifiable secret sharing.
pub trait PvssAdapter {
    /// Deal a secret into one encrypted share per recipient public key.
    fn deal(
        &self,
        secret: &[u8],
        recipient_pks: &[Vec<u8>],
        ctx: &PvssContext,
    ) -> Result<EncryptedShares, PvssError>;

    /// Verify that a set of encrypted shares is well formed.
    ///
    /// Implementations should reject bundles whose embedded backend id does
    /// not match [`PvssAdapter::backend_id`].
    fn verify_shares(&self, shares: &EncryptedShares, ctx: &PvssContext) -> Result<(), PvssError>;

    /// Recover the secret from a threshold subset of decrypted shares.
    ///
    /// Implementations should reject shares that were produced by a different
    /// backend than [`PvssAdapter::backend_id`].
    fn recover(
        &self,
        decrypted_shares: &[DecryptedShare],
        ctx: &PvssContext,
    ) -> Result<Vec<u8>, PvssError>;

    /// Returns the stable backend identifier.
    fn backend_id(&self) -> &'static str;
}

/// Minimal no-op adapter for trait-surface smoke tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoopPvssAdapter;

impl PvssAdapter for NoopPvssAdapter {
    fn deal(
        &self,
        _secret: &[u8],
        _recipient_pks: &[Vec<u8>],
        _ctx: &PvssContext,
    ) -> Result<EncryptedShares, PvssError> {
        Err(PvssError::BackendError("noop-pvss".to_owned()))
    }

    fn verify_shares(&self, _shares: &EncryptedShares, _ctx: &PvssContext) -> Result<(), PvssError> {
        Err(PvssError::BackendError("noop-pvss".to_owned()))
    }

    fn recover(
        &self,
        _decrypted_shares: &[DecryptedShare],
        _ctx: &PvssContext,
    ) -> Result<Vec<u8>, PvssError> {
        Err(PvssError::BackendError("noop-pvss".to_owned()))
    }

    fn backend_id(&self) -> &'static str {
        "noop-pvss"
    }
}
