//! `pvthfhe-keygen` — P4 keygen adapter crate.
//!
//! This crate provides the `KeygenAdapter` trait that bridges the frozen
//! P4 interface (from `pvthfhe-keygen-spec`) to the `HermineAdapter`
//! PVSS implementation.

#![deny(missing_docs)]

pub mod hermine;

/// Error type returned by `KeygenAdapter` methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeygenError {
    message: String,
}

impl KeygenError {
    /// Creates a new `KeygenError` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for KeygenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for KeygenError {}

/// Opaque placeholder for a participant descriptor (real types live in keygen-spec).
#[derive(Debug, Clone, Default)]
pub struct Participant {
    /// Participant index (1-based).
    pub id: u16,
}

/// Opaque placeholder for a keygen session (full type in keygen-spec).
#[derive(Debug, Clone, Default)]
pub struct KeygenSession {
    /// Session identifier string.
    pub session_id: String,
    /// Threshold for the session.
    pub threshold: u16,
    /// Participants registered for this session.
    pub participants: Vec<Participant>,
    /// Raw bytes of the derived session identifier.
    pub session_id_bytes: Vec<u8>,
}

/// Opaque placeholder for a share.
#[derive(Debug, Clone, Default)]
pub struct Share {
    /// Owning session id.
    pub session_id: String,
    /// Session threshold required for reconstruction.
    pub threshold: Option<u16>,
    /// Participant this share belongs to.
    pub participant_id: Option<u16>,
    /// The secret share value (Shamir evaluation).
    pub secret_value: Option<u64>,
    /// SHA-256 commitment to the share value.
    pub commitment: Option<Vec<u8>>,
}

/// Opaque placeholder for a public verification artifact.
#[derive(Debug, Clone, Default)]
pub struct PublicVerificationArtifact {
    /// Owning session id.
    pub session_id: String,
    /// Session threshold bound into the public artifact.
    pub threshold: Option<u16>,
    /// Per-participant commitments (SHA-256 hashes).
    pub commitments: Vec<Vec<u8>>,
    /// Dealer that produced this artifact.
    pub dealer_id: Option<u16>,
}

/// Opaque placeholder for an abort-with-blame proof.
#[derive(Debug, Clone, Default)]
pub struct BlameProof {
    /// Owning session id.
    pub session_id: String,
    /// Human-readable blame reason.
    pub reason: String,
    /// Identifier of the accused party.
    pub accused_id: Option<u16>,
    /// Raw evidence bytes.
    pub evidence: Option<Vec<u8>>,
}

/// Opaque placeholder for the reconstructed BFV public key.
#[derive(Debug, Clone, Default)]
pub struct BFVPublicKey {
    /// Raw bytes of the BFV key (stub: empty).
    pub bytes: Vec<u8>,
}

/// Adapter trait that decouples the aggregator coordinator from the concrete
/// PVSS back-end.  The real implementation is `HermineAdapter`.
pub trait KeygenAdapter: Send + Sync {
    /// Creates a new keygen session for the given participants and threshold.
    fn generate_session(
        &self,
        participants: &[Participant],
        threshold: u16,
    ) -> Result<KeygenSession, KeygenError>;

    /// Generates PVSS shares and a public verification artifact for a dealer.
    fn generate_shares(
        &self,
        session: &KeygenSession,
        dealer_id: u16,
    ) -> Result<(Vec<Share>, PublicVerificationArtifact), KeygenError>;

    /// Verifies a dealer's public verification artifact.
    fn verify_transcript(&self, artifact: &PublicVerificationArtifact)
        -> Result<bool, KeygenError>;

    /// Verifies that the public artifact matches the supplied shares.
    fn public_verify(
        &self,
        artifact: &PublicVerificationArtifact,
        shares: &[Share],
    ) -> Result<bool, KeygenError>;

    /// Produces a blame proof for the first detected dealing inconsistency.
    fn blame_dealing(
        &self,
        artifact: &PublicVerificationArtifact,
        shares: &[Share],
    ) -> Result<Option<BlameProof>, KeygenError>;

    /// Reconstructs the BFV public key from a quorum of shares.
    fn reconstruct_bfv_key(&self, shares: &[Share]) -> Result<BFVPublicKey, KeygenError>;
}
