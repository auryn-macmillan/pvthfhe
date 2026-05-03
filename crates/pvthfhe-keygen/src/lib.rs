//! `pvthfhe-keygen` — P4 keygen adapter crate.
//!
//! This crate provides the `KeygenAdapter` trait that bridges the frozen
//! P4 interface (from `pvthfhe-keygen-spec`) to the real Hermine-adapted
//! PVSS implementation (deferred to T4).
//!
//! # Feature flags
//!
//! * `migration-stub` — enables the `SurrogateAdapter` stub implementation.
//!   CI always builds with this flag until the surrogate coordinator in
//!   `pvthfhe-aggregator` is replaced by the real `HermineAdapter` (Step M4 of
//!   the migration plan).

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
/// PVSS back-end.  Implementors are `SurrogateAdapter` (feature `migration-stub`)
/// and the future `HermineAdapter` (T4).
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

/// Stub adapter enabled by the `migration-stub` feature.
///
/// All methods return stub/placeholder values and perform no cryptographic
/// operations.  The surrogate coordinator in `pvthfhe-aggregator` remains the
/// live code path until Step M4 of the migration plan.
#[cfg(feature = "migration-stub")]
pub mod stub {
    use super::{
        BFVPublicKey, BlameProof, KeygenAdapter, KeygenError, KeygenSession, Participant,
        PublicVerificationArtifact, Share,
    };

    /// Stub implementation of `KeygenAdapter`.  Does nothing real.
    #[derive(Debug, Default)]
    pub struct SurrogateAdapter;

    impl KeygenAdapter for SurrogateAdapter {
        fn generate_session(
            &self,
            _participants: &[Participant],
            threshold: u16,
        ) -> Result<KeygenSession, KeygenError> {
            Ok(KeygenSession {
                session_id: "stub-session".to_owned(),
                threshold,
                ..Default::default()
            })
        }

        fn generate_shares(
            &self,
            session: &KeygenSession,
            _dealer_id: u16,
        ) -> Result<(Vec<Share>, PublicVerificationArtifact), KeygenError> {
            let share = Share {
                session_id: session.session_id.clone(),
                threshold: Some(session.threshold),
                ..Default::default()
            };
            let artifact = PublicVerificationArtifact {
                session_id: session.session_id.clone(),
                threshold: Some(session.threshold),
                ..Default::default()
            };
            Ok((vec![share], artifact))
        }

        fn verify_transcript(
            &self,
            _artifact: &PublicVerificationArtifact,
        ) -> Result<bool, KeygenError> {
            Ok(true)
        }

        fn public_verify(
            &self,
            _artifact: &PublicVerificationArtifact,
            _shares: &[Share],
        ) -> Result<bool, KeygenError> {
            Ok(true)
        }

        fn blame_dealing(
            &self,
            _artifact: &PublicVerificationArtifact,
            _shares: &[Share],
        ) -> Result<Option<BlameProof>, KeygenError> {
            Ok(None)
        }

        fn reconstruct_bfv_key(&self, _shares: &[Share]) -> Result<BFVPublicKey, KeygenError> {
            Ok(BFVPublicKey { bytes: vec![] })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn stub_round_trip_compiles_and_runs() {
            let adapter = SurrogateAdapter;
            let participants = vec![Participant { id: 1 }, Participant { id: 2 }];
            let session = adapter.generate_session(&participants, 2).expect("session");
            let (_shares, artifact) = adapter.generate_shares(&session, 1).expect("shares");
            let valid = adapter.verify_transcript(&artifact).expect("verify");
            assert!(valid);
        }
    }
}
