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
#[derive(Debug, Clone)]
pub struct Participant {
    /// Participant index (1-based).
    pub id: u16,
}

/// Opaque placeholder for a keygen session (full type in keygen-spec).
#[derive(Debug, Clone)]
pub struct KeygenSession {
    /// Session identifier string.
    pub session_id: String,
    /// Threshold for the session.
    pub threshold: u16,
}

/// Opaque placeholder for a share.
#[derive(Debug, Clone)]
pub struct Share {
    /// Owning session id.
    pub session_id: String,
}

/// Opaque placeholder for a public verification artifact.
#[derive(Debug, Clone)]
pub struct PublicVerificationArtifact {
    /// Owning session id.
    pub session_id: String,
}

/// Opaque placeholder for the reconstructed BFV public key.
#[derive(Debug, Clone)]
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
        BFVPublicKey, KeygenAdapter, KeygenError, KeygenSession, Participant,
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
            })
        }

        fn generate_shares(
            &self,
            session: &KeygenSession,
            _dealer_id: u16,
        ) -> Result<(Vec<Share>, PublicVerificationArtifact), KeygenError> {
            let share = Share {
                session_id: session.session_id.clone(),
            };
            let artifact = PublicVerificationArtifact {
                session_id: session.session_id.clone(),
            };
            Ok((vec![share], artifact))
        }

        fn verify_transcript(
            &self,
            _artifact: &PublicVerificationArtifact,
        ) -> Result<bool, KeygenError> {
            Ok(true)
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
