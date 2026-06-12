//! Frozen trait surface for the P1 PVSS backend boundary.

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(all(feature = "production-profile", feature = "production-stub-allowed"))]
compile_error!("pvthfhe-pvss production-profile forbids production-stub-allowed");

/// Provable AVID: Asynchronous Verifiable Information Dispersal (ePrint 2026/1159 §4.3).
pub mod avid;
pub mod dkg_aggregation;
/// BFV-backed PVSS encryption adapter.
pub mod encrypt;
/// Key Escrow protocol for distributed key authorization (ePrint 2026/1159 §6).
pub mod key_escrow;
/// Share-decryption NIZK helpers and proof types.
pub mod nizk_decrypt;
/// Key-generation NIZK for BFV keypair correctness (C0).
pub mod nizk_keygen;
/// Share-encryption NIZK helpers and proof types.
pub mod nizk_share;
pub mod parity;
/// BN254 scalar Shamir secret sharing.
pub mod shamir;
pub mod share_computation;
/// Smudge-slot freshness enforcement (F.2).
pub mod slot_registry;

use pvthfhe_types::{ProtocolBytes, ShareSecret};

pub use encrypt::{CommittedSmudgeUse, LatticePvssBfvAdapter};
pub use nizk_decrypt::CommittedSmudgeSlot;

/// Frozen PVSS context shared across backend implementations.
#[derive(Clone, PartialEq, Eq)]
pub struct PvssContext {
    /// Total number of participants.
    pub n: usize,
    /// Threshold required for recovery.
    pub t: usize,
    /// Session binding bytes. Treat as sensitive session metadata.
    pub session_id: Vec<u8>,
    /// On-chain epoch that binds the CRS.
    pub epoch: u64,
    /// DKG anchoring root digest for session binding.
    pub dkg_root: Vec<u8>,
    /// Cryptographically-derived dealer identity index bound to the session.
    pub dealer_index: usize,
}

/// Derive a deterministic dealer index from session identity bytes.
///
/// Uses SHA-256 over the session_id with a domain separator to produce a
/// non-zero dealer index that is deterministic for the same session.
pub fn derive_dealer_index(session_id: &[u8]) -> usize {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-dealer-index-v1");
    hasher.update(session_id);
    let digest: [u8; 32] = hasher.finalize().into();
    let raw = u64::from_be_bytes(digest[..8].try_into().unwrap_or([0u8; 8]));
    // Map to [1, u16::MAX] to avoid zero and stay within reasonable range.
    (raw % u64::from(u16::MAX - 1) + 1) as usize
}

/// Encrypted-share bundle emitted by a PVSS dealer.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedShares {
    /// One ciphertext per recipient public key.
    pub ciphertexts: Vec<Vec<u8>>,
    /// Plaintext share bytes per recipient (same order as `ciphertexts`).
    ///
    /// Stored by the dealer to support decrypted-share proof construction
    /// without requiring the NIZK envelope to leak witness material.
    pub share_bytes: Vec<Vec<u8>>,
    /// Backend-defined proofs for the encrypted shares.
    pub proofs: Vec<Vec<u8>>,
    pub parity_proof: Option<Vec<u8>>,
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
    pub share_bytes: ShareSecret,
    /// Backend-defined proof of correct decryption.
    pub proof: ProtocolBytes,
}

/// Errors returned by PVSS backends.
#[derive(Clone, PartialEq, Eq)]
pub enum PvssError {
    /// Share material failed validation.
    InvalidShare { party_id: Option<u16> },
    /// Threshold recovery failed.
    RecoveryFailed { party_id: Option<u16> },
    /// Backend-specific failure surfaced as a string payload.
    BackendError(String),
    /// Domain separator in proof envelope does not match expected value.
    InvalidDomainSeparator { party_id: Option<u16> },
    /// Statement in opened proof does not match verify statement.
    StatementMismatch { party_id: Option<u16> },
    /// Fiat-Shamir challenge verification failed.
    ChallengeVerificationFailed { party_id: Option<u16> },
    /// Reconstructed ciphertext_v does not match statement.
    CiphertextVMismatch { party_id: Option<u16> },
    /// Commitment structure is invalid (empty, too large, or cannot be recovered).
    InvalidCommitmentStructure { party_id: Option<u16> },
    /// Lattice binding tag verification failed.
    LatticeBindingVerificationFailed { party_id: Option<u16> },
    /// D2 hash binding verification failed (Ajtaï share-commitment check).
    D2HashBindingFailed { party_id: Option<u16> },
    /// BFV encryption relation proof verification failed.
    BfvEncryptionProofFailed { party_id: Option<u16> },
    /// Committed smudging slot was reused in the same decryption session.
    SmudgeSlotReused {
        /// Party that attempted to reuse a slot.
        party_id: u16,
        /// Slot identifier that was already consumed.
        slot_id: u16,
    },
    /// Cross-share Reed-Solomon parity / batched share computation check failed.
    ShareVerification(String),
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
            .field("share_len", &self.share_bytes.expose().len())
            .field("proof_len", &self.proof.len())
            .finish()
    }
}

impl core::fmt::Debug for PvssError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidShare { party_id } => write_debug_with_party(f, "InvalidShare", *party_id),
            Self::RecoveryFailed { party_id } => {
                write_debug_with_party(f, "RecoveryFailed", *party_id)
            }
            Self::BackendError(_) => f.write_str("BackendError(<redacted>)"),
            Self::InvalidDomainSeparator { party_id } => {
                write_debug_with_party(f, "InvalidDomainSeparator", *party_id)
            }
            Self::StatementMismatch { party_id } => {
                write_debug_with_party(f, "StatementMismatch", *party_id)
            }
            Self::ChallengeVerificationFailed { party_id } => {
                write_debug_with_party(f, "ChallengeVerificationFailed", *party_id)
            }
            Self::CiphertextVMismatch { party_id } => {
                write_debug_with_party(f, "CiphertextVMismatch", *party_id)
            }
            Self::InvalidCommitmentStructure { party_id } => {
                write_debug_with_party(f, "InvalidCommitmentStructure", *party_id)
            }
            Self::LatticeBindingVerificationFailed { party_id } => {
                write_debug_with_party(f, "LatticeBindingVerificationFailed", *party_id)
            }
            Self::D2HashBindingFailed { party_id } => {
                write_debug_with_party(f, "D2HashBindingFailed", *party_id)
            }
            Self::BfvEncryptionProofFailed { party_id } => {
                write_debug_with_party(f, "BfvEncryptionProofFailed", *party_id)
            }
            Self::SmudgeSlotReused { .. } => f.write_str("SmudgeSlotReused(<redacted>)"),
            Self::ShareVerification(s) => write!(f, "ShareVerification({s})"),
        }
    }
}

impl core::fmt::Display for PvssError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidShare { party_id } => write_with_party(f, "invalid PVSS share", *party_id),
            Self::RecoveryFailed { party_id } => {
                write_with_party(f, "PVSS recovery failed", *party_id)
            }
            Self::BackendError(s) => write!(f, "PVSS backend error: {s}"),
            Self::InvalidDomainSeparator { party_id } => {
                write_with_party(f, "PVSS proof domain separator mismatch", *party_id)
            }
            Self::StatementMismatch { party_id } => {
                write_with_party(f, "PVSS proof statement mismatch", *party_id)
            }
            Self::ChallengeVerificationFailed { party_id } => write_with_party(
                f,
                "PVSS Fiat-Shamir challenge verification failed",
                *party_id,
            ),
            Self::CiphertextVMismatch { party_id } => {
                write_with_party(f, "PVSS ciphertext_v reconstruction mismatch", *party_id)
            }
            Self::InvalidCommitmentStructure { party_id } => {
                write_with_party(f, "PVSS commitment structure invalid", *party_id)
            }
            Self::LatticeBindingVerificationFailed { party_id } => {
                write_with_party(f, "PVSS lattice binding verification failed", *party_id)
            }
            Self::D2HashBindingFailed { party_id } => {
                write_with_party(f, "PVSS D2 hash binding verification failed", *party_id)
            }
            Self::BfvEncryptionProofFailed { party_id } => write_with_party(
                f,
                "PVSS BFV encryption proof verification failed",
                *party_id,
            ),
            Self::SmudgeSlotReused { party_id, slot_id } => {
                write!(
                    f,
                    "PVSS smudge slot reused: party_id={party_id} slot_id={slot_id}"
                )
            }
            Self::ShareVerification(s) => write!(f, "PVSS share verification failed: {s}"),
        }
    }
}

/// Write a Display message with optional party attribution.
fn write_with_party(
    f: &mut core::fmt::Formatter<'_>,
    msg: &str,
    party_id: Option<u16>,
) -> core::fmt::Result {
    match party_id {
        Some(id) => write!(f, "{msg} (party {id})"),
        None => f.write_str(msg),
    }
}

/// Write a Debug variant name with optional party attribution.
fn write_debug_with_party(
    f: &mut core::fmt::Formatter<'_>,
    variant: &str,
    party_id: Option<u16>,
) -> core::fmt::Result {
    match party_id {
        Some(id) => write!(f, "{variant}(party={id})"),
        None => f.write_str(variant),
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
#[cfg(feature = "production-stub-allowed")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoopPvssAdapter;

#[cfg(feature = "production-stub-allowed")]
impl PvssAdapter for NoopPvssAdapter {
    fn deal(
        &self,
        _secret: &[u8],
        _recipient_pks: &[Vec<u8>],
        _ctx: &PvssContext,
    ) -> Result<EncryptedShares, PvssError> {
        Err(PvssError::BackendError("noop-pvss".to_owned()))
    }

    fn verify_shares(
        &self,
        _shares: &EncryptedShares,
        _ctx: &PvssContext,
    ) -> Result<(), PvssError> {
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
