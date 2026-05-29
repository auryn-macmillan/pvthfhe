//! Adapter trait and supporting types for per-share NIZK backends.
//!
//! This crate defines the [`NizkAdapter`] trait — an object-safe boundary
//! that all P1 NIZK backends must implement — along with the public statement,
//! witness, proof, and error types.
//!
//! # Security
//!
//! ⚠️ **Conditional-soundness disclosure (Open Problem P1)**:
//! Verification success via any [`NizkAdapter`] implementation is conditional
//! on the knowledge-soundness of the underlying Cyclo-companion Ajtai NIZK
//! (T2 — joint extractor — remains a skeleton).  See `SECURITY.md §P1` for the
//! full disclosure.  Do not treat an [`Ok(())`] result from
//! [`NizkAdapter::verify`] as a formal security guarantee until T2 is closed.
#![deny(missing_docs)]

pub mod adapter;
pub mod ajtai;
pub mod bfv_sigma;
pub mod fiat_shamir;
pub mod hash_bridge;
pub mod schnorr;
pub mod sigma;

pub use sigma::{
    compute_jl_entries, compute_jl_projection, compute_raw_jl_sum,
    derive_challenge_from_commitment, derive_transcript_commitment, l2_squared, prove_multi,
    verify_multi, SigmaMultiProof, B_Y, B_Z_E, B_Z_S, JL_PROJECTION_DIM, SIGMA_REPETITIONS,
};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canonical backend identifier for the Cyclo-companion Ajtai D2 NIZK.
///
/// Implementations of [`NizkAdapter`] MUST set [`NizkProof::backend_id`] to
/// this constant so consumers can detect the conditional-soundness claim.
pub const BACKEND_ID: &str = "cyclo-ajtai-d2-conditional";

/// Frozen public statement for one per-share lattice NIZK claim.
///
/// Phase 2 (N4): will extend with Cyclo CCS instance identifier and Ajtai
/// matrix parameters when `crates/pvthfhe-nizk/src/ajtai.rs` is implemented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkStatement {
    /// Canonical ciphertext bytes.
    pub ciphertext_bytes: Vec<u8>,
    /// Canonical partial decrypt-share bytes.
    pub decrypt_share_bytes: Vec<u8>,
    /// P4 PVSS commitment hash (`SHA256(session_id ∥ i_le ∥ s_i_be)` in D2 variant).
    pub pvss_commitment: [u8; 32],
    /// Bound FHE parameter tuple `(q, degree, error_bound)`.
    pub params: (u64, usize, u64),
    /// Session binding inherited from P4.
    pub session_id: String,
    /// Participant binding inherited from P4.
    pub participant_id: u16,
    /// On-chain epoch that binds the CRS (Ajtai matrix derivation seed).
    pub epoch: u64,
}

/// Frozen prover witness for one per-share lattice NIZK claim.
///
/// Phase 2 (N4): will extend with Cyclo fold witness fields.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NizkWitness {
    /// Secret share value inherited from P4 (scalar u64).
    ///
    /// Kept for backward compatibility; the Cyclo backend uses
    /// [`NizkWitness::secret_share_poly`] for the algebraic RLWE proof and only
    /// uses this field for the D2 hash-binding commitment.
    pub secret_share: u64,
    /// Ternary RLWE secret-share polynomial (length N=8192, coefficients ∈ {-1,0,1}).
    ///
    /// This is the polynomial form of the secret share used by the
    /// `CycloNizkAdapter` sigma protocol.  It is independent of
    /// [`NizkWitness::secret_share`]: the scalar is the D2 binding value while
    /// the polynomial is the RLWE algebraic witness.
    pub secret_share_poly: Vec<i64>,
    /// Canonical lattice error vector (`e_i`; must satisfy `‖e_i‖_∞ ≤ B_e`).
    pub error: Vec<i64>,
    /// Canonical prover randomness bytes.
    pub randomness: Vec<u8>,
}

/// Opaque deterministic proof record.
///
/// The [`NizkProof::backend_id`] field MUST equal [`BACKEND_ID`] for any proof
/// produced by backends in this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkProof {
    /// Proof backend identifier; MUST equal [`BACKEND_ID`].
    pub backend_id: String,
    /// Serialized proof payload.
    pub proof_bytes: Vec<u8>,
}

impl NizkProof {
    /// Returns the canonical serialized proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
}

/// Errors produced by [`NizkAdapter`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NizkError {
    /// Verification succeeded algebraically but soundness is conditional on an
    /// unproven extractor (T2 — Open Problem P1).  See `SECURITY.md §P1`.
    #[error("conditional soundness: {0}")]
    ConditionalSoundnessDisclosure(&'static str),
    /// Statement or witness encoding is malformed.
    #[error("invalid NIZK input: {0}")]
    InvalidInput(&'static str),
    /// Proof bytes could not be decoded.
    #[error("invalid NIZK proof: {0}")]
    InvalidProof(&'static str),
    /// The proof does not satisfy the verification equation.
    #[error("NIZK verification failed: {0}")]
    VerificationFailed(&'static str),
}

/// Object-safe adapter trait for per-share P1 NIZK backends.
///
/// All methods take `&self` and `rng` is `&mut dyn rand_core::RngCore` to
/// preserve object-safety so backends can be used through `Box<dyn NizkAdapter>`.
///
/// # Security
///
/// ⚠️ See the crate-level documentation for the conditional-soundness disclosure
/// that applies to every implementation of this trait.
pub trait NizkAdapter {
    /// Returns a static identifier string for this backend.
    ///
    /// MUST equal [`BACKEND_ID`] for all backends shipped in this crate.
    fn backend_id(&self) -> &'static str;

    /// Produce a proof for the provided statement and witness.
    ///
    /// `rng` is `dyn` to preserve object-safety on the trait.
    fn prove(
        &self,
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<NizkProof, NizkError>;

    /// Verify a single proof against a statement.
    ///
    /// # Security
    ///
    /// ⚠️ May return [`NizkError::ConditionalSoundnessDisclosure`] on algebraic success
    /// — soundness is conditional.
    fn verify(&self, stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;

    /// Verify a batch of statements and proofs.
    ///
    /// Implementations MAY short-circuit on the first failure.
    fn batch_verify(&self, stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}
