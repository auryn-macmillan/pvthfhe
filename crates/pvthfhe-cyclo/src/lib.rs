//! Cyclo LatticeFold+ backend for PVTHFHE Phase 2.
//!
//! Implements sequential T=10 folding of per-share CCS instances over
//! R_{q_commit} = Z_{q_commit}\[X\]/(X^256+1).
//!
//! # Security — Phase 2 Status
//!
//! ⚠️ This crate implements real Cyclo LatticeFold+ folding.
//! Soundness is conditional on M-SIS hardness over R_{q_commit},
//! Cyclo Theorem 3 (ePrint 2026/359), and the Lemma 9 invertibility
//! heuristic used by the folding backend. The joint extractor (T2)
//! remains a skeleton — see `SECURITY.md §P1`.

pub mod adapter;
pub mod ccs_encode;
pub mod driver;
pub mod extension;
pub mod fold;
pub mod range_check;
pub mod ring;

/// Backend identifier for the Cyclo LatticeFold+ implementation.
pub const CYCLO_BACKEND_ID: &str = "cyclo-rlwe-t10-lemma9-heuristic";

/// Locked Cyclo LatticeFold+ parameters for PVTHFHE Phase 2.
///
/// All values are frozen per spec §4.1. Do not modify without updating
/// the spec addendum and recording a new Backend Lock entry in `AGENTS.md`.
pub struct CycloParams {
    /// Cyclotomic ring degree: X^{phi_commit}+1.
    pub phi_commit: usize,
    /// log₂ of the commitment modulus.
    pub log2_q_commit: u32,
    /// Commitment modulus q_commit (50-bit prime ≡ 1 mod 1024).
    pub q_commit: u64,
    /// Ajtai matrix rank *a* (columns of the commitment matrix).
    pub ajtai_rank_a: usize,
    /// Initial witness norm bound B.
    pub norm_bound_b: u64,
    /// Decomposition base *b* (binary: b=2).
    pub base_b: u32,
    /// Number of sequential fold steps T.
    pub sequential_t: u32,
    /// Number of CCS instances folded per round L.
    pub l_per_round: u32,
    /// Accumulated norm bound at depth T:
    /// `beta_at_t = norm_bound_b + sequential_t * base_b * 16`.
    /// At T=10: 1024 + 10·2·16 = 1344.
    pub beta_at_t: u64,
}

/// Locked parameter set for PVTHFHE Phase 2 Cyclo folding.
pub const PVTHFHE_CYCLO_PARAMS: CycloParams = CycloParams {
    phi_commit: 256,
    log2_q_commit: 50,
    q_commit: 562_949_953_438_721,
    ajtai_rank_a: 13,
    norm_bound_b: 1024,
    base_b: 2,
    sequential_t: 10,
    l_per_round: 1,
    beta_at_t: 1344,
};

/// A per-participant CCS instance produced by the P1 NIZK layer.
pub struct CcsPShareInstance {
    /// Participant index (1-based, sorted ascending during fold).
    pub participant_id: u16,
    /// Serialised Ajtai commitment over R_{q_commit}.
    pub ajtai_commitment_bytes: Vec<u8>,
    /// Serialised public I/O for the CCS relation.
    pub public_io_bytes: Vec<u8>,
    /// Serialised CCS witness.
    pub ccs_witness_bytes: Vec<u8>,
    /// SHA-256 binding tag tying this instance to the session transcript.
    pub sha256_binding_bytes: Vec<u8>,
}

/// Running Cyclo accumulator produced after one or more fold steps.
pub struct CycloAccumulator {
    /// Number of fold steps applied so far (0 ≤ fold_depth ≤ T).
    pub fold_depth: u32,
    /// Serialised accumulated commitment vector.
    pub acc_commitment_bytes: Vec<u8>,
    /// Serialised accumulated public I/O.
    pub acc_public_io_bytes: Vec<u8>,
    /// Current infinity-norm bound on the accumulated witness.
    pub norm_bound_current: u64,
    /// Opaque session identifier (hex string).
    pub session_id: String,
    /// SHA-256 digest of the [`CycloParams`] used for this accumulator.
    pub params_digest: [u8; 32],
}

/// Errors that can occur during Cyclo folding or verification.
#[derive(Debug, thiserror::Error)]
pub enum CycloError {
    /// The supplied CCS instance is structurally invalid.
    #[error("invalid CCS instance: {0}")]
    InvalidInstance(&'static str),
    /// The witness norm exceeds the allowed bound.
    #[error("norm bound exceeded: got {got}, max {max}")]
    NormBoundExceeded {
        /// Observed norm.
        got: u64,
        /// Maximum permitted norm.
        max: u64,
    },
    /// All T fold steps have been consumed.
    #[error("fold depth exhausted: T={0}")]
    FoldDepthExhausted(u32),
    /// The accumulator failed the verifier check.
    #[error("accumulator verification failed: {0}")]
    AccumulatorVerificationFailed(&'static str),
}

/// Object-safe trait for Cyclo LatticeFold+ adapters.
///
/// Implementors must be object-safe (`dyn CycloAdapter` must be valid).
/// The sole provided implementation today is [`adapter::StubCycloAdapter`];
/// real folding will be wired in tasks F2–F7.
pub trait CycloAdapter {
    /// Returns the backend identifier string (e.g. [`CYCLO_BACKEND_ID`]).
    fn backend_id(&self) -> &'static str;

    /// Returns a reference to the locked [`CycloParams`] used by this adapter.
    fn params(&self) -> &CycloParams;

    /// Fold a single [`CcsPShareInstance`] into `acc`, producing a new accumulator.
    ///
    /// `rng` is used for the random challenge in the Cyclo fold step.
    fn fold_one(
        &self,
        acc: CycloAccumulator,
        instance: &CcsPShareInstance,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<CycloAccumulator, CycloError>;

    /// Verify that `acc` is a valid accumulator for the given `instances`.
    fn verify_accumulator(
        &self,
        acc: &CycloAccumulator,
        instances: &[CcsPShareInstance],
    ) -> Result<(), CycloError>;

    /// Fold all `instances` sequentially, returning the final accumulator.
    ///
    /// # Soundness
    ///
    /// This fold is conditional on the Cyclo Lemma 9 invertibility
    /// heuristic for the backend's challenge sampling.
    ///
    /// Instances are folded in the order supplied; callers should sort by
    /// ascending `participant_id` before calling.
    fn fold_all(
        &self,
        instances: &[CcsPShareInstance],
        session_id: &str,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<CycloAccumulator, CycloError>;
}
