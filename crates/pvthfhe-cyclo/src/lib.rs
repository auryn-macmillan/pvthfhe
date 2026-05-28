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

#![allow(missing_docs)]

pub mod adapter;
pub mod ajtai;
pub mod ccs_encode;
pub mod ccs_rlwe;
pub mod driver;
pub mod extension;
pub mod fiat_shamir;
pub mod fold;
pub mod range_check;
pub mod ring;

use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};

/// Public fold track identity for H.2 multi-track folded instances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldTrackKind {
    /// Secret-key share witness commitment track.
    Sk,
    /// Committed smudging error witness commitment track.
    ESm,
    /// BFV encryption witness commitment track.
    EncryptionWitness,
}

impl FoldTrackKind {
    /// Domain-separated byte label for canonical fold metadata encoding.
    pub fn as_domain_bytes(&self) -> &'static [u8] {
        match self {
            Self::Sk => b"pvthfhe-fold-track-sk-v1",
            Self::ESm => b"pvthfhe-fold-track-e-sm-v1",
            Self::EncryptionWitness => b"pvthfhe-fold-track-encryption-witness-v1",
        }
    }
}

/// Public commitment and bound for one fold track.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldTrackCommitment {
    /// Domain-separated track kind.
    pub kind: FoldTrackKind,
    /// Optional smudge/encryption slot index; must be absent for `sk` and present for non-`sk` tracks.
    pub slot_index: Option<u16>,
    /// Public commitment/digest for this track. Contains no raw witness material.
    pub commitment: Vec<u8>,
    /// Public infinity-norm bound for this track.
    pub norm_bound: u64,
}

/// Public multi-track metadata bound into a folded instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiTrackFoldMetadata {
    /// Session/transcript identifier for cross-session replay protection.
    pub session_id: String,
    /// Participant identifier bound to this instance.
    pub participant_id: u16,
    /// Public party binding digest/bytes.
    pub party_binding: Vec<u8>,
    /// Number of instances in the enclosing folded batch.
    pub instance_count: u32,
    /// Independent public track commitments and bounds.
    pub tracks: Vec<FoldTrackCommitment>,
}

impl MultiTrackFoldMetadata {
    /// Canonical, domain-separated public encoding for Fiat-Shamir/fold binding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"pvthfhe-cyclo-multitrack-fold-v1");
        push_u64_len(&mut out, self.session_id.as_bytes());
        out.extend_from_slice(&self.participant_id.to_be_bytes());
        push_u64_len(&mut out, &self.party_binding);
        out.extend_from_slice(&self.instance_count.to_be_bytes());
        // KNOWN_LIMITATION(c5_usize_conv): usize→u32 fallback; track count bounded by protocol, conversion infallible in practice.
        out.extend_from_slice(
            &u32::try_from(self.tracks.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for track in &self.tracks {
            push_u64_len(&mut out, track.kind.as_domain_bytes());
            match track.slot_index {
                Some(slot) => {
                    out.push(1);
                    out.extend_from_slice(&slot.to_be_bytes());
                }
                None => {
                    out.push(0);
                    out.extend_from_slice(&0u16.to_be_bytes());
                }
            }
            out.extend_from_slice(&track.norm_bound.to_be_bytes());
            push_u64_len(&mut out, &track.commitment);
        }
        out
    }

    /// Validate public metadata consistency without inspecting private witnesses.
    pub fn validate_for_instance(
        &self,
        participant_id: u16,
        session_id: &str,
        expected_instance_count: usize,
    ) -> Result<(), CycloError> {
        if self.session_id != session_id {
            return Err(CycloError::InvalidInstance("multi-track session mismatch"));
        }
        if self.participant_id != participant_id {
            return Err(CycloError::InvalidInstance(
                "multi-track participant mismatch",
            ));
        }
        if self.instance_count as usize != expected_instance_count {
            return Err(CycloError::InvalidInstance(
                "multi-track instance_count mismatch",
            ));
        }
        if self.party_binding.is_empty() {
            return Err(CycloError::InvalidInstance(
                "multi-track party_binding is empty",
            ));
        }
        if self.tracks.is_empty() {
            return Err(CycloError::InvalidInstance("multi-track tracks are empty"));
        }
        let mut saw_sk = false;
        let mut saw_esm = false;
        let mut saw_encryption = false;
        for track in &self.tracks {
            if track.commitment.is_empty() {
                return Err(CycloError::InvalidInstance(
                    "multi-track commitment is empty",
                ));
            }
            if track.norm_bound == 0 {
                return Err(CycloError::InvalidInstance(
                    "multi-track norm_bound is zero",
                ));
            }
            if track.norm_bound > PVTHFHE_CYCLO_PARAMS.norm_bound_b {
                return Err(CycloError::NormBoundExceeded {
                    got: track.norm_bound,
                    max: PVTHFHE_CYCLO_PARAMS.norm_bound_b,
                });
            }
            match track.kind {
                FoldTrackKind::Sk => {
                    if track.slot_index.is_some() {
                        return Err(CycloError::InvalidInstance(
                            "sk track must not have slot_index",
                        ));
                    }
                    saw_sk = true;
                }
                FoldTrackKind::ESm => {
                    if track.slot_index.is_none() {
                        return Err(CycloError::InvalidInstance(
                            "e_sm track requires slot_index",
                        ));
                    }
                    saw_esm = true;
                }
                FoldTrackKind::EncryptionWitness => {
                    if track.slot_index.is_none() {
                        return Err(CycloError::InvalidInstance(
                            "encryption track requires slot_index",
                        ));
                    }
                    saw_encryption = true;
                }
            }
        }
        if !saw_sk || !saw_esm || !saw_encryption {
            return Err(CycloError::InvalidInstance(
                "multi-track metadata requires sk, e_sm, and encryption tracks",
            ));
        }
        Ok(())
    }
}

fn push_u64_len(out: &mut Vec<u8>, value: &[u8]) {
    // KNOWN_LIMITATION(c5_usize_conv): usize→u64 fallback; infallible on 64-bit, defensive on 32-bit.
    out.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    out.extend_from_slice(value);
}

/// Backend identifier for the Cyclo LatticeFold+ implementation.
pub const CYCLO_BACKEND_ID: &str = "cyclo-rlwe-t10-lemma9-heuristic";

/// CCS wire format version.
///
/// - V1: 1-matrix `M·z ⊙ z == 0` with 7-element witness (legacy, backward compat).
/// - V2: 3-matrix `(M₁·z) ⊙ (M₂·z) == M₃·z` with 5-element witness.
pub const CCS_WIRE_VERSION: u32 = 2;

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
    pub ajtai_commitment_bytes: ProtocolBytes,
    /// Serialised public I/O for the CCS relation.
    pub public_io_bytes: ProtocolBytes,
    /// Serialised CCS witness in Fr-LE wire format [u32 BE len][Fr LE elements].
    pub ccs_witness_bytes: CcsWitnessSecret,
    /// SHA-256 binding tag tying this instance to the session transcript.
    pub sha256_binding_bytes: ProtocolBytes,
    /// Serialised CCS constraint matrix [rows:u32 BE][cols:u32 BE][data: rows*cols Fr LE].
    pub ccs_matrix_bytes: ProtocolBytes,
}

impl CcsPShareInstance {
    /// Attach public H.2 multi-track commitments/norms to this fold instance.
    pub fn with_multi_track_metadata(
        self,
        metadata: MultiTrackFoldMetadata,
    ) -> MultiTrackPShareInstance {
        MultiTrackPShareInstance {
            base: self,
            multi_track_metadata: Some(metadata),
        }
    }
}

/// A backward-compatible CCS instance plus optional public H.2 multi-track metadata.
pub struct MultiTrackPShareInstance {
    /// Legacy single-track fold instance.
    pub base: CcsPShareInstance,
    /// Optional public H.2 multi-track commitments/norms bound into folding.
    pub multi_track_metadata: Option<MultiTrackFoldMetadata>,
}

impl MultiTrackPShareInstance {
    /// Borrow the legacy base instance.
    pub fn base(&self) -> &CcsPShareInstance {
        &self.base
    }

    /// Borrow the optional multi-track metadata.
    pub fn multi_track_metadata(&self) -> Option<&MultiTrackFoldMetadata> {
        self.multi_track_metadata.as_ref()
    }
}

impl From<CcsPShareInstance> for MultiTrackPShareInstance {
    fn from(base: CcsPShareInstance) -> Self {
        Self {
            base,
            multi_track_metadata: None,
        }
    }
}

/// Running Cyclo accumulator produced after one or more fold steps.
#[derive(Debug, Clone, PartialEq, Eq)]
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
/// The sole provided implementation today is [`adapter::LegacyHashChainAdapter`];
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
