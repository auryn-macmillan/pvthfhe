//! Statement, witness, and proof type definitions for the share-encryption
//! NIZK, plus the statement-derived commitments and binding tags shared by
//! the prover and verifier.

use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_foundations::types::{EncRandomness, ProtocolBytes, ShareSecret};
use pvthfhe_nizk::ajtai::{
    AjtaiCommitment, AjtaiMatrix, AjtaiParams, Rq, PHI, Q_COMMIT, WITNESS_BOUND,
};
use pvthfhe_nizk::fiat_shamir::Transcript;
use pvthfhe_nizk::sigma;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

use crate::PvssError;

use super::{
    CANONICAL_PARAMS_TOML, CHALLENGE_LEN, DIGEST_LEN, MAX_FIELD_LEN, SHARE_NIZK_DOMAIN_SEPARATOR,
};

/// Public statement for one share-encryption proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkStatement {
    /// Session binding bytes.
    pub session_id: ProtocolBytes,
    /// Zero-based dealer index bound into the transcript.
    pub dealer_index: usize,
    /// Zero-based recipient index bound into the transcript and commitment.
    pub recipient_index: usize,
    /// Recipient public-key bytes for the encrypted share.
    pub recipient_pk: ProtocolBytes,
    /// Canonical BFV parameters digest (SHA-256 over canonical params TOML).
    pub bfv_params_digest: ProtocolBytes,
    /// DKG anchoring root digest for session binding.
    pub dkg_root: ProtocolBytes,
    /// Primary ciphertext bytes produced by the BFV backend.
    pub ciphertext_u: ProtocolBytes,
    /// Hash-bound secondary ciphertext component.
    pub ciphertext_v: ProtocolBytes,
    /// Share commitment bytes (D2 hash binding).
    pub share_commitment: ProtocolBytes,
}

/// Secret witness for one share-encryption proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkWitness {
    /// Serialized share bytes.
    pub share_bytes: ShareSecret,
    /// Deterministic encryption randomness binding bytes.
    pub encryption_randomness: EncRandomness,
}

/// Serialized proof envelope (no witness material).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkProof {
    /// Serialized proof payload (ProtocolBytes, not WitnessLeakingProofBytesV0).
    pub proof_bytes: ProtocolBytes,
    /// Domain separator recorded in the proof envelope.
    pub domain_separator: String,
}

/// Decoded proof contents — no witness fields exposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkOpenedProof {
    /// Statement reconstructed from the proof payload.
    pub statement: ShareNizkStatement,
    /// Commitment ciphertext: a fresh BFV encryption created by the prover
    /// as a sigma-protocol commitment.
    pub commitment_bytes: ProtocolBytes,
    /// Deterministic binding seed for the encryption commitment.
    pub commitment_seed: [u8; DIGEST_LEN],
    /// Fresh 32-byte nonce added to commitment-seed derivation to prevent
    /// rushing-adversary precomputation of deterministic commitments.
    pub commitment_nonce: [u8; DIGEST_LEN],
    /// Commitment binding tag: SHA-256 over statement, relation_binding, commitment seed.
    pub commitment_binding: [u8; DIGEST_LEN],
    /// Fiat-Shamir challenge bytes.
    pub challenge: [u8; CHALLENGE_LEN],
    /// Lattice binding tag: commits the statement, commitment, and witness
    /// without revealing the witness.
    pub lattice_binding: [u8; DIGEST_LEN],
    /// Relation binding: SHA-256 over statement and algebraic proof.
    pub relation_binding: [u8; DIGEST_LEN],
    /// Algebraic proof: share sigma proof over RLWE relation.
    pub algebraic_proof: ProtocolBytes,
    /// BFV encryption sigma proof: self-contained statement+proof.
    pub bfv_encryption_proof: ProtocolBytes,
    /// D2 preimage binding: SHA256(commitment_ct || share_commitment || session_id || recipient_index)
    pub d2_binding: [u8; 32],
    /// Domain separator stored in the proof payload.
    pub domain_separator: String,
}

// ── Batched proof types ───────────────────────────────────────────────────

/// Track type identifier for batched share proofs (D.2+).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareNizkTrackType {
    /// Secret-key share track.
    Sk,
    /// Smudging-error share track.
    ESm,
}

/// Per-track statement for batched share proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkTrackStatement {
    /// Track type.
    pub track_type: ShareNizkTrackType,
    /// Optional slot index for ESm slots.
    pub slot_index: Option<u16>,
    /// Primary ciphertext bytes.
    pub ciphertext_u: ProtocolBytes,
    /// Hash-bound ciphertext v.
    pub ciphertext_v: ProtocolBytes,
    /// Track commitment (D2 binding).
    pub track_commitment: ProtocolBytes,
}

/// Batched statement grouping sk and esm tracks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkBatchedStatement {
    /// Session binding bytes.
    pub session_id: ProtocolBytes,
    /// Zero-based dealer index.
    pub dealer_index: usize,
    /// Zero-based recipient index.
    pub recipient_index: usize,
    /// Recipient public-key bytes.
    pub recipient_pk: ProtocolBytes,
    /// Canonical BFV parameters digest.
    pub bfv_params_digest: ProtocolBytes,
    /// DKG anchoring root digest.
    pub dkg_root: ProtocolBytes,
    /// Secret-key share track.
    pub sk: ShareNizkTrackStatement,
    /// Smudging-error share tracks (one per slot).
    pub esm_slots: Vec<ShareNizkTrackStatement>,
}

impl ShareNizkBatchedStatement {
    /// Build a legacy ShareNizkStatement for a given track (D.2 stub).
    pub fn legacy_statement_for_track(
        &self,
        track_type: ShareNizkTrackType,
        slot_index: Option<u16>,
    ) -> ShareNizkStatement {
        let (ct_u, ct_v, commitment) = match track_type {
            ShareNizkTrackType::Sk => (
                self.sk.ciphertext_u.clone(),
                self.sk.ciphertext_v.clone(),
                self.sk.track_commitment.clone(),
            ),
            ShareNizkTrackType::ESm => {
                let slot = slot_index.unwrap_or(0);
                let esm = self
                    .esm_slots
                    .get(slot as usize)
                    .cloned()
                    .unwrap_or_else(|| ShareNizkTrackStatement {
                        track_type: ShareNizkTrackType::ESm,
                        slot_index: Some(slot),
                        ciphertext_u: ProtocolBytes(vec![]),
                        ciphertext_v: ProtocolBytes(vec![]),
                        track_commitment: ProtocolBytes(vec![]),
                    });
                (esm.ciphertext_u, esm.ciphertext_v, esm.track_commitment)
            }
        };
        ShareNizkStatement {
            session_id: self.session_id.clone(),
            dealer_index: self.dealer_index,
            recipient_index: self.recipient_index,
            recipient_pk: self.recipient_pk.clone(),
            bfv_params_digest: self.bfv_params_digest.clone(),
            dkg_root: self.dkg_root.clone(),
            ciphertext_u: ct_u,
            ciphertext_v: ct_v,
            share_commitment: commitment,
        }
    }
}

pub(super) fn compute_share_d_commitment(stmt: &ShareNizkStatement) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(Tag::ShareDcommit.as_bytes());
    h.update(stmt.session_id.as_slice());
    h.update(
        u32::try_from(stmt.recipient_index)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    h.update(stmt.share_commitment.as_slice());
    h.finalize().into()
}

pub(super) fn derive_share_sigma_c_rns(session_id: &[u8], recipient_index: usize) -> Vec<u64> {
    let mut h = Sha256::new();
    h.update(Tag::ShareSigmaCRns.as_bytes());
    h.update(session_id);
    h.update(recipient_index.to_be_bytes());
    // allow-seeded-rng: Fiat-Shamir public-coin challenge polynomial; seed = SHA256(domain ‖ session_id ‖ recipient_index), so the verifier re-derives the identical c
    let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
    let moduli = pvthfhe_foundations::types::rlwe_moduli();
    let n = sigma::rlwe_n();
    let mut out = vec![0u64; n * moduli.len()];
    for (limb, modulus) in moduli.iter().enumerate() {
        for index in 0..n {
            out[limb * n + index] = rng.next_u64() % modulus;
        }
    }
    out
}

/// Compute the share commitment via RLWE sigma D2 hash binding.
///
/// Derives the sigma public polynomial `c_rns` from `(session_id, recipient_index)`,
/// computes `s_i` as a digest-derived ternary witness, and returns
/// `SHA256(pvthfhe-share-sigma-d-commitment-v1 || to_le_bytes(d_rns))`.
/// The algebraic proof verifier checks this commitment against the claimed share.
pub fn compute_share_commitment(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
) -> Result<[u8; DIGEST_LEN], PvssError> {
    compute_ajtai_d2_binding(session_id, recipient_index, share_bytes)
}

/// Compute the share commitment with per-track domain separation (D.2).
///
/// Unlike [`compute_share_commitment`], this variant includes a
/// `track_domain_tag` (e.g., [`Tag::PvssBatchedDkgShareEncryptionSkTrack`]
/// or [`Tag::PvssBatchedDkgShareEncryptionESmTrack`]) in the Ajtai D2
/// binding to prevent cross-track replay.
pub fn compute_share_commitment_tracked(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
    track_domain_tag: &[u8],
) -> Result<[u8; DIGEST_LEN], PvssError> {
    compute_ajtai_d2_binding_tracked(session_id, recipient_index, share_bytes, track_domain_tag)
}

/// Compute the hash-bound secondary ciphertext component from `ciphertext_u`.
pub fn compute_ciphertext_v(ciphertext_u: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(Tag::CiphertextV.as_bytes());
    hasher.update(ciphertext_u);
    hasher.finalize().into()
}

/// Compute the canonical BFV parameters digest.
pub fn canonical_bfv_params_digest() -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(Tag::BfvParams.as_bytes());
    hasher.update(CANONICAL_PARAMS_TOML.as_bytes());
    hasher.finalize().into()
}

pub(super) fn validate_statement(stmt: &ShareNizkStatement) -> Result<(), PvssError> {
    if stmt.session_id.is_empty()
        || stmt.recipient_pk.is_empty()
        || stmt.ciphertext_u.is_empty()
        || stmt.ciphertext_v.len() != DIGEST_LEN
        || stmt.share_commitment.len() != DIGEST_LEN
        || stmt.bfv_params_digest.len() != DIGEST_LEN
    {
        return Err(PvssError::InvalidShare {
            party_id: Some(stmt.recipient_index as u16),
        });
    }
    if stmt.recipient_pk.len() > MAX_FIELD_LEN || stmt.ciphertext_u.len() > MAX_FIELD_LEN {
        return Err(PvssError::InvalidShare {
            party_id: Some(stmt.recipient_index as u16),
        });
    }
    Ok(())
}

pub(super) fn validate_witness(witness: &ShareNizkWitness) -> Result<(), PvssError> {
    if witness.share_bytes.expose().is_empty()
        || witness.share_bytes.expose().len() > MAX_FIELD_LEN
        || witness.encryption_randomness.expose().is_empty()
        || witness.encryption_randomness.expose().len() > MAX_FIELD_LEN
    {
        return Err(PvssError::InvalidShare { party_id: None });
    }
    Ok(())
}

pub(super) fn derive_challenge(
    stmt: &ShareNizkStatement,
    commitment_ct: &[u8],
) -> [u8; CHALLENGE_LEN] {
    debug_assert!(
        stmt.dealer_index <= u32::MAX as usize,
        "dealer_index exceeds u32 range"
    );
    let participant_id = stmt.dealer_index as u32;
    let mut transcript = Transcript::new(stmt.session_id.as_slice(), participant_id);
    transcript.absorb(b"domain_separator", SHARE_NIZK_DOMAIN_SEPARATOR.as_bytes());
    transcript.absorb(b"session_id", stmt.session_id.as_slice());
    transcript.absorb(b"dealer_index", &stmt.dealer_index.to_be_bytes());
    transcript.absorb(b"recipient_index", &stmt.recipient_index.to_be_bytes());
    transcript.absorb(b"recipient_pk", stmt.recipient_pk.as_slice());
    transcript.absorb(b"bfv_params_digest", stmt.bfv_params_digest.as_slice());
    transcript.absorb(b"dkg_root", stmt.dkg_root.as_slice());
    transcript.absorb(b"ciphertext_u", stmt.ciphertext_u.as_slice());
    transcript.absorb(b"ciphertext_v", stmt.ciphertext_v.as_slice());
    transcript.absorb(b"share_commitment", stmt.share_commitment.as_slice());
    transcript.absorb(b"commitment_ct", commitment_ct);

    let mut challenge = [0u8; CHALLENGE_LEN];
    transcript.challenge_bytes(b"share-encryption-challenge", &mut challenge);
    challenge
}

// ── Binding computation helpers ───────────────────────────────────────────

pub(super) fn compute_relation_binding(
    stmt: &ShareNizkStatement,
    algebraic_proof: &[u8],
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(Tag::ShareRelationBindingV2.as_bytes());
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.recipient_pk.as_slice());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.ciphertext_v.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.update(algebraic_proof);
    h.finalize().into()
}

pub(super) fn compute_commitment_binding(
    stmt: &ShareNizkStatement,
    relation_binding: &[u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"greco-bfv-commitment-binding-v3");
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.recipient_pk.as_slice());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.update(relation_binding);
    h.finalize().into()
}

pub(super) fn compute_lattice_binding(
    stmt: &ShareNizkStatement,
    commitment_ct: &[u8],
    commitment_binding: &[u8; DIGEST_LEN],
    challenge: &[u8; CHALLENGE_LEN],
    relation_binding: &[u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"greco-bfv-binding-v1");
    hasher.update(challenge);
    hasher.update(stmt.session_id.as_slice());
    hasher.update(stmt.dealer_index.to_be_bytes());
    hasher.update(stmt.recipient_index.to_be_bytes());
    hasher.update(stmt.recipient_pk.as_slice());
    hasher.update(stmt.bfv_params_digest.as_slice());
    hasher.update(stmt.dkg_root.as_slice());
    hasher.update(stmt.ciphertext_u.as_slice());
    hasher.update(stmt.ciphertext_v.as_slice());
    hasher.update(stmt.share_commitment.as_slice());
    hasher.update(commitment_ct);
    hasher.update(commitment_binding);
    hasher.update(relation_binding);
    hasher.finalize().into()
}

pub(super) fn compute_lattice_binding_from_opened(
    stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> [u8; DIGEST_LEN] {
    compute_lattice_binding(
        stmt,
        opened.commitment_bytes.as_slice(),
        &opened.commitment_binding,
        &opened.challenge,
        &opened.relation_binding,
    )
}

/// Build opaque binding data for the BFV sigma protocol.
///
/// `session_id` and `dealer_index` are intentionally NOT included here — they
/// are now first-class params passed directly to `bfv_sigma::prove`/`verify`,
/// ensuring they cannot be accidentally omitted.
pub(super) fn bfv_sigma_binding_data(
    stmt: &ShareNizkStatement,
    d_commitment: &[u8; 32],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(Tag::ShareBfvSigmaBindingV5.as_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.ciphertext_v.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.update(d_commitment);
    h.finalize().to_vec()
}

// ── Ajtai D2 commitment ──────────────────────────────────────────────────

fn compute_ajtai_d2_binding(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
) -> Result<[u8; DIGEST_LEN], PvssError> {
    compute_ajtai_d2_binding_inner(session_id, recipient_index, share_bytes, None)
}

fn compute_ajtai_d2_binding_tracked(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
    track_domain_tag: &[u8],
) -> Result<[u8; DIGEST_LEN], PvssError> {
    compute_ajtai_d2_binding_inner(
        session_id,
        recipient_index,
        share_bytes,
        Some(track_domain_tag),
    )
}

fn compute_ajtai_d2_binding_inner(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
    track_domain_tag: Option<&[u8]>,
) -> Result<[u8; DIGEST_LEN], PvssError> {
    let mut hasher = Sha256::new();
    hasher.update(Tag::D2AjtaiMatrix.as_bytes());
    hasher.update(session_id);
    hasher.update(recipient_index.to_le_bytes());
    if let Some(tag) = track_domain_tag {
        hasher.update(tag);
    }
    let matrix_seed: [u8; DIGEST_LEN] = hasher.finalize().into();

    let params = AjtaiParams::default();
    let matrix = AjtaiMatrix::from_seed(matrix_seed, &params, 1) // allow-seeded-rng: deterministic Ajtai CRS for PVSS proof
        .map_err(|_| PvssError::D2HashBindingFailed {
            party_id: Some(recipient_index as u16),
        })?;

    let witness = encode_share_as_ajtai_witness(share_bytes)?;

    let commitment = AjtaiCommitment::commit(&matrix, &[witness]).map_err(|_| {
        PvssError::D2HashBindingFailed {
            party_id: Some(recipient_index as u16),
        }
    })?;

    Ok(commitment.to_d2_digest())
}

fn encode_share_as_ajtai_witness(share_bytes: &[u8]) -> Result<Rq, PvssError> {
    let mut coeffs = [0i64; PHI];
    let byte_count = share_bytes.len().min(PHI);
    for i in 0..byte_count {
        let val = i64::from(share_bytes[i]);
        if val > i64::try_from(WITNESS_BOUND).unwrap_or(i64::MAX) {
            return Err(PvssError::D2HashBindingFailed { party_id: None });
        }
        coeffs[i] = val;
    }
    let mut rq = Rq::new(coeffs, Q_COMMIT);
    rq.reduce()
        .map_err(|_| PvssError::D2HashBindingFailed { party_id: None })?;
    Ok(rq)
}
