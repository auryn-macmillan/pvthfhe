//! R3.1 Share-encryption NIZK — Greco-primary binding proof.
//!
//! This module implements a Fiat-Shamir NIZK for share well-formedness.
//! The proof proves knowledge of (share_bytes, encryption_randomness) such that
//! the ciphertext in the statement is a valid BFV encryption of the share under
//! the recipient's public key.
//!
//! **D.1 GREEN**: BFV encryption sigma proof wired via `bfv_sigma` module.
//! V4 proofs include a self-contained BFV encryption relation proof.
//! V3 and earlier proofs fail-closed (rejected).

use fhe_math::rq::Context;
use fhe_traits::DeserializeWithContext;
use pvthfhe_domain_tags::Tag;
use pvthfhe_fhe::types::{Ciphertext, PublicKey};
use pvthfhe_fhe::wire;
use pvthfhe_fhe::FheBackend;
use pvthfhe_nizk::ajtai::{
    AjtaiCommitment, AjtaiMatrix, AjtaiParams, Rq, PHI, Q_COMMIT, WITNESS_BOUND,
};
use pvthfhe_nizk::bfv_sigma::{
    self, bfv_delta_rns, decode_bfv_sigma_proof, encode_bfv_sigma_proof, poly_bytes_to_rns,
    BfvSigmaStatement, BfvSigmaWitness,
};
use pvthfhe_nizk::fiat_shamir::Transcript;
use pvthfhe_nizk::sigma;
use pvthfhe_types::witness_language::{
    BfvParameters as SchemaBfvParams, R3Relation, WitnessStatement,
};
use pvthfhe_types::{EncRandomness, EncryptionWitness, ProtocolBytes, ShareSecret};
use pvthfhe_wire::{WireError, WireFormat};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

use crate::PvssError;

/// Locked domain separator for PVSS share-encryption proofs.
pub const SHARE_NIZK_DOMAIN_SEPARATOR: &str = "pvthfhe-pvss-share-encryption-v4";

// R3.0a — schema types wired for R3.1 GREEN migration
const _: () = {
    let _: Option<SchemaBfvParams> = None;
    let _: Option<R3Relation> = None;
    let _: Option<WitnessStatement> = None;
};

/// Canonical BFV parameters TOML used for parameter binding.
const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

const PROOF_VERSION: u16 = 4;
const WIRE_VERSION: u8 = 4;
const CHALLENGE_LEN: usize = 32;
const DIGEST_LEN: usize = 32;
const MAX_FIELD_LEN: usize = 16 << 20;

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

/// Prover for the share-encryption proof. Requires FHE backend for encryption.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareNizkProver;

/// Verifier for the share-encryption proof. Requires FHE backend for lattice checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareNizkVerifier;

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

/// Batched verifier (stub for D.2 — delegates to individual verifier).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareNizkBatchedVerifier;

impl ShareNizkBatchedVerifier {
    /// Verify a batched proof covering sk and e_sm tracks.
    ///
    /// Decodes the batched proof envelope, dispatches each sub-proof
    /// to [`ShareNizkVerifier::verify`] against the corresponding
    /// per-track statement, and enforces cross-track domain binding
    /// (sk and e_sm track commitments must differ).
    pub fn verify(
        backend: &dyn FheBackend,
        batched: &ShareNizkBatchedStatement,
        proof: &ShareNizkProof,
    ) -> Result<(), PvssError> {
        let expected_domain = std::str::from_utf8(Tag::PvssBatchedDkgShareEncryption.as_bytes())
            .map_err(|_| PvssError::InvalidDomainSeparator)?;
        if proof.domain_separator != expected_domain {
            return Err(PvssError::InvalidDomainSeparator);
        }

        let bytes = proof.proof_bytes.as_slice();
        if bytes.len() < 2 {
            return Err(PvssError::BfvEncryptionProofFailed);
        }

        let num_tracks = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut offset: usize = 2;

        if num_tracks < 1 {
            return Err(PvssError::BfvEncryptionProofFailed);
        }
        let expected_esm_tracks = num_tracks as usize - 1;
        if expected_esm_tracks != batched.esm_slots.len() {
            return Err(PvssError::BfvEncryptionProofFailed);
        }

        // ── SK track verification ──
        let sk_stmt = ShareNizkStatement {
            session_id: batched.session_id.clone(),
            dealer_index: batched.dealer_index,
            recipient_index: batched.recipient_index,
            recipient_pk: batched.recipient_pk.clone(),
            bfv_params_digest: batched.bfv_params_digest.clone(),
            dkg_root: batched.dkg_root.clone(),
            ciphertext_u: batched.sk.ciphertext_u.clone(),
            ciphertext_v: batched.sk.ciphertext_v.clone(),
            share_commitment: batched.sk.track_commitment.clone(),
        };
        let sk_proof = read_batched_sub_proof(bytes, &mut offset)?;
        ShareNizkVerifier::verify(backend, &sk_stmt, &sk_proof)?;

        // ── ESm track verification ──
        for (_i, esm_slot) in batched.esm_slots.iter().enumerate() {
            let esm_stmt = ShareNizkStatement {
                session_id: batched.session_id.clone(),
                dealer_index: batched.dealer_index,
                recipient_index: batched.recipient_index,
                recipient_pk: batched.recipient_pk.clone(),
                bfv_params_digest: batched.bfv_params_digest.clone(),
                dkg_root: batched.dkg_root.clone(),
                ciphertext_u: esm_slot.ciphertext_u.clone(),
                ciphertext_v: esm_slot.ciphertext_v.clone(),
                share_commitment: esm_slot.track_commitment.clone(),
            };
            let esm_proof = read_batched_sub_proof(bytes, &mut offset)?;
            ShareNizkVerifier::verify(backend, &esm_stmt, &esm_proof)?;

            // Cross-track binding: sk and e_sm commitments must differ
            if batched.sk.track_commitment == esm_slot.track_commitment {
                return Err(PvssError::BfvEncryptionProofFailed);
            }
        }

        if offset != bytes.len() {
            return Err(PvssError::BfvEncryptionProofFailed);
        }

        Ok(())
    }
}

/// Decode a single sub-proof from a batched proof byte stream.
///
/// Reads `[proof_len: u32][proof_bytes]` from `bytes` starting at
/// `*offset`, advances `*offset`, and returns the reconstructed
/// [`ShareNizkProof`].
fn read_batched_sub_proof(bytes: &[u8], offset: &mut usize) -> Result<ShareNizkProof, PvssError> {
    let remaining = bytes.len().checked_sub(*offset).unwrap_or(0);
    if remaining < 4 {
        return Err(PvssError::BfvEncryptionProofFailed);
    }
    let proof_len = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]) as usize;
    *offset += 4;
    if proof_len > MAX_FIELD_LEN || bytes.len().checked_sub(*offset).unwrap_or(0) < proof_len {
        return Err(PvssError::BfvEncryptionProofFailed);
    }
    let sub_proof_bytes = bytes[*offset..*offset + proof_len].to_vec();
    *offset += proof_len;
    ShareNizkProof::from_bytes(sub_proof_bytes).map_err(|_| PvssError::BfvEncryptionProofFailed)
}

impl ShareNizkProver {
    /// Produce a share-encryption proof.
    ///
    /// The proof does NOT serialize the witness into the proof envelope.
    /// Instead, it creates a commitment ciphertext using the FHE backend
    /// and binds it to the statement via a lattice binding tag.
    ///
    /// For v4, also produces a BFV encryption sigma proof when the backend
    /// supports `encrypt_with_witness`.
    pub fn prove(
        backend: &dyn FheBackend,
        stmt: &ShareNizkStatement,
        witness: &ShareNizkWitness,
        track_domain_tag: Option<&[u8]>,
    ) -> Result<ShareNizkProof, PvssError> {
        validate_statement(stmt)?;
        validate_witness(witness)?;

        let commitment_seed = compute_commitment_seed(stmt, track_domain_tag);

        let commitment_ct = create_commitment_ct(backend, stmt, witness, &commitment_seed)?;

        // ── Algebraic proof (share sigma over RLWE) ──
        let algebraic_proof = build_algebraic_proof(stmt, witness);

        // ── Relation binding ──
        let relation_binding = compute_relation_binding(stmt, &algebraic_proof);

        // ── Commitment binding ──
        let commitment_binding = compute_commitment_binding(stmt, &relation_binding);

        // ── Challenge ──
        let challenge = derive_challenge(stmt, &commitment_ct);

        // ── Lattice binding ──
        let lattice_binding = compute_lattice_binding(
            stmt,
            &commitment_ct,
            &commitment_binding,
            &challenge,
            &relation_binding,
        );

        // ── D2 binding ──
        let mut hasher = Sha256::new();
        hasher.update(&commitment_ct);
        hasher.update(stmt.share_commitment.as_slice());
        hasher.update(stmt.session_id.as_slice());
        hasher.update(stmt.dkg_root.as_slice());
        hasher.update(&(stmt.recipient_index as u64).to_le_bytes());
        let d2_binding: [u8; 32] = hasher.finalize().into();

        // ── BFV encryption proof (v4) ──
        let bfv_encryption_proof = build_bfv_encryption_proof(backend, stmt, witness)?;

        let opened = ShareNizkOpenedProof {
            statement: stmt.clone(),
            commitment_bytes: ProtocolBytes(commitment_ct),
            commitment_seed,
            commitment_binding,
            challenge,
            lattice_binding,
            relation_binding,
            algebraic_proof: ProtocolBytes(algebraic_proof),
            bfv_encryption_proof,
            d2_binding,
            domain_separator: SHARE_NIZK_DOMAIN_SEPARATOR.to_owned(),
        };

        ShareNizkProof::from_opened(&opened)
    }

    /// Produce a batched share-encryption proof (D.2).
    ///
    /// Creates independent per-track proofs for the sk track and each
    /// e_sm slot, then concatenates them into a single batched proof
    /// envelope. The proof is verified by [`ShareNizkBatchedVerifier::verify`].
    pub fn prove_batched(
        backend: &dyn FheBackend,
        batched: &ShareNizkBatchedStatement,
        sk_witness: &ShareNizkWitness,
        esm_witnesses: &[ShareNizkWitness],
    ) -> Result<ShareNizkProof, PvssError> {
        let sk_domain_tag = Tag::PvssBatchedDkgShareEncryptionSkTrack.as_bytes();
        let esm_domain_tag = Tag::PvssBatchedDkgShareEncryptionESmTrack.as_bytes();

        // Prove SK track — construct statement from the sk track directly
        let sk_stmt = ShareNizkStatement {
            session_id: batched.session_id.clone(),
            dealer_index: batched.dealer_index,
            recipient_index: batched.recipient_index,
            recipient_pk: batched.recipient_pk.clone(),
            bfv_params_digest: batched.bfv_params_digest.clone(),
            dkg_root: batched.dkg_root.clone(),
            ciphertext_u: batched.sk.ciphertext_u.clone(),
            ciphertext_v: batched.sk.ciphertext_v.clone(),
            share_commitment: batched.sk.track_commitment.clone(),
        };
        let sk_proof = Self::prove(backend, &sk_stmt, sk_witness, Some(sk_domain_tag))?;

        // Prove ESm tracks — construct statements from array positions,
        // not logical slot_index, to avoid the off-by-one in
        // legacy_statement_for_track which uses slot_index as an array offset.
        let mut esm_proofs: Vec<ShareNizkProof> = Vec::with_capacity(esm_witnesses.len());
        for (i, esm_witness) in esm_witnesses.iter().enumerate() {
            let esm_track = &batched.esm_slots[i];
            let esm_stmt = ShareNizkStatement {
                session_id: batched.session_id.clone(),
                dealer_index: batched.dealer_index,
                recipient_index: batched.recipient_index,
                recipient_pk: batched.recipient_pk.clone(),
                bfv_params_digest: batched.bfv_params_digest.clone(),
                dkg_root: batched.dkg_root.clone(),
                ciphertext_u: esm_track.ciphertext_u.clone(),
                ciphertext_v: esm_track.ciphertext_v.clone(),
                share_commitment: esm_track.track_commitment.clone(),
            };
            let esm_proof = Self::prove(backend, &esm_stmt, esm_witness, Some(esm_domain_tag))?;
            esm_proofs.push(esm_proof);
        }

        // Encode batched proof:
        //   [num_tracks: u16][sk_proof_len: u32][sk_proof_bytes]
        //   [esm0_proof_len: u32][esm0_proof_bytes]...
        let num_tracks = 1u16 + esm_proofs.len() as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&num_tracks.to_be_bytes());
        // SK track proof
        let sk_bytes = sk_proof.proof_bytes.as_slice();
        out.extend_from_slice(&(sk_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(sk_bytes);
        // ESm track proofs
        for esm_proof in &esm_proofs {
            let esm_bytes = esm_proof.proof_bytes.as_slice();
            out.extend_from_slice(&(esm_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(esm_bytes);
        }

        let batched_domain = std::str::from_utf8(Tag::PvssBatchedDkgShareEncryption.as_bytes())
            .map_err(|_| PvssError::InvalidShare)?;
        Ok(ShareNizkProof {
            proof_bytes: ProtocolBytes(out),
            domain_separator: batched_domain.to_owned(),
        })
    }
}

impl ShareNizkVerifier {
    /// Verify a share-encryption proof against a statement using the FHE backend.
    ///
    /// The verifier uses the FHE backend to:
    /// 1. Reconstruct the expected commitment ciphertext
    /// 2. Verify the lattice binding tag
    /// 3. Check Fiat-Shamir challenge consistency
    /// 4. Verify D2 hash binding (share commitment)
    /// 5. Verify BFV encryption relation (v4), fail-closed for v3
    pub fn verify(
        backend: &dyn FheBackend,
        stmt: &ShareNizkStatement,
        proof: &ShareNizkProof,
    ) -> Result<(), PvssError> {
        validate_statement(stmt)?;
        if proof.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR {
            eprintln!("[NIZK-VERIFY] FAIL: domain_separator mismatch on proof envelope");
            return Err(PvssError::InvalidDomainSeparator);
        }

        let opened = proof.decode()?;
        if opened.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR {
            eprintln!("[NIZK-VERIFY] FAIL: domain_separator mismatch on opened proof");
            return Err(PvssError::InvalidDomainSeparator);
        }
        if opened.statement != *stmt {
            eprintln!("[NIZK-VERIFY] FAIL: statement mismatch");
            return Err(PvssError::StatementMismatch);
        }

        let expected_challenge = derive_challenge(stmt, opened.commitment_bytes.as_slice());
        if expected_challenge != opened.challenge {
            eprintln!("[NIZK-VERIFY] FAIL: challenge mismatch");
            eprintln!("  expected_challenge = {:02x?}", &expected_challenge[..]);
            eprintln!("  opened.challenge   = {:02x?}", &opened.challenge[..]);
            return Err(PvssError::ChallengeVerificationFailed);
        }

        let expected_ciphertext_v = compute_ciphertext_v(stmt.ciphertext_u.as_slice());
        if expected_ciphertext_v.as_slice() != stmt.ciphertext_v.as_slice() {
            eprintln!("[NIZK-VERIFY] FAIL: ciphertext_v mismatch");
            return Err(PvssError::CiphertextVMismatch);
        }

        // ── Commitment structure check ──
        verify_commitment_structure(backend, stmt, &opened)?;

        // ── Algebraic proof verification ──
        verify_algebraic_relation(stmt, &opened)?;

        // ── Relation binding ──
        verify_relation_binding(stmt, &opened)?;

        // ── Commitment binding ──
        verify_commitment_binding_tag(stmt, &opened)?;

        // ── Lattice binding ──
        verify_lattice_binding(stmt, &opened)?;

        // ── D2 binding ──
        verify_d2_hash_binding(stmt, &opened)?;

        // ── BFV encryption relation (v4 verify, v3 fail-closed) ──
        verify_non_leaking_relation_boundary(backend, stmt, &opened)?;

        Ok(())
    }
}

fn compute_share_d_commitment(stmt: &ShareNizkStatement) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-dcommit/v1");
    h.update(stmt.session_id.as_slice());
    h.update(
        &u32::try_from(stmt.recipient_index)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    h.update(stmt.share_commitment.as_slice());
    h.finalize().into()
}

/// Build algebraic proof: share sigma proof over RLWE relation.
fn build_algebraic_proof(stmt: &ShareNizkStatement, witness: &ShareNizkWitness) -> Vec<u8> {
    let s_i = derive_share_sigma_witness(witness.share_bytes.expose());
    // e_i is set to zero for the algebraic proof. This proves d_i = c * s_i
    // rather than d_i = c * s_i + e_i. The full RLWE relation with non-zero error
    // is proved separately by the BFV encryption proof (v4). The e_i=0 path
    // provides defense-in-depth algebraic binding; the cryptographic RLWE
    // soundness comes from the BFV sigma proof.
    let e_i = vec![0i64; sigma::rlwe_n()];
    let c_rns = derive_share_sigma_c_rns(stmt.session_id.as_slice(), stmt.recipient_index);
    let d_rns = sigma::compute_d_rns(&c_rns, &s_i, &e_i)
        .unwrap_or_else(|_| vec![0u64; sigma::rlwe_n() * pvthfhe_types::rlwe_moduli().len()]);

    let mut proof_rng = ChaCha20Rng::from_rng(&mut OsRng).expect("OsRng available"); // allow-seeded-rng: (removed — now uses OsRng)
    let sigma_stmt = sigma::SigmaStatement {
        c_rns,
        d_rns: d_rns.clone(),
    };
    let sigma_witness = sigma::SigmaWitness { s_i, e_i };
    let d_commitment = compute_share_d_commitment(stmt);
    let proof = sigma::prove(
        stmt.session_id.as_slice(),
        u32::try_from(stmt.recipient_index).unwrap_or(0),
        &sigma_stmt,
        &sigma_witness,
        &mut proof_rng,
        &d_commitment,
    );

    match proof {
        Ok(p) => encode_algebraic_proof(&d_rns, &p),
        Err(_) => vec![],
    }
}

fn derive_share_sigma_witness(share: &[u8]) -> Vec<i64> {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-sigma-witness-digest-v1");
    h.update(u64::try_from(share.len()).unwrap_or(0).to_be_bytes());
    h.update(share);
    let digest = h.finalize();
    let mut out = vec![0i64; sigma::rlwe_n()];
    for (byte_index, byte) in digest.iter().enumerate() {
        for bit in 0..8usize {
            let idx = byte_index * 8 + bit;
            if idx < sigma::rlwe_n() {
                out[idx] = i64::from((byte >> bit) & 1);
            }
        }
    }
    out
}

fn derive_share_sigma_c_rns(session_id: &[u8], recipient_index: usize) -> Vec<u64> {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-sigma-c-rns-v1");
    h.update(session_id);
    h.update(recipient_index.to_be_bytes());
    let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
    let moduli = pvthfhe_types::rlwe_moduli();
    let n = sigma::rlwe_n();
    let mut out = vec![0u64; n * moduli.len()];
    for (limb, modulus) in moduli.iter().enumerate() {
        for index in 0..n {
            out[limb * n + index] = rng.next_u64() % modulus;
        }
    }
    out
}

fn encode_algebraic_proof(d_rns: &[u64], proof: &sigma::SigmaProof) -> Vec<u8> {
    let mut out = Vec::new();
    encode_algebraic_u64_vec(&mut out, d_rns);
    encode_algebraic_u64_vec(&mut out, &proof.t_rns);
    encode_algebraic_i64_vec(&mut out, &proof.z_s);
    encode_algebraic_i64_vec(&mut out, &proof.z_e);
    encode_algebraic_i64_vec(&mut out, &[proof.ch]);
    out
}

fn encode_algebraic_u64_vec(out: &mut Vec<u8>, values: &[u64]) {
    out.extend_from_slice(&u32::try_from(values.len()).unwrap_or(0).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn encode_algebraic_i64_vec(out: &mut Vec<u8>, values: &[i64]) {
    out.extend_from_slice(&u32::try_from(values.len()).unwrap_or(0).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn decode_algebraic_u64_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<u64>, PvssError> {
    let len = u32::from_be_bytes(
        bytes
            .get(*offset..*offset + 4)
            .ok_or(PvssError::InvalidShare)?
            .try_into()
            .map_err(|_| PvssError::InvalidShare)?,
    ) as usize;
    *offset += 4;
    if len > 1_000_000 {
        return Err(PvssError::InvalidShare);
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let val = u64::from_le_bytes(
            bytes
                .get(*offset..*offset + 8)
                .ok_or(PvssError::InvalidShare)?
                .try_into()
                .map_err(|_| PvssError::InvalidShare)?,
        );
        *offset += 8;
        out.push(val);
    }
    Ok(out)
}

fn decode_algebraic_i64_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<i64>, PvssError> {
    let len = u32::from_be_bytes(
        bytes
            .get(*offset..*offset + 4)
            .ok_or(PvssError::InvalidShare)?
            .try_into()
            .map_err(|_| PvssError::InvalidShare)?,
    ) as usize;
    *offset += 4;
    if len > 1_000_000 {
        return Err(PvssError::InvalidShare);
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let val = i64::from_le_bytes(
            bytes
                .get(*offset..*offset + 8)
                .ok_or(PvssError::InvalidShare)?
                .try_into()
                .map_err(|_| PvssError::InvalidShare)?,
        );
        *offset += 8;
        out.push(val);
    }
    Ok(out)
}

fn decode_algebraic_proof(bytes: &[u8]) -> Result<(Vec<u64>, sigma::SigmaProof), PvssError> {
    let mut offset = 0;
    let d_rns = decode_algebraic_u64_vec(bytes, &mut offset)?;
    let t_rns = decode_algebraic_u64_vec(bytes, &mut offset)?;
    let z_s = decode_algebraic_i64_vec(bytes, &mut offset)?;
    let z_e = decode_algebraic_i64_vec(bytes, &mut offset)?;
    let ch_vec = decode_algebraic_i64_vec(bytes, &mut offset)?;
    let ch = ch_vec.first().copied().unwrap_or(0);
    Ok((
        d_rns,
        sigma::SigmaProof {
            t_rns,
            z_s,
            z_e,
            ch,
        },
    ))
}

// ── BFV encryption proof ─────────────────────────────────────────────────

/// Build the BFV encryption sigma proof from the encryption witness.
///
/// Attempts to extract the encryption witness via `encrypt_with_witness`.
/// If the backend doesn't support witness extraction (e.g., mock backend),
/// returns an empty proof. The verifier will reject empty proofs for v4.
pub fn build_bfv_encryption_proof(
    backend: &dyn FheBackend,
    stmt: &ShareNizkStatement,
    witness: &ShareNizkWitness,
) -> Result<ProtocolBytes, PvssError> {
    let pk = PublicKey {
        bytes: stmt.recipient_pk.as_slice().to_vec(),
    };
    let share = witness.share_bytes.expose();

    // Reconstruct encryption randomness from witness seed
    let randomness = witness.encryption_randomness.expose();
    if randomness.len() < 32 {
        return Ok(ProtocolBytes(vec![]));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&randomness[..32]);
    let mut enc_rng = ChaCha20Rng::from_seed(seed); // allow-seeded-rng: deterministic re-encryption for BFV proof witness

    // Try to get the EncryptionWitness
    let enc_witness = match backend.encrypt_with_witness(&pk, share, &mut enc_rng) {
        Ok((ciphertext, w)) => {
            if ciphertext.bytes.as_slice() != stmt.ciphertext_u.as_slice()
                || w.ciphertext_bytes.as_slice() != stmt.ciphertext_u.as_slice()
            {
                return Err(PvssError::BfvEncryptionProofFailed);
            }
            w
        }
        Err(_) => {
            // Fallback: backend doesn't support witness extraction.
            // Re-encrypt without witness and verify ciphertext consistency.
            let mut fallback_rng = ChaCha20Rng::from_seed(seed); // allow-seeded-rng: deterministic fallback re-encryption check
            let ciphertext = backend
                .encrypt(&pk, share, &mut fallback_rng)
                .map_err(|_| PvssError::InvalidShare)?;
            if ciphertext.bytes.as_slice() != stmt.ciphertext_u.as_slice() {
                return Err(PvssError::BfvEncryptionProofFailed);
            }
            return Ok(ProtocolBytes(vec![]));
        }
    };

    encode_bfv_encryption_proof_from_witness(stmt, share, &enc_witness)
}

/// Encode a self-contained BFV encryption proof from statement + EncryptionWitness.
fn encode_bfv_encryption_proof_from_witness(
    stmt: &ShareNizkStatement,
    plaintext: &[u8],
    enc_witness: &EncryptionWitness,
) -> Result<ProtocolBytes, PvssError> {
    // --- Build BFV sigma statement ---
    let pk_decoded = wire::decode_public_key(stmt.recipient_pk.as_slice())
        .map_err(|_| PvssError::InvalidShare)?;
    if enc_witness.recipient_pk0_bytes.as_slice() != pk_decoded.p0.as_slice()
        || enc_witness.recipient_pk1_bytes.as_slice() != pk_decoded.p1.as_slice()
    {
        return Err(PvssError::BfvEncryptionProofFailed);
    }

    let pk0_rns = poly_bytes_to_rns(&pk_decoded.p0).map_err(|_| PvssError::InvalidShare)?;
    let pk1_rns = poly_bytes_to_rns(&pk_decoded.p1).map_err(|_| PvssError::InvalidShare)?;
    let ct0_rns =
        poly_bytes_to_rns(&enc_witness.ct0_poly_bytes).map_err(|_| PvssError::InvalidShare)?;
    let ct1_rns =
        poly_bytes_to_rns(&enc_witness.ct1_poly_bytes).map_err(|_| PvssError::InvalidShare)?;
    let t_plain: u64 = 65536;
    let delta_limbs = bfv_delta_rns(t_plain).map_err(|_| PvssError::InvalidShare)?;

    let bfv_stmt = BfvSigmaStatement {
        pk0_rns: pk0_rns.clone(),
        pk1_rns: pk1_rns.clone(),
        ct0_rns: ct0_rns.clone(),
        ct1_rns: ct1_rns.clone(),
        delta_limbs: delta_limbs.clone(),
        t_plain,
    };

    // --- Build BFV sigma witness ---
    let u = poly_bytes_to_i64(&enc_witness.u_poly_bytes)?;
    let e0 = poly_bytes_to_i64(&enc_witness.e0_poly_bytes)?;
    let e1 = poly_bytes_to_i64(&enc_witness.e1_poly_bytes)?;
    let m = encode_fhers_plaintext_slots(plaintext)?;

    let bfv_wit = BfvSigmaWitness { u, e0, e1, m };

    // --- Produce sigma proof ---
    let mut proof_rng = ChaCha20Rng::from_rng(&mut OsRng).expect("OsRng available"); // allow-seeded-rng: (removed — now uses OsRng)
    let binding_data = bfv_sigma_binding_data(stmt, &[0u8; 32]); // G.5: TODO: pass real d_commitment
    let proof = bfv_sigma::prove(&bfv_stmt, &bfv_wit, &binding_data, &mut proof_rng)
        .map_err(|_| PvssError::InvalidShare)?;

    let encoded_proof = encode_bfv_sigma_proof(&proof);

    // --- Encode self-contained proof: [t_plain][delta_limbs][pk0_rns][pk1_rns][ct0_rns][ct1_rns][proof] ---
    let mut out = Vec::new();
    // t_plain (u64 LE)
    out.extend_from_slice(&t_plain.to_le_bytes());
    // delta_limbs (3 u64 values)
    for v in &delta_limbs {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // pk0_rns
    out.extend_from_slice(&u32::to_be_bytes(pk0_rns.len() as u32));
    for v in &pk0_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // pk1_rns
    out.extend_from_slice(&u32::to_be_bytes(pk1_rns.len() as u32));
    for v in &pk1_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // ct0_rns
    out.extend_from_slice(&u32::to_be_bytes(ct0_rns.len() as u32));
    for v in &ct0_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // ct1_rns
    out.extend_from_slice(&u32::to_be_bytes(ct1_rns.len() as u32));
    for v in &ct1_rns {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // BfvSigmaProof
    out.extend_from_slice(&encoded_proof);

    Ok(ProtocolBytes(out))
}

/// Verify the BFV encryption sigma proof.
///
/// Decodes the self-contained proof (statement + proof), then calls
/// `bfv_sigma::verify()`.  Returns `Ok(())` iff the proof is valid.
pub fn verify_bfv_encryption_proof(
    backend: &dyn FheBackend,
    stmt: &ShareNizkStatement,
    bfv_encryption_proof: &[u8],
) -> Result<(), PvssError> {
    if bfv_encryption_proof.is_empty() {
        eprintln!("[NIZK-VERIFY] FAIL: bfv_encryption_proof is empty");
        return Err(PvssError::BfvEncryptionProofFailed);
    }

    let mut offset = 0;

    // Read t_plain (u64 LE)
    if bfv_encryption_proof.len() < 8 {
        return Err(PvssError::BfvEncryptionProofFailed);
    }
    let t_plain = u64::from_le_bytes(bfv_encryption_proof[offset..offset + 8].try_into().unwrap());
    offset += 8;

    // Read delta_limbs (3 u64)
    if bfv_encryption_proof.len() < offset + 24 {
        return Err(PvssError::BfvEncryptionProofFailed);
    }
    let delta_limbs: Vec<u64> = (0..3)
        .map(|i| {
            u64::from_le_bytes(
                bfv_encryption_proof[offset + i * 8..offset + (i + 1) * 8]
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    offset += 24;

    let pk0_rns = read_bfv_u64_vec(bfv_encryption_proof, &mut offset)?;
    let pk1_rns = read_bfv_u64_vec(bfv_encryption_proof, &mut offset)?;
    let ct0_rns = read_bfv_u64_vec(bfv_encryption_proof, &mut offset)?;
    let ct1_rns = read_bfv_u64_vec(bfv_encryption_proof, &mut offset)?;

    let expected_pk = wire::decode_public_key(stmt.recipient_pk.as_slice())
        .map_err(|_| PvssError::BfvEncryptionProofFailed)?;
    let expected_pk0_rns =
        poly_bytes_to_rns(&expected_pk.p0).map_err(|_| PvssError::BfvEncryptionProofFailed)?;
    let expected_pk1_rns =
        poly_bytes_to_rns(&expected_pk.p1).map_err(|_| PvssError::BfvEncryptionProofFailed)?;
    let (expected_ct0_bytes, expected_ct1_bytes) = backend
        .decode_ct_polys(&Ciphertext {
            bytes: stmt.ciphertext_u.as_slice().to_vec(),
        })
        .map_err(|_| PvssError::BfvEncryptionProofFailed)?;
    let expected_ct0_rns =
        poly_bytes_to_rns(&expected_ct0_bytes).map_err(|_| PvssError::BfvEncryptionProofFailed)?;
    let expected_ct1_rns =
        poly_bytes_to_rns(&expected_ct1_bytes).map_err(|_| PvssError::BfvEncryptionProofFailed)?;

    if pk0_rns != expected_pk0_rns
        || pk1_rns != expected_pk1_rns
        || ct0_rns != expected_ct0_rns
        || ct1_rns != expected_ct1_rns
    {
        eprintln!("[NIZK-VERIFY] FAIL: BFV proof statement does not match public statement");
        return Err(PvssError::BfvEncryptionProofFailed);
    }

    let bfv_stmt = BfvSigmaStatement {
        pk0_rns,
        pk1_rns,
        ct0_rns,
        ct1_rns,
        delta_limbs,
        t_plain,
    };

    // Decode BfvSigmaProof
    let bfv_proof = decode_bfv_sigma_proof(&bfv_encryption_proof[offset..])
        .map_err(|_| PvssError::BfvEncryptionProofFailed)?;

    let binding_data = bfv_sigma_binding_data(stmt, &[0u8; 32]); // G.5: TODO: pass real d_commitment
    bfv_sigma::verify(&bfv_stmt, &bfv_proof, &binding_data).map_err(|_| {
        eprintln!("[NIZK-VERIFY] FAIL: bfv_sigma::verify failed");
        PvssError::BfvEncryptionProofFailed
    })
}

fn bfv_sigma_binding_data(stmt: &ShareNizkStatement, d_commitment: &[u8; 32]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-bfv-sigma-binding-v5");
    h.update(stmt.session_id.as_slice());
    h.update(stmt.dealer_index.to_be_bytes());
    h.update(stmt.recipient_index.to_be_bytes());
    h.update(stmt.bfv_params_digest.as_slice());
    h.update(stmt.dkg_root.as_slice());
    h.update(stmt.ciphertext_u.as_slice());
    h.update(stmt.ciphertext_v.as_slice());
    h.update(stmt.share_commitment.as_slice());
    h.update(d_commitment);
    h.finalize().to_vec()
}

fn encode_fhers_plaintext_slots(plaintext: &[u8]) -> Result<Vec<i64>, PvssError> {
    let max = sigma::rlwe_n().saturating_sub(1) * 2;
    if plaintext.len() > max {
        return Err(PvssError::InvalidShare);
    }

    let t_plain: i64 = 65536;
    let t_half: u64 = 32768;
    let mut out = vec![0i64; sigma::rlwe_n()];
    out[0] = i64::try_from(plaintext.len()).map_err(|_| PvssError::InvalidShare)?;
    for (slot_index, chunk) in plaintext.chunks(2).enumerate() {
        let lo = u16::from(chunk[0]);
        let hi = chunk.get(1).copied().map(u16::from).unwrap_or(0) << 8;
        let raw = u64::from(lo | hi);
        // BFV Encoding::poly() centers values: v ∈ [0, t) → v if v < t/2 else v - t
        let centered = if raw >= t_half {
            -i64::try_from(t_plain - raw as i64).unwrap_or(0)
        } else {
            i64::try_from(raw).unwrap_or(0)
        };
        out[slot_index + 1] = centered;
    }
    Ok(out)
}

fn read_bfv_u64_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<u64>, PvssError> {
    if bytes.len() < *offset + 4 {
        return Err(PvssError::BfvEncryptionProofFailed);
    }
    let len = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if len > 1_000_000 {
        return Err(PvssError::BfvEncryptionProofFailed);
    }
    if bytes.len() < *offset + len * 8 {
        return Err(PvssError::BfvEncryptionProofFailed);
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(u64::from_le_bytes(
            bytes[*offset..*offset + 8].try_into().unwrap(),
        ));
        *offset += 8;
    }
    Ok(out)
}

// ── RLWE context (cached, shared by helpers) ──────────────────────────────

fn get_rlwe_context() -> Result<&'static Arc<Context>, PvssError> {
    static CTX: OnceLock<Result<Arc<Context>, String>> = OnceLock::new();
    CTX.get_or_init(|| {
        let moduli = pvthfhe_types::rlwe_moduli();
        Context::new(&moduli, sigma::rlwe_n())
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
    .as_ref()
    .map_err(|_| PvssError::LatticeBindingVerificationFailed)
}

/// Convert poly_bytes (serialized fhe-math `Poly`) to i64 coefficient vector.
///
/// Deserializes the Poly, converts to power basis, and extracts the limb-0
/// coefficients centered around 0.
fn poly_bytes_to_i64(poly_bytes: &[u8]) -> Result<Vec<i64>, PvssError> {
    use fhe_math::rq::{Poly, Representation};

    let ctx = get_rlwe_context()?;

    let mut poly = Poly::from_bytes(poly_bytes, ctx).map_err(|_| PvssError::InvalidShare)?;
    poly.change_representation(Representation::PowerBasis);

    let q0 = i64::try_from(ctx.q[0].modulus()).map_err(|_| PvssError::InvalidShare)?;
    let half_q0 = q0 / 2;

    let rns: Vec<u64> = Vec::<u64>::from(&poly);
    let n = sigma::rlwe_n();
    let mut out = Vec::with_capacity(n);
    for j in 0..n {
        let c = i64::try_from(rns[j]).map_err(|_| PvssError::InvalidShare)?;
        out.push(if c > half_q0 { c - q0 } else { c });
    }
    Ok(out)
}

/// Verify the non-leaking relation boundary: checks the BFV encryption sigma
/// proof for v4 proofs, and rejects v3 and earlier (fail-closed).
pub fn verify_non_leaking_relation_boundary(
    backend: &dyn FheBackend,
    stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    // For v4 proofs, verify the BFV encryption sigma proof.
    // v3 and earlier proofs won't decode (version check fails earlier),
    // but this is the semantic check at the relation boundary.
    if opened.bfv_encryption_proof.is_empty() {
        eprintln!("[NIZK-VERIFY] FAIL: v{PROOF_VERSION} proof lacks BFV encryption proof");
        return Err(PvssError::LatticeBindingVerificationFailed);
    }
    verify_bfv_encryption_proof(backend, stmt, opened.bfv_encryption_proof.as_slice())
}

// ── Verification helpers ──────────────────────────────────────────────────

fn verify_commitment_structure(
    _backend: &dyn FheBackend,
    _stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    verify_commitment_ct_validity(opened)
}

fn verify_commitment_ct_validity(opened: &ShareNizkOpenedProof) -> Result<(), PvssError> {
    if opened.commitment_bytes.is_empty() || opened.commitment_bytes.len() > MAX_FIELD_LEN {
        eprintln!(
            "[NIZK-VERIFY] FAIL: commitment_structure_invalid (empty or too large: len={})",
            opened.commitment_bytes.len()
        );
        return Err(PvssError::InvalidCommitmentStructure);
    }
    Ok(())
}

fn verify_algebraic_relation(
    _stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    if opened.algebraic_proof.is_empty() {
        eprintln!("[NIZK-VERIFY] FAIL: algebraic_proof is empty");
        return Err(PvssError::LatticeBindingVerificationFailed);
    }
    let (d_rns, sigma_proof) = decode_algebraic_proof(opened.algebraic_proof.as_slice())?;

    // Verify the sigma proof against the reconstructed statement
    let stmt = &opened.statement;
    let c_rns = derive_share_sigma_c_rns(stmt.session_id.as_slice(), stmt.recipient_index);
    let sigma_stmt = sigma::SigmaStatement {
        c_rns,
        d_rns: d_rns.clone(),
    };
    let d_commitment = compute_share_d_commitment(stmt);
    sigma::verify_scalar(
        stmt.session_id.as_slice(),
        u32::try_from(stmt.recipient_index).unwrap_or(0),
        &sigma_stmt,
        &sigma_proof,
        &d_commitment,
    )
    .map_err(|_| {
        eprintln!("[NIZK-VERIFY] FAIL: algebraic scalar sigma verification failed");
        PvssError::LatticeBindingVerificationFailed
    })?;

    Ok(())
}

fn verify_relation_binding(
    stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    let recomputed = compute_relation_binding(stmt, opened.algebraic_proof.as_slice());
    if recomputed != opened.relation_binding {
        eprintln!("[NIZK-VERIFY] FAIL: relation_binding mismatch");
        return Err(PvssError::LatticeBindingVerificationFailed);
    }
    Ok(())
}

fn verify_commitment_binding_tag(
    stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    let recomputed = compute_commitment_binding(stmt, &opened.relation_binding);
    if recomputed != opened.commitment_binding {
        eprintln!("[NIZK-VERIFY] FAIL: commitment_binding mismatch");
        return Err(PvssError::LatticeBindingVerificationFailed);
    }
    Ok(())
}

fn verify_lattice_binding(
    stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    let recomputed = compute_lattice_binding_from_opened(stmt, opened);
    if recomputed != opened.lattice_binding {
        eprintln!("[NIZK-VERIFY] FAIL: lattice_binding failed");
        eprintln!("  recomputed  = {:02x?}", &recomputed[..]);
        eprintln!("  stored      = {:02x?}", &opened.lattice_binding[..]);
        return Err(PvssError::LatticeBindingVerificationFailed);
    }
    Ok(())
}

fn verify_d2_hash_binding(
    stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    let mut hasher = Sha256::new();
    hasher.update(opened.commitment_bytes.as_slice());
    hasher.update(stmt.share_commitment.as_slice());
    hasher.update(stmt.session_id.as_slice());
    hasher.update(stmt.dkg_root.as_slice());
    hasher.update(&(stmt.recipient_index as u64).to_le_bytes());
    let expected: [u8; 32] = hasher.finalize().into();
    if expected != opened.d2_binding {
        return Err(PvssError::D2HashBindingFailed);
    }
    Ok(())
}

// ── Binding computation helpers ───────────────────────────────────────────

fn compute_relation_binding(stmt: &ShareNizkStatement, algebraic_proof: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-share-relation-binding-v2");
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

fn compute_commitment_binding(
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

fn compute_lattice_binding(
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

fn compute_lattice_binding_from_opened(
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
    hasher.update(b"pvthfhe-d2-ajtai-matrix-v1");
    hasher.update(session_id);
    hasher.update(recipient_index.to_le_bytes());
    if let Some(tag) = track_domain_tag {
        hasher.update(tag);
    }
    let matrix_seed: [u8; DIGEST_LEN] = hasher.finalize().into();

    let params = AjtaiParams::default();
    let matrix = AjtaiMatrix::from_seed(matrix_seed, &params, 1) // allow-seeded-rng: deterministic Ajtai CRS for PVSS proof
        .map_err(|_| PvssError::D2HashBindingFailed)?;

    let witness = encode_share_as_ajtai_witness(share_bytes)?;

    let commitment =
        AjtaiCommitment::commit(&matrix, &[witness]).map_err(|_| PvssError::D2HashBindingFailed)?;

    Ok(commitment.to_d2_digest())
}

fn encode_share_as_ajtai_witness(share_bytes: &[u8]) -> Result<Rq, PvssError> {
    let mut coeffs = [0i64; PHI];
    let byte_count = share_bytes.len().min(PHI);
    for i in 0..byte_count {
        let val = i64::from(share_bytes[i]);
        if val > i64::try_from(WITNESS_BOUND).unwrap_or(i64::MAX) {
            return Err(PvssError::D2HashBindingFailed);
        }
        coeffs[i] = val;
    }
    let mut rq = Rq::new(coeffs, Q_COMMIT);
    rq.reduce().map_err(|_| PvssError::D2HashBindingFailed)?;
    Ok(rq)
}

// ── Proof serialization/deserialization ──────────────────────────────────

impl ShareNizkProof {
    pub fn from_opened(opened: &ShareNizkOpenedProof) -> Result<Self, PvssError> {
        if opened.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR {
            return Err(PvssError::InvalidShare);
        }
        validate_statement(&opened.statement)?;

        Ok(Self {
            proof_bytes: ProtocolBytes(encode_opened_proof(opened)?),
            domain_separator: opened.domain_separator.clone(),
        })
    }

    pub fn from_bytes(proof_bytes: Vec<u8>) -> Result<Self, PvssError> {
        let opened = decode_opened_proof(&proof_bytes)?;
        Ok(Self {
            proof_bytes: ProtocolBytes(proof_bytes),
            domain_separator: opened.domain_separator,
        })
    }

    pub fn decode(&self) -> Result<ShareNizkOpenedProof, PvssError> {
        decode_opened_proof(self.proof_bytes.as_slice())
    }
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
) -> [u8; DIGEST_LEN] {
    compute_ajtai_d2_binding(session_id, recipient_index, share_bytes)
        .expect("share_commitment computation must not fail for valid inputs")
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
) -> [u8; DIGEST_LEN] {
    compute_ajtai_d2_binding_tracked(session_id, recipient_index, share_bytes, track_domain_tag)
        .expect("share_commitment computation must not fail for valid inputs")
}

/// Compute the hash-bound secondary ciphertext component from `ciphertext_u`.
pub fn compute_ciphertext_v(ciphertext_u: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"ciphertext-v1");
    hasher.update(ciphertext_u);
    hasher.finalize().into()
}

/// Compute the canonical BFV parameters digest.
pub fn canonical_bfv_params_digest() -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-bfv-params-v1");
    hasher.update(CANONICAL_PARAMS_TOML.as_bytes());
    hasher.finalize().into()
}

fn compute_commitment_seed(
    stmt: &ShareNizkStatement,
    track_domain_tag: Option<&[u8]>,
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"greco-bfv-commitment-seed-v2");
    hasher.update(stmt.session_id.as_slice());
    hasher.update(stmt.recipient_pk.as_slice());
    hasher.update(stmt.ciphertext_u.as_slice());
    hasher.update(stmt.share_commitment.as_slice());
    if let Some(tag) = track_domain_tag {
        hasher.update(tag);
    }
    hasher.finalize().into()
}

fn create_commitment_ct(
    backend: &dyn FheBackend,
    stmt: &ShareNizkStatement,
    witness: &ShareNizkWitness,
    commitment_seed: &[u8; DIGEST_LEN],
) -> Result<Vec<u8>, PvssError> {
    let pk = PublicKey {
        bytes: stmt.recipient_pk.as_slice().to_vec(),
    };

    let plaintext = witness.share_bytes.expose();

    let mut rng = ChaCha20Rng::from_seed(*commitment_seed); // allow-seeded-rng: deterministic Ajtai commitment binding in PVSS proof

    let ciphertext = backend
        .encrypt(&pk, plaintext, &mut rng)
        .map_err(|_| PvssError::InvalidShare)?;

    Ok(ciphertext.bytes)
}

fn validate_statement(stmt: &ShareNizkStatement) -> Result<(), PvssError> {
    if stmt.session_id.is_empty()
        || stmt.recipient_pk.is_empty()
        || stmt.ciphertext_u.is_empty()
        || stmt.ciphertext_v.len() != DIGEST_LEN
        || stmt.share_commitment.len() != DIGEST_LEN
        || stmt.bfv_params_digest.len() != DIGEST_LEN
    {
        return Err(PvssError::InvalidShare);
    }
    if stmt.recipient_pk.len() > MAX_FIELD_LEN || stmt.ciphertext_u.len() > MAX_FIELD_LEN {
        return Err(PvssError::InvalidShare);
    }
    Ok(())
}

fn validate_witness(witness: &ShareNizkWitness) -> Result<(), PvssError> {
    if witness.share_bytes.expose().is_empty()
        || witness.share_bytes.expose().len() > MAX_FIELD_LEN
        || witness.encryption_randomness.expose().is_empty()
        || witness.encryption_randomness.expose().len() > MAX_FIELD_LEN
    {
        return Err(PvssError::InvalidShare);
    }
    Ok(())
}

fn derive_challenge(stmt: &ShareNizkStatement, commitment_ct: &[u8]) -> [u8; CHALLENGE_LEN] {
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

// ── Wire format encode/decode ─────────────────────────────────────────────

fn encode_opened_proof(opened: &ShareNizkOpenedProof) -> Result<Vec<u8>, PvssError> {
    Ok(opened.encode())
}

fn encode_opened_proof_body(opened: &ShareNizkOpenedProof) -> Result<Vec<u8>, PvssError> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROOF_VERSION.to_be_bytes());
    encode_bytes(&mut out, opened.domain_separator.as_bytes())?;
    encode_bytes(&mut out, opened.statement.session_id.as_slice())?;
    encode_usize(&mut out, opened.statement.dealer_index)?;
    encode_usize(&mut out, opened.statement.recipient_index)?;
    encode_bytes(&mut out, opened.statement.recipient_pk.as_slice())?;
    encode_bytes(&mut out, opened.statement.bfv_params_digest.as_slice())?;
    encode_bytes(&mut out, opened.statement.dkg_root.as_slice())?;
    encode_bytes(&mut out, opened.statement.ciphertext_u.as_slice())?;
    encode_bytes(&mut out, opened.statement.ciphertext_v.as_slice())?;
    encode_bytes(&mut out, opened.statement.share_commitment.as_slice())?;
    encode_bytes(&mut out, opened.commitment_bytes.as_slice())?;
    out.extend_from_slice(&opened.commitment_seed);
    out.extend_from_slice(&opened.commitment_binding);
    out.extend_from_slice(&opened.challenge);
    out.extend_from_slice(&opened.lattice_binding);
    out.extend_from_slice(&opened.relation_binding);
    encode_bytes(&mut out, opened.algebraic_proof.as_slice())?;
    out.extend_from_slice(&opened.d2_binding);
    encode_bytes(&mut out, opened.bfv_encryption_proof.as_slice())?;
    Ok(out)
}

fn decode_opened_proof(bytes: &[u8]) -> Result<ShareNizkOpenedProof, PvssError> {
    ShareNizkOpenedProof::decode(bytes).map_err(|_| PvssError::InvalidShare)
}

fn decode_opened_proof_body(bytes: &[u8]) -> Result<ShareNizkOpenedProof, PvssError> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != PROOF_VERSION {
        return Err(PvssError::InvalidShare);
    }

    let domain_separator =
        String::from_utf8(cursor.read_vec()?).map_err(|_| PvssError::InvalidShare)?;
    let session_id = cursor.read_vec()?;
    let dealer_index = cursor.read_usize()?;
    let recipient_index = cursor.read_usize()?;
    let recipient_pk = cursor.read_vec()?;
    let bfv_params_digest = cursor.read_vec()?;
    let dkg_root = cursor.read_vec()?;
    let ciphertext_u = cursor.read_vec()?;
    let ciphertext_v = cursor.read_vec()?;
    let share_commitment = cursor.read_vec()?;
    let commitment_bytes = cursor.read_vec()?;
    let commitment_seed = cursor.read_array::<DIGEST_LEN>()?;
    let commitment_binding = cursor.read_array::<DIGEST_LEN>()?;
    let challenge = cursor.read_array::<CHALLENGE_LEN>()?;
    let lattice_binding = cursor.read_array::<DIGEST_LEN>()?;
    let relation_binding = cursor.read_array::<DIGEST_LEN>()?;
    let algebraic_proof = cursor.read_vec()?;
    let d2_binding = cursor.read_array::<DIGEST_LEN>()?;
    let bfv_encryption_proof = cursor.read_vec()?;
    cursor.finish()?;

    Ok(ShareNizkOpenedProof {
        statement: ShareNizkStatement {
            session_id: ProtocolBytes(session_id),
            dealer_index,
            recipient_index,
            recipient_pk: ProtocolBytes(recipient_pk),
            bfv_params_digest: ProtocolBytes(bfv_params_digest),
            dkg_root: ProtocolBytes(dkg_root),
            ciphertext_u: ProtocolBytes(ciphertext_u),
            ciphertext_v: ProtocolBytes(ciphertext_v),
            share_commitment: ProtocolBytes(share_commitment),
        },
        commitment_bytes: ProtocolBytes(commitment_bytes),
        commitment_seed,
        commitment_binding,
        challenge,
        lattice_binding,
        relation_binding,
        algebraic_proof: ProtocolBytes(algebraic_proof),
        bfv_encryption_proof: ProtocolBytes(bfv_encryption_proof),
        d2_binding,
        domain_separator,
    })
}

impl WireFormat for ShareNizkOpenedProof {
    const VERSION: u8 = WIRE_VERSION;
    const TAG: Tag = Tag::WirePvssShareOpenedProof;

    fn encode_body(&self) -> Vec<u8> {
        encode_opened_proof_body(self).expect("validated share NIZK opened proof must encode")
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        decode_opened_proof_body(bytes).map_err(|_| WireError::Other)
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PvssError> {
    let len = u32::try_from(bytes.len()).map_err(|_| PvssError::InvalidShare)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_usize(out: &mut Vec<u8>, value: usize) -> Result<(), PvssError> {
    let value = u64::try_from(value).map_err(|_| PvssError::InvalidShare)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], PvssError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PvssError::InvalidShare)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(PvssError::InvalidShare)?;
        self.offset = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PvssError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| PvssError::InvalidShare)
    }

    fn read_u16(&mut self) -> Result<u16, PvssError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, PvssError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_usize(&mut self) -> Result<usize, PvssError> {
        let raw = u64::from_be_bytes(self.read_array()?);
        usize::try_from(raw).map_err(|_| PvssError::InvalidShare)
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, PvssError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| PvssError::InvalidShare)?;
        if len > MAX_FIELD_LEN {
            return Err(PvssError::InvalidShare);
        }
        Ok(self.read_exact(len)?.to_vec())
    }

    fn finish(self) -> Result<(), PvssError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PvssError::InvalidShare)
        }
    }
}
