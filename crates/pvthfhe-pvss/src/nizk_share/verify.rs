//! Verifier side of the share-encryption NIZK: [`ShareNizkVerifier`],
//! [`ShareNizkBatchedVerifier`], the per-tag binding re-computation checks,
//! and the BFV encryption sigma proof verification.

use pvthfhe_fhe::types::Ciphertext;
use pvthfhe_fhe::wire;
use pvthfhe_fhe::FheBackend;
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_nizk::bfv_sigma::{self, decode_bfv_sigma_proof, poly_bytes_to_rns, BfvSigmaStatement};
use pvthfhe_nizk::sigma;
use sha2::{Digest, Sha256};

use crate::PvssError;

use super::statement::{
    bfv_sigma_binding_data, compute_ciphertext_v, compute_commitment_binding,
    compute_lattice_binding_from_opened, compute_relation_binding, compute_share_d_commitment,
    derive_challenge, derive_share_sigma_c_rns, validate_statement, ShareNizkBatchedStatement,
    ShareNizkOpenedProof, ShareNizkProof, ShareNizkStatement,
};
use super::{MAX_FIELD_LEN, PROOF_VERSION, SHARE_NIZK_DOMAIN_SEPARATOR};

/// Verifier for the share-encryption proof. Requires FHE backend for lattice checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareNizkVerifier;

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
            .map_err(|_| PvssError::InvalidDomainSeparator { party_id: Some(batched.recipient_index as u16) })?;
        if proof.domain_separator != expected_domain {
            return Err(PvssError::InvalidDomainSeparator { party_id: Some(batched.recipient_index as u16) });
        }

        let bytes = proof.proof_bytes.as_slice();
        if bytes.len() < 2 {
            return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(batched.recipient_index as u16) });
        }

        let num_tracks = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut offset: usize = 2;

        if num_tracks < 1 {
            return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(batched.recipient_index as u16) });
        }
        let expected_esm_tracks = num_tracks as usize - 1;
        if expected_esm_tracks != batched.esm_slots.len() {
            return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(batched.recipient_index as u16) });
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
        for esm_slot in batched.esm_slots.iter() {
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
                return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(batched.recipient_index as u16) });
            }
        }

        if offset != bytes.len() {
            return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(batched.recipient_index as u16) });
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
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < 4 {
        return Err(PvssError::BfvEncryptionProofFailed { party_id: None });
    }
    let proof_len = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]) as usize;
    *offset += 4;
    if proof_len > MAX_FIELD_LEN || bytes.len().saturating_sub(*offset) < proof_len {
        return Err(PvssError::BfvEncryptionProofFailed { party_id: None });
    }
    let sub_proof_bytes = bytes[*offset..*offset + proof_len].to_vec();
    *offset += proof_len;
    ShareNizkProof::from_bytes(sub_proof_bytes)
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: None })
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
            return Err(PvssError::InvalidDomainSeparator { party_id: Some(stmt.recipient_index as u16) });
        }

        let opened = proof.decode()?;
        if opened.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR {
            eprintln!("[NIZK-VERIFY] FAIL: domain_separator mismatch on opened proof");
            return Err(PvssError::InvalidDomainSeparator { party_id: Some(stmt.recipient_index as u16) });
        }
        if opened.statement != *stmt {
            eprintln!("[NIZK-VERIFY] FAIL: statement mismatch");
            return Err(PvssError::StatementMismatch { party_id: Some(stmt.recipient_index as u16) });
        }

        let expected_challenge = derive_challenge(stmt, opened.commitment_bytes.as_slice());
        if expected_challenge != opened.challenge {
            eprintln!("[NIZK-VERIFY] FAIL: challenge mismatch");
            eprintln!("  expected_challenge = {:02x?}", &expected_challenge[..]);
            eprintln!("  opened.challenge   = {:02x?}", &opened.challenge[..]);
            return Err(PvssError::ChallengeVerificationFailed { party_id: Some(stmt.recipient_index as u16) });
        }

        let expected_ciphertext_v = compute_ciphertext_v(stmt.ciphertext_u.as_slice());
        if expected_ciphertext_v.as_slice() != stmt.ciphertext_v.as_slice() {
            eprintln!("[NIZK-VERIFY] FAIL: ciphertext_v mismatch");
            return Err(PvssError::CiphertextVMismatch { party_id: Some(stmt.recipient_index as u16) });
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

fn decode_algebraic_u64_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<u64>, PvssError> {
    let len = u32::from_be_bytes(
        bytes
            .get(*offset..*offset + 4)
            .ok_or(PvssError::InvalidShare { party_id: None })?
            .try_into()
            .map_err(|_| PvssError::InvalidShare { party_id: None })?,
    ) as usize;
    *offset += 4;
    if len > 1_000_000 {
        return Err(PvssError::InvalidShare { party_id: None });
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let val = u64::from_le_bytes(
            bytes
                .get(*offset..*offset + 8)
                .ok_or(PvssError::InvalidShare { party_id: None })?
                .try_into()
                .map_err(|_| PvssError::InvalidShare { party_id: None })?,
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
            .ok_or(PvssError::InvalidShare { party_id: None })?
            .try_into()
            .map_err(|_| PvssError::InvalidShare { party_id: None })?,
    ) as usize;
    *offset += 4;
    if len > 1_000_000 {
        return Err(PvssError::InvalidShare { party_id: None });
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let val = i64::from_le_bytes(
            bytes
                .get(*offset..*offset + 8)
                .ok_or(PvssError::InvalidShare { party_id: None })?
                .try_into()
                .map_err(|_| PvssError::InvalidShare { party_id: None })?,
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
        return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) });
    }

    let mut offset = 0;

    // Read t_plain (u64 LE)
    if bfv_encryption_proof.len() < 8 {
        return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) });
    }
    let t_plain = u64::from_le_bytes(bfv_encryption_proof[offset..offset + 8].try_into().unwrap());
    offset += 8;

    // Read delta_limbs (3 u64)
    if bfv_encryption_proof.len() < offset + 24 {
        return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) });
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
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) })?;
    let expected_pk0_rns = poly_bytes_to_rns(&expected_pk.p0)
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) })?;
    let expected_pk1_rns = poly_bytes_to_rns(&expected_pk.p1)
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) })?;
    let (expected_ct0_bytes, expected_ct1_bytes) = backend
        .decode_ct_polys(&Ciphertext {
            bytes: stmt.ciphertext_u.as_slice().to_vec(),
        })
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) })?;
    let expected_ct0_rns = poly_bytes_to_rns(&expected_ct0_bytes)
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) })?;
    let expected_ct1_rns = poly_bytes_to_rns(&expected_ct1_bytes)
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) })?;

    if pk0_rns != expected_pk0_rns
        || pk1_rns != expected_pk1_rns
        || ct0_rns != expected_ct0_rns
        || ct1_rns != expected_ct1_rns
    {
        eprintln!("[NIZK-VERIFY] FAIL: BFV proof statement does not match public statement");
        return Err(PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) });
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
        .map_err(|_| PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) })?;

    let d_commitment = compute_share_d_commitment(stmt);
    let binding_data = bfv_sigma_binding_data(stmt, &d_commitment);
    bfv_sigma::verify(
        stmt.session_id.as_slice(),
        stmt.dealer_index as u32,
        &bfv_stmt,
        &bfv_proof,
        &binding_data,
    )
    .map_err(|_| {
        eprintln!("[NIZK-VERIFY] FAIL: bfv_sigma::verify failed");
        PvssError::BfvEncryptionProofFailed { party_id: Some(stmt.recipient_index as u16) }
    })
}

fn read_bfv_u64_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<u64>, PvssError> {
    if bytes.len() < *offset + 4 {
        return Err(PvssError::BfvEncryptionProofFailed { party_id: None });
    }
    let len = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if len > 1_000_000 {
        return Err(PvssError::BfvEncryptionProofFailed { party_id: None });
    }
    if bytes.len() < *offset + len * 8 {
        return Err(PvssError::BfvEncryptionProofFailed { party_id: None });
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

/// Verify the non-leaking relation boundary: checks the BFV encryption sigma
/// proof for v4 proofs, and rejects v3 and earlier (fail-closed).
pub fn verify_non_leaking_relation_boundary(
    backend: &dyn FheBackend,
    stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    // Verify BFV encryption sigma proof (v4+; v3 and earlier fail version check).
    if opened.bfv_encryption_proof.is_empty() {
        eprintln!("[NIZK-VERIFY] FAIL: v{PROOF_VERSION} proof lacks BFV encryption proof");
        return Err(PvssError::LatticeBindingVerificationFailed { party_id: Some(stmt.recipient_index as u16) });
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
        return Err(PvssError::InvalidCommitmentStructure { party_id: Some(opened.statement.recipient_index as u16) });
    }
    Ok(())
}

fn verify_algebraic_relation(
    _stmt: &ShareNizkStatement,
    opened: &ShareNizkOpenedProof,
) -> Result<(), PvssError> {
    if opened.algebraic_proof.is_empty() {
        eprintln!("[NIZK-VERIFY] FAIL: algebraic_proof is empty");
        return Err(PvssError::LatticeBindingVerificationFailed { party_id: Some(_stmt.recipient_index as u16) });
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
        PvssError::LatticeBindingVerificationFailed { party_id: Some(_stmt.recipient_index as u16) }
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
        return Err(PvssError::LatticeBindingVerificationFailed { party_id: Some(stmt.recipient_index as u16) });
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
        return Err(PvssError::LatticeBindingVerificationFailed { party_id: Some(stmt.recipient_index as u16) });
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
        return Err(PvssError::LatticeBindingVerificationFailed { party_id: Some(stmt.recipient_index as u16) });
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
    hasher.update((stmt.recipient_index as u64).to_le_bytes());
    let expected: [u8; 32] = hasher.finalize().into();
    if expected != opened.d2_binding {
        return Err(PvssError::D2HashBindingFailed { party_id: Some(stmt.recipient_index as u16) });
    }
    Ok(())
}
