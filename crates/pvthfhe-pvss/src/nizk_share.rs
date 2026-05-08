//! Share-encryption NIZK built on the shared Fiat-Shamir transcript.
//!
//! **Research prototype — conditional soundness only.**
//! This module implements a commitment-binding Fiat-Shamir proof that binds the
//! share bytes, ciphertext components, and recipient public key via a hash chain.
//! It does NOT implement the full Sigma+Ajtai+BFV joint-extractor relation
//! described in P3-pvss; that obligation is tracked in the assumptions ledger
//! under `pvss-bfv-composition` (status: GoWithCaveat, extractor unproven).
//! The proof envelopes carry witness material and are NOT zero-knowledge.

use pvthfhe_nizk::fiat_shamir::Transcript;
use sha2::{Digest, Sha256};

use crate::PvssError;

/// Locked domain separator for PVSS share-encryption proofs.
pub const SHARE_NIZK_DOMAIN_SEPARATOR: &str = "pvthfhe-pvss-share-encryption-v1";

const PROOF_VERSION: u16 = 1;
const CHALLENGE_LEN: usize = 32;
const DIGEST_LEN: usize = 32;
const SHARE_COEFF_BOUND: i16 = 255;
const MAX_FIELD_LEN: usize = 1 << 20;

/// Public statement for one share-encryption proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkStatement {
    /// Session binding bytes.
    pub session_id: Vec<u8>,
    /// Zero-based dealer index bound into the transcript.
    pub dealer_index: usize,
    /// Zero-based recipient index bound into the transcript and commitment.
    pub recipient_index: usize,
    /// Recipient public-key bytes for the encrypted share.
    pub recipient_pk: Vec<u8>,
    /// Primary ciphertext bytes produced by the BFV backend.
    pub ciphertext_u: Vec<u8>,
    /// Hash-bound secondary ciphertext component.
    pub ciphertext_v: Vec<u8>,
    /// Share commitment bytes.
    pub share_commitment: Vec<u8>,
}

/// Secret witness for one share-encryption proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkWitness {
    /// Serialized share bytes.
    pub share_bytes: Vec<u8>,
    /// Deterministic encryption randomness binding bytes.
    pub encryption_randomness: Vec<u8>,
}

/// Serialized proof envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkProof {
    /// Serialized proof payload.
    pub proof_bytes: Vec<u8>,
    /// Domain separator recorded in the proof envelope.
    pub domain_separator: String,
}

/// Decoded proof contents for tests and adapter wiring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareNizkOpenedProof {
    /// Statement reconstructed from the proof payload.
    pub statement: ShareNizkStatement,
    /// Share bytes opened by the proof.
    pub share_bytes: Vec<u8>,
    /// Integer share coefficients used for the norm-bound check.
    pub share_coeffs: Vec<i16>,
    /// Deterministic randomness bytes used for the binding digest.
    pub encryption_randomness: Vec<u8>,
    /// Fiat-Shamir challenge bytes.
    pub challenge: [u8; CHALLENGE_LEN],
    /// Binding digest over the witness and statement.
    pub binding: [u8; DIGEST_LEN],
    /// Domain separator stored in the proof payload.
    pub domain_separator: String,
}

/// Deterministic prover for the share-encryption proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareNizkProver;

/// Deterministic verifier for the share-encryption proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareNizkVerifier;

impl ShareNizkProver {
    /// Produce a deterministic share-encryption proof for a statement/witness pair.
    pub fn prove(
        stmt: &ShareNizkStatement,
        witness: &ShareNizkWitness,
    ) -> Result<ShareNizkProof, PvssError> {
        validate_statement(stmt)?;
        validate_witness(witness)?;

        let share_coeffs = witness
            .share_bytes
            .iter()
            .copied()
            .map(i16::from)
            .collect::<Vec<_>>();
        let challenge = derive_challenge(stmt);
        let binding = compute_binding(
            stmt,
            &witness.share_bytes,
            &share_coeffs,
            &witness.encryption_randomness,
            &challenge,
        );

        let opened = ShareNizkOpenedProof {
            statement: stmt.clone(),
            share_bytes: witness.share_bytes.clone(),
            share_coeffs,
            encryption_randomness: witness.encryption_randomness.clone(),
            challenge,
            binding,
            domain_separator: SHARE_NIZK_DOMAIN_SEPARATOR.to_owned(),
        };

        ShareNizkProof::from_opened(&opened)
    }
}

impl ShareNizkVerifier {
    /// Verify a deterministic share-encryption proof against a statement.
    pub fn verify(stmt: &ShareNizkStatement, proof: &ShareNizkProof) -> Result<(), PvssError> {
        validate_statement(stmt)?;
        if proof.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR {
            return Err(PvssError::InvalidShare);
        }

        let opened = proof.decode()?;
        if opened.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR || opened.statement != *stmt {
            return Err(PvssError::InvalidShare);
        }

        validate_share_coeffs(&opened.share_bytes, &opened.share_coeffs)?;

        let expected_commitment = compute_share_commitment(
            &stmt.session_id,
            stmt.recipient_index,
            &opened.share_bytes,
        );
        if expected_commitment.as_slice() != stmt.share_commitment.as_slice() {
            return Err(PvssError::InvalidShare);
        }

        let expected_ciphertext_v = compute_ciphertext_v(&stmt.ciphertext_u);
        if expected_ciphertext_v.as_slice() != stmt.ciphertext_v.as_slice() {
            return Err(PvssError::InvalidShare);
        }

        let expected_challenge = derive_challenge(stmt);
        if expected_challenge != opened.challenge {
            return Err(PvssError::InvalidShare);
        }

        let expected_binding = compute_binding(
            stmt,
            &opened.share_bytes,
            &opened.share_coeffs,
            &opened.encryption_randomness,
            &opened.challenge,
        );
        if expected_binding != opened.binding {
            return Err(PvssError::InvalidShare);
        }

        Ok(())
    }
}

impl ShareNizkProof {
    /// Encode a decoded/opened proof back into the serialized envelope.
    pub fn from_opened(opened: &ShareNizkOpenedProof) -> Result<Self, PvssError> {
        if opened.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR {
            return Err(PvssError::InvalidShare);
        }
        validate_statement(&opened.statement)?;
        validate_witness(&ShareNizkWitness {
            share_bytes: opened.share_bytes.clone(),
            encryption_randomness: opened.encryption_randomness.clone(),
        })?;
        validate_share_coeffs(&opened.share_bytes, &opened.share_coeffs)?;

        Ok(Self {
            proof_bytes: encode_opened_proof(opened)?,
            domain_separator: opened.domain_separator.clone(),
        })
    }

    /// Wrap raw proof bytes after decoding them successfully.
    pub fn from_bytes(proof_bytes: Vec<u8>) -> Result<Self, PvssError> {
        let opened = decode_opened_proof(&proof_bytes)?;
        Ok(Self {
            proof_bytes,
            domain_separator: opened.domain_separator,
        })
    }

    /// Decode the serialized proof payload into structured contents.
    pub fn decode(&self) -> Result<ShareNizkOpenedProof, PvssError> {
        decode_opened_proof(&self.proof_bytes)
    }
}

/// Compute the share commitment `SHA256(session_id || recipient_index_le || share_bytes)`.
pub fn compute_share_commitment(
    session_id: &[u8],
    recipient_index: usize,
    share_bytes: &[u8],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(recipient_index.to_le_bytes());
    hasher.update(share_bytes);
    hasher.finalize().into()
}

/// Compute the hash-bound secondary ciphertext component from `ciphertext_u`.
pub fn compute_ciphertext_v(ciphertext_u: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"ciphertext-v1");
    hasher.update(ciphertext_u);
    hasher.finalize().into()
}

fn validate_statement(stmt: &ShareNizkStatement) -> Result<(), PvssError> {
    if stmt.session_id.is_empty()
        || stmt.recipient_pk.is_empty()
        || stmt.ciphertext_u.is_empty()
        || stmt.ciphertext_v.len() != DIGEST_LEN
        || stmt.share_commitment.len() != DIGEST_LEN
    {
        return Err(PvssError::InvalidShare);
    }
    if stmt.recipient_pk.len() > MAX_FIELD_LEN || stmt.ciphertext_u.len() > MAX_FIELD_LEN {
        return Err(PvssError::InvalidShare);
    }
    Ok(())
}

fn validate_witness(witness: &ShareNizkWitness) -> Result<(), PvssError> {
    if witness.share_bytes.is_empty()
        || witness.share_bytes.len() > MAX_FIELD_LEN
        || witness.encryption_randomness.is_empty()
        || witness.encryption_randomness.len() > MAX_FIELD_LEN
    {
        return Err(PvssError::InvalidShare);
    }
    Ok(())
}

fn validate_share_coeffs(share_bytes: &[u8], share_coeffs: &[i16]) -> Result<(), PvssError> {
    if share_coeffs.len() != share_bytes.len() {
        return Err(PvssError::InvalidShare);
    }

    for (byte, coeff) in share_bytes.iter().zip(share_coeffs.iter().copied()) {
        if !(0..=SHARE_COEFF_BOUND).contains(&coeff) {
            return Err(PvssError::InvalidShare);
        }
        if u8::try_from(coeff).map_err(|_| PvssError::InvalidShare)? != *byte {
            return Err(PvssError::InvalidShare);
        }
    }

    Ok(())
}

fn derive_challenge(stmt: &ShareNizkStatement) -> [u8; CHALLENGE_LEN] {
    let participant_id = u32::try_from(stmt.dealer_index).unwrap_or(u32::MAX);
    let mut transcript = Transcript::new(&stmt.session_id, participant_id);
    transcript.absorb(b"domain_separator", SHARE_NIZK_DOMAIN_SEPARATOR.as_bytes());
    transcript.absorb(b"session_id", &stmt.session_id);
    transcript.absorb(b"dealer_index", &stmt.dealer_index.to_be_bytes());
    transcript.absorb(b"recipient_index", &stmt.recipient_index.to_be_bytes());
    transcript.absorb(b"recipient_pk", &stmt.recipient_pk);
    transcript.absorb(b"ciphertext_u", &stmt.ciphertext_u);
    transcript.absorb(b"ciphertext_v", &stmt.ciphertext_v);
    transcript.absorb(b"share_commitment", &stmt.share_commitment);

    let mut challenge = [0u8; CHALLENGE_LEN];
    transcript.challenge_bytes(b"share-encryption-challenge", &mut challenge);
    challenge
}

fn compute_binding(
    stmt: &ShareNizkStatement,
    share_bytes: &[u8],
    share_coeffs: &[i16],
    encryption_randomness: &[u8],
    challenge: &[u8; CHALLENGE_LEN],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"pvss-bfv-binding-v1");
    hasher.update(challenge);
    hasher.update(&stmt.recipient_pk);
    hasher.update(&stmt.ciphertext_u);
    hasher.update(&stmt.ciphertext_v);
    hasher.update(&stmt.share_commitment);
    hasher.update(share_bytes);
    for coeff in share_coeffs {
        hasher.update(coeff.to_le_bytes());
    }
    hasher.update(encryption_randomness);
    hasher.finalize().into()
}

fn encode_opened_proof(opened: &ShareNizkOpenedProof) -> Result<Vec<u8>, PvssError> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROOF_VERSION.to_be_bytes());
    encode_bytes(&mut out, opened.domain_separator.as_bytes())?;
    encode_bytes(&mut out, &opened.statement.session_id)?;
    encode_usize(&mut out, opened.statement.dealer_index)?;
    encode_usize(&mut out, opened.statement.recipient_index)?;
    encode_bytes(&mut out, &opened.statement.recipient_pk)?;
    encode_bytes(&mut out, &opened.statement.ciphertext_u)?;
    encode_bytes(&mut out, &opened.statement.ciphertext_v)?;
    encode_bytes(&mut out, &opened.statement.share_commitment)?;
    encode_bytes(&mut out, &opened.share_bytes)?;
    encode_i16s(&mut out, &opened.share_coeffs)?;
    encode_bytes(&mut out, &opened.encryption_randomness)?;
    out.extend_from_slice(&opened.challenge);
    out.extend_from_slice(&opened.binding);
    Ok(out)
}

fn decode_opened_proof(bytes: &[u8]) -> Result<ShareNizkOpenedProof, PvssError> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != PROOF_VERSION {
        return Err(PvssError::InvalidShare);
    }

    let domain_separator = String::from_utf8(cursor.read_vec()?).map_err(|_| PvssError::InvalidShare)?;
    let session_id = cursor.read_vec()?;
    let dealer_index = cursor.read_usize()?;
    let recipient_index = cursor.read_usize()?;
    let recipient_pk = cursor.read_vec()?;
    let ciphertext_u = cursor.read_vec()?;
    let ciphertext_v = cursor.read_vec()?;
    let share_commitment = cursor.read_vec()?;
    let share_bytes = cursor.read_vec()?;
    let share_coeffs = cursor.read_i16s()?;
    let encryption_randomness = cursor.read_vec()?;
    let challenge = cursor.read_array::<CHALLENGE_LEN>()?;
    let binding = cursor.read_array::<DIGEST_LEN>()?;
    cursor.finish()?;

    Ok(ShareNizkOpenedProof {
        statement: ShareNizkStatement {
            session_id,
            dealer_index,
            recipient_index,
            recipient_pk,
            ciphertext_u,
            ciphertext_v,
            share_commitment,
        },
        share_bytes,
        share_coeffs,
        encryption_randomness,
        challenge,
        binding,
        domain_separator,
    })
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

fn encode_i16s(out: &mut Vec<u8>, values: &[i16]) -> Result<(), PvssError> {
    let len = u32::try_from(values.len()).map_err(|_| PvssError::InvalidShare)?;
    out.extend_from_slice(&len.to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
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
        let end = self.offset.checked_add(len).ok_or(PvssError::InvalidShare)?;
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

    fn read_i16s(&mut self) -> Result<Vec<i16>, PvssError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| PvssError::InvalidShare)?;
        if len > MAX_FIELD_LEN {
            return Err(PvssError::InvalidShare);
        }

        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(i16::from_le_bytes(self.read_array()?));
        }
        Ok(values)
    }

    fn finish(self) -> Result<(), PvssError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PvssError::InvalidShare)
        }
    }
}
