//! Share-decryption NIZK wrapper over the shared Cyclo/Ajtai adapter.

use pvthfhe_domain_tags::Tag;
use pvthfhe_nizk::{
    adapter::CycloNizkAdapter, hash_bridge, NizkAdapter, NizkProof, NizkStatement, NizkWitness,
};
use pvthfhe_rng::OsRng;
use pvthfhe_types::witness_language::{BfvParameters as SchemaBfvParams, R3Relation};
use pvthfhe_types::Secret;
use pvthfhe_wire::{WireError, WireFormat};

use ark_bn254::Fr;
// R3.0a — schema types wired for R3.2 GREEN migration
const _: () = {
    let _: Option<SchemaBfvParams> = None;
    let _: Option<R3Relation> = None;
};
use sha2::{Digest, Sha256};

use crate::dkg_aggregation::{compute_esm_aggregate_commitment, compute_sk_aggregate_commitment};
use crate::PvssError;

/// Locked domain separator for PVSS share-decryption proofs.
pub const DECRYPT_NIZK_DOMAIN_SEPARATOR: &str = "pvthfhe-pvss-share-decryption-v1";

const PROOF_VERSION: u16 = 3;
const WIRE_VERSION: u8 = 3;
const MAX_FIELD_LEN: usize = 33_554_432; // 32 MiB — G1: 90-round sigma inner proof up to 17.7 MB for N=8192
const RLWE_DEGREE: usize = 8192;
const RLWE_Q_LOG2: u64 = 174;
const RLWE_ERROR_BOUND: u64 = 16;
const DIGEST_LEN: usize = 32;

/// Decryption-proof smudging mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptNizkMode {
    /// Legacy threshold decryption using fresh local smudging noise.
    LegacyLocalSmudge,
    /// Threshold decryption using a DKG-committed smudging slot.
    CommittedSmudge {
        /// One-based committed smudging slot identifier.
        slot_id: u16,
        /// Decryption round bound to this committed slot use.
        decrypt_round: u64,
        /// Public hash of `(ciphertext_u, ciphertext_v)` bound to the statement.
        ciphertext_hash: [u8; DIGEST_LEN],
        /// Accepted DKG participant set used for aggregate commitment checks.
        accepted_participant_ids: Vec<u16>,
        /// Public aggregate secret-key share commitment `DKG.sk_agg_commits[j]`.
        sk_agg_commit: [u8; DIGEST_LEN],
        /// Public aggregate smudging share commitment `DKG.esm_agg_commits[j][slot]`.
        esm_agg_commit: [u8; DIGEST_LEN],
    },
}

/// Public statement for one share-decryption proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptNizkStatement {
    /// Session binding bytes.
    pub session_id: Vec<u8>,
    /// Zero-based decrypting party index.
    pub party_index: usize,
    /// Primary ciphertext bytes.
    pub ciphertext_u: Vec<u8>,
    /// Secondary ciphertext binding bytes.
    pub ciphertext_v: Vec<u8>,
    /// Claimed decrypted-share bytes.
    pub decrypted_share_bytes: Vec<u8>,
    /// Decrypting party public-key bytes.
    pub party_pk: Vec<u8>,
    /// On-chain epoch that binds the CRS.
    pub epoch: u64,
    /// DKG transcript root binding this decryption to the exact anchor set.
    pub dkg_root: Vec<u8>,
    /// Explicit smudging mode for this decryption relation.
    pub mode: DecryptNizkMode,
    /// Expected DKG-anchored secret-key aggregate share for witness binding.
    pub expected_sk_agg_share: u64,
    /// Cryptographically-derived dealer identity index bound to the session.
    pub dealer_index: usize,
}

/// Secret witness for one share-decryption proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptNizkWitness {
    /// Party secret-key bytes.
    pub secret_key_bytes: Secret<Vec<u8>>,
    /// Canonicalized decryption-noise bytes.
    pub decryption_noise: Secret<Vec<u8>>,
    /// Aggregate secret-key share scalar for committed-smudge commitment checks.
    pub sk_agg_share: Option<u64>,
    /// Aggregate committed smudging share scalar for the selected slot.
    pub esm_agg_share: Option<u64>,
    /// Explicit committed `e_sm` polynomial bytes used instead of fresh local noise.
    pub esm_noise_poly_bytes: Option<Vec<u8>>,
}

/// Serialized proof envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptNizkProof {
    /// Serialized proof payload.
    pub proof_bytes: Vec<u8>,
    /// Domain separator recorded in the proof envelope.
    pub domain_separator: String,
}

/// Decoded proof contents for adapter wiring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptNizkOpenedProof {
    /// Statement reconstructed from the proof payload.
    pub statement: DecryptNizkStatement,
    /// Backend identifier for the wrapped shared NIZK.
    pub backend_id: String,
    /// Wrapped shared NIZK proof bytes.
    pub inner_proof_bytes: Vec<u8>,
    /// Domain separator stored in the proof payload.
    pub domain_separator: String,
}

/// Deterministic prover for the share-decryption proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecryptNizkProver;

/// Deterministic verifier for the share-decryption proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecryptNizkVerifier;

impl DecryptNizkProver {
    /// Produce a deterministic share-decryption proof for a statement/witness pair.
    pub fn prove(
        stmt: &DecryptNizkStatement,
        witness: &DecryptNizkWitness,
    ) -> Result<DecryptNizkProof, PvssError> {
        validate_statement(stmt)?;
        validate_witness(stmt, witness)?;

        let participant_id =
            u16::try_from(stmt.party_index).map_err(|_| PvssError::InvalidShare)?;
        let session_id = hex_encode(&stmt.session_id);
        let secret_share = proof_secret_share(stmt, witness)?;
        let inner_stmt = NizkStatement {
            ciphertext_bytes: encode_ciphertext_bytes(stmt)?,
            decrypt_share_bytes: stmt.decrypted_share_bytes.clone(),
            pvss_commitment: proof_commitment(stmt, &session_id, participant_id, secret_share),
            params: (RLWE_Q_LOG2, RLWE_DEGREE, RLWE_ERROR_BOUND),
            session_id,
            participant_id,
            epoch: stmt.epoch,
        };
        let inner_witness = NizkWitness {
            secret_share,
            secret_share_poly: derive_secret_share_poly(witness.secret_key_bytes.expose_secret()),
            error: derive_error_vector(proof_noise_bytes(stmt, witness)?),
            randomness: derive_randomness(
                witness.secret_key_bytes.expose_secret(),
                proof_noise_bytes(stmt, witness)?,
            ),
        };
        let mut rng = OsRng;
        let inner_proof = CycloNizkAdapter
            .prove(&inner_stmt, &inner_witness, &mut rng)
            .map_err(|_| PvssError::InvalidShare)?;

        let opened = DecryptNizkOpenedProof {
            statement: stmt.clone(),
            backend_id: inner_proof.backend_id,
            inner_proof_bytes: inner_proof.proof_bytes,
            domain_separator: DECRYPT_NIZK_DOMAIN_SEPARATOR.to_owned(),
        };

        DecryptNizkProof::from_opened(&opened)
    }
}

impl DecryptNizkVerifier {
    /// Verify a deterministic share-decryption proof against a statement.
    pub fn verify(stmt: &DecryptNizkStatement, proof: &DecryptNizkProof) -> Result<(), PvssError> {
        validate_statement(stmt)?;
        if proof.domain_separator != DECRYPT_NIZK_DOMAIN_SEPARATOR {
            return Err(PvssError::InvalidShare);
        }

        let opened = proof.decode()?;
        if opened.domain_separator != DECRYPT_NIZK_DOMAIN_SEPARATOR || opened.statement != *stmt {
            return Err(PvssError::InvalidShare);
        }

        let participant_id =
            u16::try_from(stmt.party_index).map_err(|_| PvssError::InvalidShare)?;
        let session_id = hex_encode(&stmt.session_id);
        let bound_secret_share = verify_secret_share(stmt);
        let inner_stmt = NizkStatement {
            ciphertext_bytes: encode_ciphertext_bytes(stmt)?,
            decrypt_share_bytes: stmt.decrypted_share_bytes.clone(),
            pvss_commitment: verify_commitment(
                stmt,
                &session_id,
                participant_id,
                bound_secret_share,
            ),
            params: (RLWE_Q_LOG2, RLWE_DEGREE, RLWE_ERROR_BOUND),
            session_id,
            participant_id,
            epoch: stmt.epoch,
        };
        let inner_proof = NizkProof {
            backend_id: opened.backend_id,
            proof_bytes: opened.inner_proof_bytes,
        };

        CycloNizkAdapter
            .verify(&inner_stmt, &inner_proof)
            .map_err(|e| {
                eprintln!("PVSS inner verify error: {e:?}");
                eprintln!("PVSS inner proof_bytes len: {}", proof.proof_bytes.len());
                PvssError::ShareVerification(format!("sigma verify: {e}"))
            })
    }
}

impl DecryptNizkProof {
    /// Encode a decoded/opened proof back into the serialized envelope.
    pub fn from_opened(opened: &DecryptNizkOpenedProof) -> Result<Self, PvssError> {
        if opened.domain_separator != DECRYPT_NIZK_DOMAIN_SEPARATOR {
            return Err(PvssError::InvalidShare);
        }
        validate_statement(&opened.statement)?;
        if opened.backend_id.is_empty() || opened.inner_proof_bytes.is_empty() {
            return Err(PvssError::InvalidShare);
        }

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
    pub fn decode(&self) -> Result<DecryptNizkOpenedProof, PvssError> {
        decode_opened_proof(&self.proof_bytes)
    }
}

fn validate_statement(stmt: &DecryptNizkStatement) -> Result<(), PvssError> {
    if stmt.session_id.is_empty()
        || stmt.ciphertext_u.is_empty()
        || stmt.ciphertext_v.is_empty()
        || stmt.decrypted_share_bytes.is_empty()
        || stmt.party_pk.is_empty()
        || stmt.dkg_root.is_empty()
    {
        return Err(PvssError::InvalidShare);
    }
    if stmt.session_id.len() > MAX_FIELD_LEN
        || stmt.ciphertext_u.len() > MAX_FIELD_LEN
        || stmt.ciphertext_v.len() > MAX_FIELD_LEN
        || stmt.decrypted_share_bytes.len() > MAX_FIELD_LEN
        || stmt.party_pk.len() > MAX_FIELD_LEN
        || stmt.dkg_root.len() > MAX_FIELD_LEN
        || stmt.party_index > usize::from(u16::MAX)
    {
        return Err(PvssError::InvalidShare);
    }
    validate_mode(stmt)?;
    Ok(())
}

fn validate_mode(stmt: &DecryptNizkStatement) -> Result<(), PvssError> {
    match &stmt.mode {
        DecryptNizkMode::LegacyLocalSmudge => Ok(()),
        DecryptNizkMode::CommittedSmudge {
            slot_id,
            ciphertext_hash,
            accepted_participant_ids,
            sk_agg_commit,
            esm_agg_commit,
            ..
        } => {
            if *slot_id == 0
                || accepted_participant_ids.is_empty()
                || accepted_participant_ids.len() > usize::from(u16::MAX)
                || sk_agg_commit.iter().all(|byte| *byte == 0)
                || esm_agg_commit.iter().all(|byte| *byte == 0)
            {
                return Err(PvssError::InvalidShare);
            }
            if *ciphertext_hash
                != compute_decrypt_ciphertext_hash(&stmt.ciphertext_u, &stmt.ciphertext_v)
            {
                return Err(PvssError::InvalidShare);
            }
            for window in accepted_participant_ids.windows(2) {
                if window[0] >= window[1] {
                    return Err(PvssError::InvalidShare);
                }
            }
            Ok(())
        }
    }
}

fn validate_witness(
    stmt: &DecryptNizkStatement,
    witness: &DecryptNizkWitness,
) -> Result<(), PvssError> {
    if witness.secret_key_bytes.expose_secret().is_empty()
        || witness.decryption_noise.expose_secret().is_empty()
        || witness.secret_key_bytes.expose_secret().len() > MAX_FIELD_LEN
        || witness.decryption_noise.expose_secret().len() > MAX_FIELD_LEN
    {
        return Err(PvssError::InvalidShare);
    }
    match &stmt.mode {
        DecryptNizkMode::LegacyLocalSmudge => Ok(()),
        DecryptNizkMode::CommittedSmudge {
            slot_id,
            accepted_participant_ids,
            sk_agg_commit,
            esm_agg_commit,
            ..
        } => {
            let sk_agg_share = witness.sk_agg_share.ok_or(PvssError::InvalidShare)?;
            let esm_agg_share = witness.esm_agg_share.ok_or(PvssError::InvalidShare)?;
            let esm_noise_poly_bytes = witness
                .esm_noise_poly_bytes
                .as_ref()
                .ok_or(PvssError::InvalidShare)?;
            if esm_noise_poly_bytes.is_empty() || esm_noise_poly_bytes.len() > MAX_FIELD_LEN {
                return Err(PvssError::InvalidShare);
            }
            let recipient_id =
                u16::try_from(stmt.party_index).map_err(|_| PvssError::InvalidShare)?;
            let expected_sk = compute_sk_aggregate_commitment(
                &stmt.session_id,
                &stmt.dkg_root,
                recipient_id,
                accepted_participant_ids,
                Fr::from(sk_agg_share),
            );
            if expected_sk != *sk_agg_commit {
                return Err(PvssError::InvalidShare);
            }
            let expected_esm = compute_esm_aggregate_commitment(
                &stmt.session_id,
                &stmt.dkg_root,
                recipient_id,
                accepted_participant_ids,
                *slot_id,
                Fr::from(esm_agg_share),
            );
            if expected_esm != *esm_agg_commit {
                return Err(PvssError::InvalidShare);
            }
            if let Some(ref esm_bytes) = witness.esm_noise_poly_bytes {
                let derived_esm_share = derive_party_binding(esm_bytes);
                if derived_esm_share != esm_agg_share {
                    return Err(PvssError::InvalidShare);
                }
            }
            Ok(())
        }
    }
}

fn proof_secret_share(
    stmt: &DecryptNizkStatement,
    witness: &DecryptNizkWitness,
) -> Result<u64, PvssError> {
    match stmt.mode {
        DecryptNizkMode::LegacyLocalSmudge => {
            // Phase 0 safety freeze: legacy local smudging may still exist, but
            // it must not silently replace a missing DKG-committed aggregate
            // secret-key share with a public-key-derived binding.
            witness.sk_agg_share.ok_or(PvssError::InvalidShare)
        }
        DecryptNizkMode::CommittedSmudge { .. } => {
            witness.sk_agg_share.ok_or(PvssError::InvalidShare)
        }
    }
}

fn proof_noise_bytes<'a>(
    stmt: &DecryptNizkStatement,
    witness: &'a DecryptNizkWitness,
) -> Result<&'a [u8], PvssError> {
    match &stmt.mode {
        DecryptNizkMode::LegacyLocalSmudge => Ok(witness.decryption_noise.expose_secret()),
        DecryptNizkMode::CommittedSmudge { .. } => witness
            .esm_noise_poly_bytes
            .as_deref()
            .ok_or(PvssError::InvalidShare),
    }
}

fn proof_commitment(
    stmt: &DecryptNizkStatement,
    session_id: &str,
    participant_id: u16,
    secret_share: u64,
) -> [u8; DIGEST_LEN] {
    match &stmt.mode {
        DecryptNizkMode::LegacyLocalSmudge => {
            hash_bridge::commit(session_id, participant_id, secret_share)
        }
        DecryptNizkMode::CommittedSmudge { sk_agg_commit, .. } => *sk_agg_commit,
    }
}

fn verify_secret_share(stmt: &DecryptNizkStatement) -> u64 {
    stmt.expected_sk_agg_share
}

fn verify_commitment(
    stmt: &DecryptNizkStatement,
    session_id: &str,
    participant_id: u16,
    secret_share: u64,
) -> [u8; DIGEST_LEN] {
    match &stmt.mode {
        DecryptNizkMode::LegacyLocalSmudge => {
            hash_bridge::commit(session_id, participant_id, secret_share)
        }
        DecryptNizkMode::CommittedSmudge { sk_agg_commit, .. } => *sk_agg_commit,
    }
}

/// Compute the public ciphertext hash used by committed-smudge decrypt statements.
pub fn compute_decrypt_ciphertext_hash(
    ciphertext_u: &[u8],
    ciphertext_v: &[u8],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-decrypt-ciphertext-hash-v1");
    hasher.update((ciphertext_u.len() as u64).to_be_bytes());
    hasher.update(ciphertext_u);
    hasher.update((ciphertext_v.len() as u64).to_be_bytes());
    hasher.update(ciphertext_v);
    hasher.finalize().into()
}

/// Derive a scalar binding from a party's public key for sk_agg_share fallback.
pub fn derive_party_binding(party_pk: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-decrypt-party-binding-v1");
    hasher.update(party_pk);
    let digest: [u8; 32] = hasher.finalize().into();
    u64::from_be_bytes(digest[..8].try_into().unwrap_or([0u8; 8]))
}

fn derive_secret_share_poly(secret_key_bytes: &[u8]) -> Vec<i64> {
    secret_key_bytes
        .iter()
        .copied()
        .map(|byte| match byte % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        })
        .collect()
}

fn derive_error_vector(decryption_noise: &[u8]) -> Vec<i64> {
    decryption_noise
        .iter()
        .copied()
        .map(|byte| i64::from((byte % 5) as i8) - 2)
        .collect()
}

fn derive_randomness(secret_key_bytes: &[u8], decryption_noise: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DECRYPT_NIZK_DOMAIN_SEPARATOR.as_bytes());
    hasher.update(secret_key_bytes);
    hasher.update(decryption_noise);
    hasher.finalize().to_vec()
}

fn encode_ciphertext_bytes(stmt: &DecryptNizkStatement) -> Result<Vec<u8>, PvssError> {
    let mut out = Vec::new();
    encode_bytes(&mut out, &stmt.ciphertext_u)?;
    encode_bytes(&mut out, &stmt.ciphertext_v)?;
    encode_bytes(&mut out, &stmt.party_pk)?;
    encode_bytes(&mut out, &stmt.dkg_root)?;
    encode_mode(&mut out, &stmt.mode)?;
    Ok(out)
}

fn encode_opened_proof(opened: &DecryptNizkOpenedProof) -> Result<Vec<u8>, PvssError> {
    Ok(opened.encode())
}

fn encode_opened_proof_body(opened: &DecryptNizkOpenedProof) -> Result<Vec<u8>, PvssError> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROOF_VERSION.to_be_bytes());
    encode_bytes(&mut out, opened.domain_separator.as_bytes())?;
    encode_bytes(&mut out, &opened.statement.session_id)?;
    encode_usize(&mut out, opened.statement.party_index)?;
    encode_bytes(&mut out, &opened.statement.ciphertext_u)?;
    encode_bytes(&mut out, &opened.statement.ciphertext_v)?;
    encode_bytes(&mut out, &opened.statement.decrypted_share_bytes)?;
    encode_bytes(&mut out, &opened.statement.party_pk)?;
    out.extend_from_slice(&opened.statement.epoch.to_be_bytes());
    encode_bytes(&mut out, &opened.statement.dkg_root)?;
    out.extend_from_slice(&opened.statement.expected_sk_agg_share.to_be_bytes());
    encode_usize(&mut out, opened.statement.dealer_index)?;
    encode_mode(&mut out, &opened.statement.mode)?;
    encode_bytes(&mut out, opened.backend_id.as_bytes())?;
    encode_bytes(&mut out, &opened.inner_proof_bytes)?;
    Ok(out)
}

fn decode_opened_proof(bytes: &[u8]) -> Result<DecryptNizkOpenedProof, PvssError> {
    DecryptNizkOpenedProof::decode(bytes).map_err(|_| PvssError::InvalidShare)
}

fn decode_opened_proof_body(bytes: &[u8]) -> Result<DecryptNizkOpenedProof, PvssError> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != PROOF_VERSION {
        return Err(PvssError::InvalidShare);
    }

    let domain_separator =
        String::from_utf8(cursor.read_vec()?).map_err(|_| PvssError::InvalidShare)?;
    let session_id = cursor.read_vec()?;
    let party_index = cursor.read_usize()?;
    let ciphertext_u = cursor.read_vec()?;
    let ciphertext_v = cursor.read_vec()?;
    let decrypted_share_bytes = cursor.read_vec()?;
    let party_pk = cursor.read_vec()?;
    let epoch = cursor.read_u64()?;
    let dkg_root = cursor.read_vec()?;
    let expected_sk_agg_share = cursor.read_u64()?;
    let dealer_index = cursor.read_usize()?;
    let mode = cursor.read_mode()?;
    let backend_id = String::from_utf8(cursor.read_vec()?).map_err(|_| PvssError::InvalidShare)?;
    let inner_proof_bytes = cursor.read_vec()?;
    cursor.finish()?;

    Ok(DecryptNizkOpenedProof {
        statement: DecryptNizkStatement {
            session_id,
            party_index,
            ciphertext_u,
            ciphertext_v,
            decrypted_share_bytes,
            party_pk,
            epoch,
            dkg_root,
            expected_sk_agg_share,
            dealer_index,
            mode,
        },
        backend_id,
        inner_proof_bytes,
        domain_separator,
    })
}

impl WireFormat for DecryptNizkOpenedProof {
    const VERSION: u8 = WIRE_VERSION;
    const TAG: Tag = Tag::WirePvssDecryptOpenedProof;

    fn encode_body(&self) -> Vec<u8> {
        encode_opened_proof_body(self).expect("validated decrypt NIZK opened proof must encode")
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

fn encode_mode(out: &mut Vec<u8>, mode: &DecryptNizkMode) -> Result<(), PvssError> {
    match mode {
        DecryptNizkMode::LegacyLocalSmudge => out.push(0),
        DecryptNizkMode::CommittedSmudge {
            slot_id,
            decrypt_round,
            ciphertext_hash,
            accepted_participant_ids,
            sk_agg_commit,
            esm_agg_commit,
        } => {
            out.push(1);
            out.extend_from_slice(&slot_id.to_be_bytes());
            out.extend_from_slice(&decrypt_round.to_be_bytes());
            out.extend_from_slice(ciphertext_hash);
            let len = u32::try_from(accepted_participant_ids.len())
                .map_err(|_| PvssError::InvalidShare)?;
            out.extend_from_slice(&len.to_be_bytes());
            for participant_id in accepted_participant_ids {
                out.extend_from_slice(&participant_id.to_be_bytes());
            }
            out.extend_from_slice(sk_agg_commit);
            out.extend_from_slice(esm_agg_commit);
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(LUT[(byte >> 4) as usize]));
        out.push(char::from(LUT[(byte & 0x0f) as usize]));
    }
    out
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

    fn read_u64(&mut self) -> Result<u64, PvssError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_mode(&mut self) -> Result<DecryptNizkMode, PvssError> {
        let tag = *self.read_exact(1)?.first().ok_or(PvssError::InvalidShare)?;
        match tag {
            0 => Ok(DecryptNizkMode::LegacyLocalSmudge),
            1 => {
                let slot_id = u16::from_be_bytes(self.read_array()?);
                let decrypt_round = self.read_u64()?;
                let ciphertext_hash = self.read_array()?;
                let participant_count =
                    usize::try_from(self.read_u32()?).map_err(|_| PvssError::InvalidShare)?;
                if participant_count == 0 || participant_count > usize::from(u16::MAX) {
                    return Err(PvssError::InvalidShare);
                }
                let mut accepted_participant_ids = Vec::with_capacity(participant_count);
                for _ in 0..participant_count {
                    accepted_participant_ids.push(u16::from_be_bytes(self.read_array()?));
                }
                let sk_agg_commit = self.read_array()?;
                let esm_agg_commit = self.read_array()?;
                Ok(DecryptNizkMode::CommittedSmudge {
                    slot_id,
                    decrypt_round,
                    ciphertext_hash,
                    accepted_participant_ids,
                    sk_agg_commit,
                    esm_agg_commit,
                })
            }
            _ => Err(PvssError::InvalidShare),
        }
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
