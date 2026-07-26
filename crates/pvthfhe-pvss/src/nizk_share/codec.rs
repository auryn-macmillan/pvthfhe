//! Wire codec for the share-encryption proof envelope: opened-proof
//! encode/decode, the [`WireFormat`] implementation, and the byte [`Cursor`].

use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_foundations::types::ProtocolBytes;
use pvthfhe_foundations::wire::{WireError, WireFormat};

use crate::PvssError;

use super::statement::{
    validate_statement, ShareNizkOpenedProof, ShareNizkProof, ShareNizkStatement,
};
use super::{
    CHALLENGE_LEN, DIGEST_LEN, MAX_FIELD_LEN, PROOF_VERSION, SHARE_NIZK_DOMAIN_SEPARATOR,
    WIRE_VERSION,
};

// ── Proof serialization/deserialization ──────────────────────────────────

impl ShareNizkProof {
    pub fn from_opened(opened: &ShareNizkOpenedProof) -> Result<Self, PvssError> {
        if opened.domain_separator != SHARE_NIZK_DOMAIN_SEPARATOR {
            return Err(PvssError::InvalidShare {
                party_id: Some(opened.statement.recipient_index as u16),
            });
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
    out.extend_from_slice(&opened.commitment_nonce);
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
    ShareNizkOpenedProof::decode(bytes).map_err(|_| PvssError::InvalidShare { party_id: None })
}

fn decode_opened_proof_body(bytes: &[u8]) -> Result<ShareNizkOpenedProof, PvssError> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != PROOF_VERSION {
        return Err(PvssError::InvalidShare { party_id: None });
    }

    let domain_separator = String::from_utf8(cursor.read_vec()?)
        .map_err(|_| PvssError::InvalidShare { party_id: None })?;
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
    let commitment_nonce = cursor.read_array::<DIGEST_LEN>()?;
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
        commitment_nonce,
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
        encode_opened_proof_body(self).unwrap_or_default()
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        decode_opened_proof_body(bytes).map_err(|_| WireError::Other)
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PvssError> {
    let len = u32::try_from(bytes.len()).map_err(|_| PvssError::InvalidShare { party_id: None })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_usize(out: &mut Vec<u8>, value: usize) -> Result<(), PvssError> {
    let value = u64::try_from(value).map_err(|_| PvssError::InvalidShare { party_id: None })?;
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
            .ok_or(PvssError::InvalidShare { party_id: None })?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(PvssError::InvalidShare { party_id: None })?;
        self.offset = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PvssError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| PvssError::InvalidShare { party_id: None })
    }

    fn read_u16(&mut self) -> Result<u16, PvssError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, PvssError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_usize(&mut self) -> Result<usize, PvssError> {
        let raw = u64::from_be_bytes(self.read_array()?);
        usize::try_from(raw).map_err(|_| PvssError::InvalidShare { party_id: None })
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, PvssError> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| PvssError::InvalidShare { party_id: None })?;
        if len > MAX_FIELD_LEN {
            return Err(PvssError::InvalidShare { party_id: None });
        }
        Ok(self.read_exact(len)?.to_vec())
    }

    fn finish(self) -> Result<(), PvssError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PvssError::InvalidShare { party_id: None })
        }
    }
}
