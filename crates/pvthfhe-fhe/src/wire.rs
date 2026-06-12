//! Versioned wire formats for FHE byte payloads.
//!
//! These encodings back the opaque `bytes` fields exposed by the crate's public
//! wrapper types. They are versioned so later tasks can evolve the payload
//! layout without changing those wrapper structs.
//!
//! ## Research Limitation (F13 — MPC-AUDIT-2026-06-12)
//!
//! Wire type deserialization (`KeygenShareV1`, `PublicKeyV1`, `DecryptShareV2`)
//! validates length bounds but does NOT validate that polynomial coefficient
//! bytes represent valid field elements (i.e., bytes < modulus for each RNS
//! limb). Invalid coefficients are caught later during cryptographic operations
//! (BFV decryption will fail or produce garbage).
//!
//! Full coefficient-domain validation is deferred to production hardening.

use crate::FheError;
use pvthfhe_domain_tags::Tag;
use pvthfhe_types::ProtocolBytes;
use pvthfhe_wire::{WireError, WireFormat};

const WIRE_V1: u8 = 0x01;
const WIRE_V2: u8 = 0x02;
const LENGTH_PREFIX_BYTES: usize = 4;
const CIPHERTEXT_HASH_BYTES: usize = 32;
/// Max bytes for a single CRS/key/share field (8192 coeffs × 3 moduli × 8 bytes ≈ 196K).
const MAX_FHE_FIELD_BYTES: usize = 196_608;

/// Version-1 key generation share wire payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeygenShareV1 {
    /// Common random polynomial bytes.
    pub crp: ProtocolBytes,
    /// Party-zero public key share bytes.
    pub p0_share: ProtocolBytes,
}

/// Version-1 collective public key wire payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyV1 {
    /// First public key component bytes.
    pub p0: Vec<u8>,
    /// Second public key component bytes.
    pub p1: Vec<u8>,
}

/// Version-2 decryption share wire payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptShareV2 {
    /// Party identifier claimed by this share envelope.
    pub party_id: u32,
    /// SHA-256 hash of the ciphertext bytes decrypted by the producer.
    pub ciphertext_hash: [u8; 32],
    /// Partial decryption share polynomial bytes.
    pub d_share_poly: ProtocolBytes,
}

/// Encode a version-1 key generation share.
pub fn encode_keygen_share(crp: &[u8], p0_share: &[u8]) -> Vec<u8> {
    KeygenShareV1 {
        crp: ProtocolBytes(crp.to_vec()),
        p0_share: ProtocolBytes(p0_share.to_vec()),
    }
    .encode()
}

/// Decode a version-1 key generation share.
pub fn decode_keygen_share(bytes: &[u8]) -> Result<KeygenShareV1, FheError> {
    KeygenShareV1::decode(bytes).map_err(wire_error)
}

/// Encode a version-1 public key.
pub fn encode_public_key(p0: &[u8], p1: &[u8]) -> Vec<u8> {
    PublicKeyV1 {
        p0: p0.to_vec(),
        p1: p1.to_vec(),
    }
    .encode()
}

/// Decode a version-1 public key.
pub fn decode_public_key(bytes: &[u8]) -> Result<PublicKeyV1, FheError> {
    PublicKeyV1::decode(bytes).map_err(wire_error)
}

/// Encode a version-2 decryption share.
pub fn encode_decrypt_share(
    party_id: u32,
    ciphertext_hash: &[u8; 32],
    d_share_poly: &[u8],
) -> Vec<u8> {
    DecryptShareV2 {
        party_id,
        ciphertext_hash: *ciphertext_hash,
        d_share_poly: ProtocolBytes(d_share_poly.to_vec()),
    }
    .encode()
}

/// Decode a version-2 decryption share.
pub fn decode_decrypt_share(bytes: &[u8]) -> Result<DecryptShareV2, FheError> {
    DecryptShareV2::decode(bytes).map_err(wire_error)
}

impl WireFormat for KeygenShareV1 {
    const VERSION: u8 = WIRE_V1;
    const TAG: Tag = Tag::WireFheKeygenShare;

    fn encode_body(&self) -> Vec<u8> {
        encode_fields(&[self.crp.as_slice(), self.p0_share.as_slice()]).unwrap_or_default()
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let crp = decoder.read_field()?;
        let p0_share = decoder.read_field()?;
        decoder.finish()?;

        if crp.is_empty() || crp.len() > MAX_FHE_FIELD_BYTES {
            return Err(WireError::Other);
        }
        if p0_share.is_empty() || p0_share.len() > MAX_FHE_FIELD_BYTES {
            return Err(WireError::Other);
        }

        Ok(Self {
            crp: ProtocolBytes(crp),
            p0_share: ProtocolBytes(p0_share),
        })
    }
}

impl WireFormat for PublicKeyV1 {
    const VERSION: u8 = WIRE_V1;
    const TAG: Tag = Tag::WireFhePublicKey;

    fn encode_body(&self) -> Vec<u8> {
        encode_fields(&[&self.p0, &self.p1]).unwrap_or_default()
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let p0 = decoder.read_field()?;
        let p1 = decoder.read_field()?;
        decoder.finish()?;

        if p0.is_empty() || p0.len() > MAX_FHE_FIELD_BYTES {
            return Err(WireError::Other);
        }
        if p1.is_empty() || p1.len() > MAX_FHE_FIELD_BYTES {
            return Err(WireError::Other);
        }

        Ok(Self { p0, p1 })
    }
}

impl WireFormat for DecryptShareV2 {
    const VERSION: u8 = WIRE_V2;
    const TAG: Tag = Tag::WireFheDecryptShare;

    fn encode_body(&self) -> Vec<u8> {
        let d_share_field = encode_fields(&[self.d_share_poly.as_slice()]).unwrap_or_default();
        let mut out = Vec::with_capacity(4 + CIPHERTEXT_HASH_BYTES + d_share_field.len());
        out.extend_from_slice(&self.party_id.to_be_bytes());
        out.extend_from_slice(&self.ciphertext_hash);
        out.extend_from_slice(&d_share_field);
        out
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        let party_id_bytes = bytes.get(..4).ok_or(WireError::MissingLengthPrefix)?;
        let party_id = u32::from_be_bytes(party_id_bytes.try_into().map_err(|_| WireError::Other)?);
        let ciphertext_hash_bytes = bytes
            .get(4..4 + CIPHERTEXT_HASH_BYTES)
            .ok_or(WireError::MissingLengthPrefix)?;
        let ciphertext_hash: [u8; 32] = ciphertext_hash_bytes
            .try_into()
            .map_err(|_| WireError::Other)?;

        let mut decoder = Decoder::new(&bytes[4 + CIPHERTEXT_HASH_BYTES..]);
        let d_share_poly = decoder.read_field()?;
        decoder.finish()?;

        if d_share_poly.is_empty() || d_share_poly.len() > MAX_FHE_FIELD_BYTES {
            return Err(WireError::Other);
        }

        Ok(Self {
            party_id,
            ciphertext_hash,
            d_share_poly: ProtocolBytes(d_share_poly),
        })
    }
}

fn encode_fields(fields: &[&[u8]]) -> Result<Vec<u8>, WireError> {
    if fields.is_empty() {
        return Err(WireError::Other);
    }
    let payload_len: usize = fields
        .iter()
        .map(|field| LENGTH_PREFIX_BYTES + field.len())
        .sum();
    let mut out = Vec::with_capacity(payload_len);

    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| WireError::LengthOverflow)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }

    Ok(out)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_field(&mut self) -> Result<Vec<u8>, WireError> {
        let len_end = self
            .offset
            .checked_add(LENGTH_PREFIX_BYTES)
            .ok_or(WireError::LengthOverflow)?;
        let len_bytes = self
            .bytes
            .get(self.offset..len_end)
            .ok_or(WireError::MissingLengthPrefix)?;
        let len = u32::from_be_bytes(len_bytes.try_into().map_err(|_| WireError::Other)?);
        self.offset = len_end;

        let field_len = usize::try_from(len).map_err(|_| WireError::Other)?;
        let field_end = self
            .offset
            .checked_add(field_len)
            .ok_or(WireError::LengthOverflow)?;
        let field = self
            .bytes
            .get(self.offset..field_end)
            .ok_or(WireError::Other)?;
        self.offset = field_end;

        Ok(field.to_vec())
    }

    fn finish(self) -> Result<(), WireError> {
        if self.offset != self.bytes.len() {
            return Err(WireError::TrailingBytes);
        }

        Ok(())
    }
}

fn decode_error(reason: impl Into<String>) -> FheError {
    FheError::DecodeError {
        reason: reason.into(),
    }
}

fn wire_error(error: WireError) -> FheError {
    decode_error(format!("wire format error: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_fields_oversized_returns_error() {
        let huge = vec![0u8; (u32::MAX as usize) + 1];
        let result = encode_fields(&[&huge]);
        assert_eq!(result, Err(WireError::LengthOverflow));
    }

    #[test]
    fn encode_fields_empty_rejected() {
        let result = encode_fields(&[]);
        assert_eq!(result, Err(WireError::Other));
    }

    #[test]
    fn keygen_share_decode_rejects_oversized_crp() {
        let mut wire = vec![WIRE_V1]; // version
        let tag = Tag::WireFheKeygenShare.as_bytes();
        let oversized_len = 1_073_741_824u32; // 1GB — impossibly large
        let body_len: u32 = (tag.len() + 4 + 4 + 4 + 4) as u32; // tag + crp_len(4) + crp(4) + p0_len(4) + p0(4)
        wire.extend_from_slice(&body_len.to_be_bytes());
        wire.extend_from_slice(tag);
        wire.extend_from_slice(&oversized_len.to_be_bytes());
        wire.extend_from_slice(b"abcd");
        wire.extend_from_slice(&4u32.to_be_bytes());
        wire.extend_from_slice(b"efgh");
        let result = decode_keygen_share(&wire);
        assert!(result.is_err(), "oversized CRP should be rejected");
    }

    #[test]
    fn public_key_decode_rejects_oversized_p0() {
        let mut wire = vec![WIRE_V1]; // version
        let tag = Tag::WireFhePublicKey.as_bytes();
        let oversized_len = 1_073_741_824u32;
        let body_len = 4 + tag.len() + 4 + 4;
        wire.extend_from_slice(&(body_len as u32).to_be_bytes());
        wire.extend_from_slice(tag);
        wire.extend_from_slice(&oversized_len.to_be_bytes());
        wire.extend_from_slice(b"abcd");
        wire.extend_from_slice(&4u32.to_be_bytes());
        wire.extend_from_slice(b"efgh");
        let result = decode_public_key(&wire);
        assert!(result.is_err(), "oversized p0 should be rejected");
    }

    #[test]
    fn public_key_decode_rejects_oversized_p1() {
        let mut wire = vec![WIRE_V1]; // version
        let tag = Tag::WireFhePublicKey.as_bytes();
        let oversized_len = 1_073_741_824u32;
        let body_len = 4 + tag.len() + 4 + 4;
        wire.extend_from_slice(&(body_len as u32).to_be_bytes());
        wire.extend_from_slice(tag);
        wire.extend_from_slice(&4u32.to_be_bytes());
        wire.extend_from_slice(b"abcd");
        wire.extend_from_slice(&oversized_len.to_be_bytes());
        wire.extend_from_slice(b"efgh");
        let result = decode_public_key(&wire);
        assert!(result.is_err(), "oversized p1 should be rejected");
    }
}
