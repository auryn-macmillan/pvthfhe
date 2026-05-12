//! Versioned wire formats for FHE byte payloads.
//!
//! These encodings back the opaque `bytes` fields exposed by the crate's public
//! wrapper types. They are versioned so later tasks can evolve the payload
//! layout without changing those wrapper structs.

use crate::FheError;
use pvthfhe_domain_tags::Tag;
use pvthfhe_types::ProtocolBytes;
use pvthfhe_wire::{WireError, WireFormat};

const WIRE_V1: u8 = 0x01;
const LENGTH_PREFIX_BYTES: usize = 4;

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

/// Version-1 decryption share wire payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptShareV1 {
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

/// Encode a version-1 decryption share.
pub fn encode_decrypt_share(d_share_poly: &[u8]) -> Vec<u8> {
    DecryptShareV1 {
        d_share_poly: ProtocolBytes(d_share_poly.to_vec()),
    }
    .encode()
}

/// Decode a version-1 decryption share.
pub fn decode_decrypt_share(bytes: &[u8]) -> Result<DecryptShareV1, FheError> {
    DecryptShareV1::decode(bytes).map_err(wire_error)
}

impl WireFormat for KeygenShareV1 {
    const VERSION: u8 = WIRE_V1;
    const TAG: Tag = Tag::WireFheKeygenShare;

    fn encode_body(&self) -> Vec<u8> {
        encode_fields(&[self.crp.as_slice(), self.p0_share.as_slice()])
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let crp = decoder.read_field()?;
        let p0_share = decoder.read_field()?;
        decoder.finish()?;

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
        encode_fields(&[&self.p0, &self.p1])
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let p0 = decoder.read_field()?;
        let p1 = decoder.read_field()?;
        decoder.finish()?;

        Ok(Self { p0, p1 })
    }
}

impl WireFormat for DecryptShareV1 {
    const VERSION: u8 = WIRE_V1;
    const TAG: Tag = Tag::WireFheDecryptShare;

    fn encode_body(&self) -> Vec<u8> {
        encode_fields(&[self.d_share_poly.as_slice()])
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes);
        let d_share_poly = decoder.read_field()?;
        decoder.finish()?;

        Ok(Self {
            d_share_poly: ProtocolBytes(d_share_poly),
        })
    }
}

fn encode_fields(fields: &[&[u8]]) -> Vec<u8> {
    let payload_len: usize = fields
        .iter()
        .map(|field| LENGTH_PREFIX_BYTES + field.len())
        .sum();
    let mut out = Vec::with_capacity(payload_len);

    for field in fields {
        #[allow(clippy::expect_used)]
        let len = u32::try_from(field.len()).expect("wire field length exceeds u32");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }

    out
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
