//! Versioned wire formats for FHE byte payloads.
//!
//! These encodings back the opaque `bytes` fields exposed by the crate's public
//! wrapper types. They are versioned so later tasks can evolve the payload
//! layout without changing those wrapper structs.

use crate::FheError;

const WIRE_V1: u8 = 0x01;
const LENGTH_PREFIX_BYTES: usize = 4;

/// Version-1 key generation share wire payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeygenShareV1 {
    /// Common random polynomial bytes.
    pub crp: Vec<u8>,
    /// Party-zero public key share bytes.
    pub p0_share: Vec<u8>,
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
    pub d_share_poly: Vec<u8>,
}

/// Encode a version-1 key generation share.
pub fn encode_keygen_share(crp: &[u8], p0_share: &[u8]) -> Vec<u8> {
    encode_fields(&[crp, p0_share])
}

/// Decode a version-1 key generation share.
pub fn decode_keygen_share(bytes: &[u8]) -> Result<KeygenShareV1, FheError> {
    let mut decoder = Decoder::new(bytes)?;
    let crp = decoder.read_field()?;
    let p0_share = decoder.read_field()?;
    decoder.finish()?;

    Ok(KeygenShareV1 { crp, p0_share })
}

/// Encode a version-1 public key.
pub fn encode_public_key(p0: &[u8], p1: &[u8]) -> Vec<u8> {
    encode_fields(&[p0, p1])
}

/// Decode a version-1 public key.
pub fn decode_public_key(bytes: &[u8]) -> Result<PublicKeyV1, FheError> {
    let mut decoder = Decoder::new(bytes)?;
    let p0 = decoder.read_field()?;
    let p1 = decoder.read_field()?;
    decoder.finish()?;

    Ok(PublicKeyV1 { p0, p1 })
}

/// Encode a version-1 decryption share.
pub fn encode_decrypt_share(d_share_poly: &[u8]) -> Vec<u8> {
    encode_fields(&[d_share_poly])
}

/// Decode a version-1 decryption share.
pub fn decode_decrypt_share(bytes: &[u8]) -> Result<DecryptShareV1, FheError> {
    let mut decoder = Decoder::new(bytes)?;
    let d_share_poly = decoder.read_field()?;
    decoder.finish()?;

    Ok(DecryptShareV1 { d_share_poly })
}

fn encode_fields(fields: &[&[u8]]) -> Vec<u8> {
    let payload_len: usize = fields
        .iter()
        .map(|field| LENGTH_PREFIX_BYTES + field.len())
        .sum();
    let mut out = Vec::with_capacity(1 + payload_len);
    out.push(WIRE_V1);

    for field in fields {
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
    fn new(bytes: &'a [u8]) -> Result<Self, FheError> {
        if bytes.is_empty() {
            return Err(decode_error("missing version byte"));
        }

        if bytes[0] != WIRE_V1 {
            return Err(decode_error(format!(
                "unsupported wire version: 0x{:02x}",
                bytes[0]
            )));
        }

        Ok(Self { bytes, offset: 1 })
    }

    fn read_field(&mut self) -> Result<Vec<u8>, FheError> {
        let len_end = self
            .offset
            .checked_add(LENGTH_PREFIX_BYTES)
            .ok_or_else(|| decode_error("length prefix overflow"))?;
        let len_bytes = self
            .bytes
            .get(self.offset..len_end)
            .ok_or_else(|| decode_error("truncated length prefix"))?;
        let len = u32::from_be_bytes(len_bytes.try_into().expect("slice length checked"));
        self.offset = len_end;

        let field_len = usize::try_from(len).expect("u32 always fits into usize");
        let field_end = self
            .offset
            .checked_add(field_len)
            .ok_or_else(|| decode_error("field length overflow"))?;
        let field = self
            .bytes
            .get(self.offset..field_end)
            .ok_or_else(|| decode_error("truncated field bytes"))?;
        self.offset = field_end;

        Ok(field.to_vec())
    }

    fn finish(self) -> Result<(), FheError> {
        if self.offset != self.bytes.len() {
            return Err(decode_error("trailing bytes after wire payload"));
        }

        Ok(())
    }
}

fn decode_error(reason: impl Into<String>) -> FheError {
    FheError::DecodeError {
        reason: reason.into(),
    }
}
