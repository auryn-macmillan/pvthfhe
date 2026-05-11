//! Canonical wire format for PVTHFHE adapters. Phase R0.5.

use pvthfhe_domain_tags::Tag;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    TrailingBytes,
    BadVersion,
    MissingLengthPrefix,
    BadTag,
    LengthOverflow,
    Other,
}

/// Canonical versioned, length-prefixed PVTHFHE wire envelope.
///
/// Wire layout:
/// `[version: u8][len: u32 BE][body: len bytes]`
///
/// The framed body is domain-separated as `Self::TAG.as_bytes() || payload`.
/// Implementations encode and decode only the deterministic payload bytes via
/// [`Self::encode_body`] and [`Self::decode_body`].
pub trait WireFormat: Sized {
    const VERSION: u8;
    const TAG: Tag;

    fn encode_body(&self) -> Vec<u8>;

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError>;

    fn encode(&self) -> Vec<u8> {
        let payload = self.encode_body();
        let tag = Self::TAG.as_bytes();
        let body_len = tag
            .len()
            .checked_add(payload.len())
            .expect("wire body length overflow");
        let body_len = u32::try_from(body_len).expect("wire body length exceeds u32");

        let mut out = Vec::with_capacity(1 + 4 + tag.len() + payload.len());
        out.push(Self::VERSION);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(&payload);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let version = *bytes.first().ok_or(WireError::MissingLengthPrefix)?;
        if version != Self::VERSION {
            return Err(WireError::BadVersion);
        }

        if bytes.len() < 5 {
            return Err(WireError::MissingLengthPrefix);
        }

        let len = u32::from_be_bytes(bytes[1..5].try_into().expect("slice length checked"));
        let len = usize::try_from(len).map_err(|_| WireError::LengthOverflow)?;
        let expected_end = 5usize.checked_add(len).ok_or(WireError::LengthOverflow)?;
        if bytes.len() > expected_end {
            return Err(WireError::TrailingBytes);
        }
        if bytes.len() < expected_end {
            return Err(WireError::MissingLengthPrefix);
        }

        let body = &bytes[5..expected_end];
        let tag = Self::TAG.as_bytes();
        let payload = body.strip_prefix(tag).ok_or(WireError::BadTag)?;
        Self::decode_body(payload)
    }
}
