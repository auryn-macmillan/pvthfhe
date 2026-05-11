use proptest::prelude::*;
use pvthfhe_domain_tags::Tag;
use pvthfhe_wire::{WireError, WireFormat};

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestPayload(Vec<u8>);

impl WireFormat for TestPayload {
    const VERSION: u8 = 1;
    const TAG: Tag = Tag::WireTestPayload;

    fn encode_body(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self(bytes.to_vec()))
    }
}

fn assert_round_trip<T>(payload: T)
where
    T: WireFormat + PartialEq + core::fmt::Debug,
{
    let encoded = payload.encode();
    let decoded = T::decode(&encoded).unwrap();
    assert_eq!(decoded, payload);
}

proptest! {
    #[test]
    fn round_trip_property(payload in any::<Vec<u8>>()) {
        // RED: this should not compile until GREEN adds `impl WireFormat for TestPayload`.
        assert_round_trip(TestPayload(payload));
    }
}

#[test]
fn decode_rejects_trailing_bytes() {
    let encoded = TestPayload(vec![1, 2, 3]).encode();
    let mut with_trailing = encoded.clone();
    with_trailing.push(0xFF);

    assert_eq!(
        TestPayload::decode(&with_trailing),
        Err(WireError::TrailingBytes)
    );
}

#[test]
fn decode_rejects_wrong_version_byte() {
    let bytes_with_version_zero = vec![0x00, 0x01, 0x02];

    assert_eq!(
        TestPayload::decode(&bytes_with_version_zero),
        Err(WireError::BadVersion)
    );
}

#[test]
fn decode_rejects_missing_length_prefix() {
    let missing_length_prefix = vec![TestPayload::VERSION];

    assert_eq!(
        TestPayload::decode(&missing_length_prefix),
        Err(WireError::MissingLengthPrefix)
    );
}
