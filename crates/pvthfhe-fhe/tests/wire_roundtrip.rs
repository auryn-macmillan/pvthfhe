//! Round-trip tests for versioned FHE wire payloads.

use pvthfhe_fhe::wire::{
    decode_decrypt_share, decode_keygen_share, decode_public_key, encode_decrypt_share,
    encode_keygen_share, encode_public_key,
};

#[test]
fn wire_keygen_share_round_trips_with_v1_prefix() {
    let crp_bytes = [0x10, 0x20, 0x30, 0x40];
    let p0_share_bytes = [0xaa, 0xbb, 0xcc];

    let encoded = encode_keygen_share(&crp_bytes, &p0_share_bytes);
    let decoded = decode_keygen_share(&encoded).expect("keygen share should decode");

    assert_eq!(encoded[0], 0x01);
    assert_eq!(decoded.crp.as_slice(), crp_bytes);
    assert_eq!(decoded.p0_share.as_slice(), p0_share_bytes);
}

#[test]
fn wire_public_key_round_trips_with_v1_prefix() {
    let p0_bytes = [0x01, 0x02, 0x03];
    let p1_bytes = [0xf0, 0xe0, 0xd0, 0xc0];

    let encoded = encode_public_key(&p0_bytes, &p1_bytes);
    let decoded = decode_public_key(&encoded).expect("public key should decode");

    assert_eq!(encoded[0], 0x01);
    assert_eq!(decoded.p0, p0_bytes);
    assert_eq!(decoded.p1, p1_bytes);
}

#[test]
fn wire_decrypt_share_round_trips_with_v1_prefix() {
    let d_share_poly = [0xde, 0xad, 0xbe, 0xef];

    let encoded = encode_decrypt_share(&d_share_poly);
    let decoded = decode_decrypt_share(&encoded).expect("decrypt share should decode");

    assert_eq!(encoded[0], 0x01);
    assert_eq!(decoded.d_share_poly.as_slice(), d_share_poly);
}
