//! Integration tests for aggregate public-key generation in `FhersBackend`.

use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};
use rand::thread_rng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn fhers_aggregate_keygen_returns_v1_public_key_bytes() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [24u8; 32];
    let mut rng = thread_rng();

    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let decoded = wire::decode_public_key(&pk.bytes).expect("decode public key");

    assert_eq!(pk.bytes[0], 0x01);
    assert!(!decoded.p0.is_empty(), "p0 should not be empty");
    assert!(!decoded.p1.is_empty(), "p1 should not be empty");
}
