#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration test for real keygen shares in `FhersBackend`.

use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};
use rand::thread_rng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn fhers_keygen_share_uses_v1_wire_and_session_scoped_crp() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [42u8; 32];
    let mut rng = thread_rng();

    let shares = [1u32, 2, 3]
        .into_iter()
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    let decoded = shares
        .iter()
        .map(|share| wire::decode_keygen_share(&share.bytes).expect("decode keygen share"))
        .collect::<Vec<_>>();

    for share in &shares {
        assert_eq!(share.bytes[0], 0x01);
    }

    assert!(decoded
        .windows(2)
        .all(|window| window[0].crp == window[1].crp));
}
