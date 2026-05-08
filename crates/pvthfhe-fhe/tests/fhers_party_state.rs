//! Integration tests for per-party decryption state plumbing in `FhersBackend`.

use pvthfhe_fhe::{fhers::FhersBackend, FheBackend, FheError};
use rand::thread_rng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn fhers_party_state_setup_threshold_populates_per_party_sums() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [31u8; 32];
    let mut rng = thread_rng();

    for party_id in 1u32..=5 {
        backend
            .keygen_share_with_session(&session_id, party_id, &mut rng)
            .expect("keygen share");
    }

    backend
        .setup_threshold(5, 3)
        .expect("setup threshold state");

    for party_id in 1u32..=5 {
        let state = backend
            .take_party_state(party_id)
            .expect("party state should exist");
        assert_eq!(state.sk_poly_sum.len(), backend.bfv_params().degree());
        assert!(state.esi_poly_sum.is_empty(), "smudging is deferred in C1");
    }

    assert!(matches!(
        backend.take_party_state(99),
        Err(FheError::UnknownParty { party_id: 99 })
    ));
}
