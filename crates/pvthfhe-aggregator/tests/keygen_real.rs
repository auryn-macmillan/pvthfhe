//! Integration test: keygen_real.

use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn must<T, E: core::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

#[test]
fn keygen_real_n8_produces_v1_public_key_bytes() {
    let backend = must(
        FhersBackend::load_params(TEST_PARAMS_TOML),
        "load real backend",
    );
    let mut simulator = KeygenSimulator::new_with_backend(8, 5, backend);
    let result = must(simulator.run(), "run keygen simulator");

    let transcript = match result {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(blamed) => panic!("expected complete transcript, blamed: {blamed:?}"),
    };

    assert_eq!(transcript.participant_set.len(), 8);
    assert_eq!(transcript.round1_messages.len(), 8);
    assert_eq!(transcript.round2_messages.len(), 8);
    assert_eq!(
        transcript
            .round3_aggregate
            .aggregate_pk
            .bytes
            .first()
            .copied(),
        Some(0x01)
    );
    let decoded = must(
        wire::decode_public_key(&transcript.round3_aggregate.aggregate_pk.bytes),
        "decode aggregate public key",
    );
    assert!(!decoded.p0.is_empty());
    assert!(!decoded.p1.is_empty());
}
