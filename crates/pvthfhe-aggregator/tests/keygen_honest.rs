//! Integration tests: keygen_honest.
#![allow(clippy::unwrap_used)]
use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_fhe::{mock::MockBackend, FheBackend};

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn honest_n4_keygen() {
    acknowledge_mock_backend();
    let toml = r#"
        [rlwe]
        n = 1024
        log2_q = 54
        t_plain = 65537
        moduli = [288230376173076481, 288230376167047169, 288230376161280001]
        variance = 10
    "#;
    let backend = MockBackend::load_params(toml).unwrap();
    let mut sim = KeygenSimulator::new(4, 2, backend);
    let result = sim.run().unwrap();
    assert!(matches!(result, KeygenResult::Complete(_)));
}
