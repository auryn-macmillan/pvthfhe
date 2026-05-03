//! Integration tests: keygen_honest.
#![allow(clippy::unwrap_used)]
use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_fhe::{mock::MockBackend, FheBackend};

#[test]
fn honest_n4_keygen() {
    let toml = r#"
        [rlwe]
        n = 1024
        log2_q = 54
        t_plain = 65537
    "#;
    let backend = MockBackend::load_params(toml).unwrap();
    let mut sim = KeygenSimulator::new(4, 2, backend);
    let result = sim.run().unwrap();
    assert!(matches!(result, KeygenResult::Complete(_)));
}
