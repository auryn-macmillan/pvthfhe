//! Integration tests: keygen_honest.
#![allow(clippy::unwrap_used)]
use pvthfhe_aggregator::keygen::simulator::{KeygenError, KeygenResult, KeygenSimulator};
use pvthfhe_fhe::{mock::MockBackend, FheBackend};

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

fn mock_backend() -> MockBackend {
    acknowledge_mock_backend();
    let toml = r#"
        [rlwe]
        n = 1024
        log2_q = 54
        t_plain = 65537
        moduli = [288230376173076481, 288230376167047169, 288230376161280001]
        variance = 10
    "#;
    MockBackend::load_params(toml).unwrap()
}

#[test]
fn honest_n5_keygen() {
    let backend = mock_backend();
    let mut sim = KeygenSimulator::new(5, 2, backend).unwrap();
    let result = sim.run().unwrap();
    assert!(matches!(result, KeygenResult::Complete(_)));
}

#[test]
fn new_rejects_t_zero() {
    let backend = mock_backend();
    let result = KeygenSimulator::new(3, 0, backend);
    assert!(matches!(
        result,
        Err(KeygenError::InvalidThreshold { n: 3, t: 0 })
    ));
}

#[test]
fn new_rejects_t_greater_than_n() {
    let backend = mock_backend();
    let result = KeygenSimulator::new(3, 4, backend);
    assert!(matches!(
        result,
        Err(KeygenError::InvalidThreshold { n: 3, t: 4 })
    ));
}

#[test]
fn new_rejects_n_zero() {
    let backend = mock_backend();
    let result = KeygenSimulator::new(0, 1, backend);
    assert!(matches!(
        result,
        Err(KeygenError::InvalidThreshold { n: 0, t: 1 })
    ));
}

#[test]
fn new_rejects_t_exceeds_max_threshold() {
    let backend = mock_backend();
    // n=10, max_t = (10-1)/2 = 4. t=6 exceeds.
    let result = KeygenSimulator::new(10, 6, backend);
    assert!(matches!(
        result,
        Err(KeygenError::InvalidThreshold { n: 10, t: 6 })
    ));
}

#[test]
fn new_accepts_valid_threshold() {
    let backend = mock_backend();
    // n=10, max_t = (10-1)/2 = 4. t=4 is valid.
    assert!(KeygenSimulator::new(10, 4, backend).is_ok());
}
