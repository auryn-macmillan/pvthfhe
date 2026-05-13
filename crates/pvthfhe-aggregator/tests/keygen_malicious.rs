//! Integration tests: keygen_malicious.
#![allow(clippy::unwrap_used)]
use pvthfhe_aggregator::keygen::simulator::{FaultType, KeygenResult, KeygenSimulator};
use pvthfhe_fhe::{mock::MockBackend, FheBackend};

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn malformed_proof_blamed() {
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
    let mut sim = KeygenSimulator::new(5, 2, backend).unwrap();
    sim.inject_fault(1, FaultType::MalformedProof);
    let result = sim.run().unwrap();
    match result {
        KeygenResult::Blamed(ids) => assert!(ids.contains(&1)),
        _ => unreachable!("Expected Blamed, got {:?}", result),
    }
}

#[test]
fn withhold_share_blamed() {
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
    let mut sim = KeygenSimulator::new(5, 2, backend).unwrap();
    sim.inject_fault(1, FaultType::WithholdShare);
    let result = sim.run().unwrap();
    match result {
        KeygenResult::Blamed(ids) => assert!(ids.contains(&1)),
        _ => unreachable!("Expected Blamed, got {:?}", result),
    }
}

#[test]
fn equivocate_blamed() {
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
    let mut sim = KeygenSimulator::new(5, 2, backend).unwrap();
    sim.inject_fault(2, FaultType::Equivocate);
    let result = sim.run().unwrap();
    match result {
        KeygenResult::Blamed(ids) => assert!(ids.contains(&2)),
        _ => unreachable!("Expected Blamed, got {:?}", result),
    }
}
