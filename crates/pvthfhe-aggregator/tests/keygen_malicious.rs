//! Integration tests: keygen_malicious.
#![allow(clippy::unwrap_used)]
use pvthfhe_aggregator::keygen::simulator::{FaultType, KeygenResult, KeygenSimulator};
use pvthfhe_fhe::{mock::MockBackend, FheBackend};

#[test]
fn malformed_proof_blamed() {
    let toml = r#"
        [rlwe]
        n = 1024
        log2_q = 54
        t_plain = 65537
    "#;
    let backend = MockBackend::load_params(toml).unwrap();
    let mut sim = KeygenSimulator::new(4, 2, backend);
    sim.inject_fault(0, FaultType::MalformedProof);
    let result = sim.run().unwrap();
    match result {
        KeygenResult::Blamed(ids) => assert!(ids.contains(&0)),
        _ => unreachable!("Expected Blamed, got {:?}", result),
    }
}

#[test]
fn withhold_share_blamed() {
    let toml = r#"
        [rlwe]
        n = 1024
        log2_q = 54
        t_plain = 65537
    "#;
    let backend = MockBackend::load_params(toml).unwrap();
    let mut sim = KeygenSimulator::new(4, 2, backend);
    sim.inject_fault(1, FaultType::WithholdShare);
    let result = sim.run().unwrap();
    match result {
        KeygenResult::Blamed(ids) => assert!(ids.contains(&1)),
        _ => unreachable!("Expected Blamed, got {:?}", result),
    }
}

#[test]
fn equivocate_blamed() {
    let toml = r#"
        [rlwe]
        n = 1024
        log2_q = 54
        t_plain = 65537
    "#;
    let backend = MockBackend::load_params(toml).unwrap();
    let mut sim = KeygenSimulator::new(4, 2, backend);
    sim.inject_fault(2, FaultType::Equivocate);
    let result = sim.run().unwrap();
    match result {
        KeygenResult::Blamed(ids) => assert!(ids.contains(&2)),
        _ => unreachable!("Expected Blamed, got {:?}", result),
    }
}
