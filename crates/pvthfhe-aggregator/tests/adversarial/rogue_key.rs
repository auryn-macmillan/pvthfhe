use super::*;
use pvthfhe_aggregator::keygen::simulator::FaultType;

const SEED: u64 = 41;

#[test]
fn adversarial_rogue_key_fault_blames_party_zero() {
    let mut simulator = simulator_from_seed(SEED);
    simulator.inject_fault(0, FaultType::MalformedProof);

    let result = simulator.run().unwrap();

    assert_blamed(result, 0);
}
