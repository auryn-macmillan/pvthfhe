use super::*;
use pvthfhe_aggregator::keygen::simulator::FaultType;

const SEED: u64 = 44;

#[test]
fn adversarial_malformed_nizk_blames_party_one() {
    let mut simulator = simulator_from_seed(SEED);
    simulator.inject_fault(1, FaultType::MalformedProof);

    let result = simulator.run().unwrap();

    assert_blamed(result, 1);
}
