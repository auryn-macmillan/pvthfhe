use super::*;
use pvthfhe_aggregator::keygen::simulator::FaultType;

const SEED: u64 = 43;

#[test]
fn adversarial_withhold_reveal_blames_party_two() {
    let mut simulator = simulator_from_seed(SEED);
    simulator.inject_fault(2, FaultType::WithholdShare);

    let result = simulator.run().unwrap();

    assert_blamed(result, 2);
}
