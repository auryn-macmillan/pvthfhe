use super::*;
use pvthfhe_aggregator::keygen::simulator::FaultType;

const SEED: u64 = 42;

#[test]
fn adversarial_equivocation_blames_party_one() {
    let mut simulator = simulator_from_seed(SEED);
    simulator.inject_fault(1, FaultType::Equivocate);

    let result = simulator.run().unwrap();

    assert_blamed(result, 1);
}
