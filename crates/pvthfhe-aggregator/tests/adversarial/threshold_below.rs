use super::*;
use pvthfhe_aggregator::decrypt::DecryptError;

const SEED: u64 = 48;

#[test]
fn adversarial_threshold_below_rejects_t_minus_one_shares() {
    let fixture = decrypt_fixture(SEED);

    let result = aggregate_fixture_shares(&fixture, &fixture.shares[..fixture.threshold - 1]);

    assert!(matches!(
        result,
        Err(DecryptError::InsufficientShares { needed, got }) if needed == fixture.threshold && got == fixture.threshold - 1
    ));
}
