use super::*;
use pvthfhe_aggregator::decrypt::DecryptError;

const SEED: u64 = 45;

#[test]
fn adversarial_replayed_share_is_rejected_as_duplicate_party() {
    let fixture = decrypt_fixture(SEED);
    let replayed = vec![fixture.shares[0].clone(), fixture.shares[0].clone()];

    let result = aggregate_fixture_shares(&fixture, &replayed);

    assert!(matches!(result, Err(DecryptError::DuplicateParty(1))));
}
