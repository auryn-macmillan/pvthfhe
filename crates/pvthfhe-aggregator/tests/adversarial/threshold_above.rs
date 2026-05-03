use super::*;

const SEED: u64 = 49;

#[test]
fn adversarial_threshold_above_accepts_more_than_t_shares() {
    let fixture = decrypt_fixture(SEED);

    let recovered = aggregate_fixture_shares(&fixture, &fixture.shares).unwrap();

    assert_eq!(recovered, fixture.plaintext);
}
