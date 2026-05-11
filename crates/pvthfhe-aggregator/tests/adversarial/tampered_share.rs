use super::*;
use pvthfhe_aggregator::decrypt::DecryptError;

const SEED: u64 = 47;

#[test]
fn adversarial_tampered_share_nizk_is_rejected() {
    let fixture = decrypt_fixture(SEED);
    let mut shares = fixture.shares[..2].to_vec();
    shares[0].nizk = vec![0];

    let result = aggregate_fixture_shares(&fixture, &shares);

    assert!(matches!(
        result,
        Err(DecryptError::NizkVerify { party_id: 1 })
    ));
}
