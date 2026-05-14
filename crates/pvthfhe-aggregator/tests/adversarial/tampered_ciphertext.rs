use super::*;
use pvthfhe_aggregator::decrypt::DecryptError;

const SEED: u64 = 46;

#[test]
fn adversarial_tampered_ciphertext_hash_is_rejected() {
    let fixture = decrypt_fixture(SEED);
    let mut shares = fixture.shares[..2].to_vec();
    shares[0].ciphertext_hash[0] ^= 0xFF;

    let result = aggregate_fixture_shares(&fixture, &shares);

    assert!(matches!(
        result,
        Err(DecryptError::InvalidShare { party_id: 1, .. })
    ));
}
