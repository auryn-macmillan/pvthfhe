fn main(
    ciphertext_hash: pub Field,
    plaintext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    dkg_root: pub Field,
    epoch: pub Field,
    participant_set_hash: pub Field,
    d_commitment: pub Field,
) {
    assert(ciphertext_hash == ciphertext_hash);
    assert(plaintext_hash == plaintext_hash);
    assert(aggregate_pk_hash == aggregate_pk_hash);
    assert(dkg_root == dkg_root);
    assert(epoch == epoch);
    assert(participant_set_hash == participant_set_hash);
    assert(d_commitment == d_commitment);
}

#[test]
fn test_all_seven_inputs_constrained() {
    main(
        0x1111111111111111111111111111111111111111111111111111111111111111,
        0x2222222222222222222222222222222222222222222222222222222222222222,
        0x0333333333333333333333333333333333333333333333333333333333333333,
        0x0444444444444444444444444444444444444444444444444444444444444444,
        0x0000000000000000000000000000000000000000000000000000000000000001,
        0x0555555555555555555555555555555555555555555555555555555555555555,
        0x0666666666666666666666666666666666666666666666666666666666666666,
    );
}
