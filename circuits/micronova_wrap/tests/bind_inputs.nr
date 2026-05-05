use poseidon;

#[test]
fn test_all_seven_inputs_constrained() {
    let ciphertext_hash = 0x1111111111111111111111111111111111111111111111111111111111111111;
    let plaintext_hash = 0x2222222222222222222222222222222222222222222222222222222222222222;
    let aggregate_pk_hash = 0x0333333333333333333333333333333333333333333333333333333333333333;
    let dkg_root = 0x0444444444444444444444444444444444444444444444444444444444444444;
    let epoch = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let participant_set_hash = 0x0555555555555555555555555555555555555555555555555555555555555555;
    let d_commitment = poseidon::poseidon::bn254::hash_2([dkg_root, participant_set_hash]);
    let combined = poseidon::poseidon::bn254::hash_5([
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
    ]);
    let accumulated_hash = poseidon::poseidon::bn254::hash_4([
        combined,
        participant_set_hash,
        d_commitment,
        epoch,
    ]);

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        accumulated_hash,
    );
}
