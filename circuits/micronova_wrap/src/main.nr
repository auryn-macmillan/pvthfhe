use poseidon;

fn expected_d_commitment(dkg_root: Field, participant_set_hash: Field) -> Field {
    poseidon::poseidon::bn254::hash_2([dkg_root, participant_set_hash])
}

fn expected_accumulated_hash(
    ciphertext_hash: Field,
    plaintext_hash: Field,
    aggregate_pk_hash: Field,
    dkg_root: Field,
    epoch: Field,
    participant_set_hash: Field,
    d_commitment: Field,
) -> Field {
    let combined = poseidon::poseidon::bn254::hash_5([
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
    ]);

    poseidon::poseidon::bn254::hash_4([
        combined,
        participant_set_hash,
        d_commitment,
        epoch,
    ])
}

fn main(
    ciphertext_hash: pub Field,
    plaintext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    dkg_root: pub Field,
    epoch: pub Field,
    participant_set_hash: pub Field,
    d_commitment: pub Field,
    accumulated_hash: Field,
) -> pub Field {
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(participant_set_hash != 0, "participant_set_hash must be non-zero");
    assert(ciphertext_hash != plaintext_hash, "ciphertext_hash must differ from plaintext_hash");

    let expected_d = expected_d_commitment(dkg_root, participant_set_hash);
    assert(expected_d == d_commitment, "d_commitment mismatch");

    let expected_accumulated = expected_accumulated_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );
    assert(expected_accumulated == accumulated_hash, "accumulator mismatch");

    accumulated_hash
}

#[test]
fn test_honest() {
    let ciphertext_hash: Field = 11;
    let plaintext_hash: Field = 22;
    let aggregate_pk_hash: Field = 33;
    let dkg_root: Field = 44;
    let epoch: Field = 1;
    let participant_set_hash: Field = 55;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let accumulated_hash = expected_accumulated_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );

    let output = main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        accumulated_hash,
    );

    assert(output == accumulated_hash, "public accumulator output mismatch");
}

#[test(should_fail)]
fn test_fail_zero_epoch() {
    let ciphertext_hash: Field = 11;
    let plaintext_hash: Field = 22;
    let aggregate_pk_hash: Field = 33;
    let dkg_root: Field = 44;
    let epoch: Field = 0;
    let participant_set_hash: Field = 55;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let accumulated_hash = expected_accumulated_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );

    let _ = main(
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

#[test(should_fail)]
fn test_fail_tampered_d_commitment() {
    let ciphertext_hash: Field = 11;
    let plaintext_hash: Field = 22;
    let aggregate_pk_hash: Field = 33;
    let dkg_root: Field = 44;
    let epoch: Field = 1;
    let participant_set_hash: Field = 55;
    let honest_d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let tampered_d_commitment = honest_d_commitment + 1;
    let accumulated_hash = expected_accumulated_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        tampered_d_commitment,
    );

    let _ = main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        tampered_d_commitment,
        accumulated_hash,
    );
}

#[test(should_fail)]
fn test_fail_wrong_accumulated_hash() {
    let ciphertext_hash: Field = 11;
    let plaintext_hash: Field = 22;
    let aggregate_pk_hash: Field = 33;
    let dkg_root: Field = 44;
    let epoch: Field = 1;
    let participant_set_hash: Field = 55;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let accumulated_hash = expected_accumulated_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    ) + 1;

    let _ = main(
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

#[test]
fn test_all_seven_inputs_constrained() {
    let ciphertext_hash = 0x1111111111111111111111111111111111111111111111111111111111111111;
    let plaintext_hash = 0x2222222222222222222222222222222222222222222222222222222222222222;
    let aggregate_pk_hash = 0x0333333333333333333333333333333333333333333333333333333333333333;
    let dkg_root = 0x0444444444444444444444444444444444444444444444444444444444444444;
    let epoch = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let participant_set_hash = 0x0555555555555555555555555555555555555555555555555555555555555555;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let accumulated_hash = expected_accumulated_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );

    let _ = main(
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
