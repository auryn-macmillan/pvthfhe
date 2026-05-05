use poseidon;

fn expected_d_commitment(dkg_root: Field, participant_set_hash: Field) -> Field {
    poseidon::poseidon::bn254::hash_2([dkg_root, participant_set_hash])
}

fn expected_final_acc_hash(
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
    final_acc_hash: Field,
    n_participants: pub Field,
) {
    assert(epoch as u64 > 0, "epoch must be positive");

    let expected_d = expected_d_commitment(dkg_root, participant_set_hash);
    assert(expected_d == d_commitment, "d_commitment mismatch");

    let expected_acc = expected_final_acc_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );
    assert(expected_acc == final_acc_hash, "accumulator mismatch");

    assert(n_participants as u64 > 0, "n_participants must be positive");
}

#[test]
fn test_honest() {
    let ciphertext_hash: Field = 101;
    let plaintext_hash: Field = 202;
    let aggregate_pk_hash: Field = 303;
    let dkg_root: Field = 404;
    let epoch: Field = 9;
    let participant_set_hash: Field = 505;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let final_acc_hash = expected_final_acc_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );
    let n_participants: Field = 16;

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        final_acc_hash,
        n_participants,
    );
}

#[test(should_fail)]
fn test_fail_zero_epoch() {
    let ciphertext_hash: Field = 101;
    let plaintext_hash: Field = 202;
    let aggregate_pk_hash: Field = 303;
    let dkg_root: Field = 404;
    let epoch: Field = 0;
    let participant_set_hash: Field = 505;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let final_acc_hash = expected_final_acc_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );
    let n_participants: Field = 16;

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        final_acc_hash,
        n_participants,
    );
}

#[test(should_fail)]
fn test_fail_tampered_d_commitment() {
    let ciphertext_hash: Field = 101;
    let plaintext_hash: Field = 202;
    let aggregate_pk_hash: Field = 303;
    let dkg_root: Field = 404;
    let epoch: Field = 9;
    let participant_set_hash: Field = 505;
    let honest_d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let tampered_d_commitment = honest_d_commitment + 1;
    let final_acc_hash = expected_final_acc_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        tampered_d_commitment,
    );
    let n_participants: Field = 16;

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        tampered_d_commitment,
        final_acc_hash,
        n_participants,
    );
}

#[test(should_fail)]
fn test_fail_wrong_final_acc_hash() {
    let ciphertext_hash: Field = 101;
    let plaintext_hash: Field = 202;
    let aggregate_pk_hash: Field = 303;
    let dkg_root: Field = 404;
    let epoch: Field = 9;
    let participant_set_hash: Field = 505;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let final_acc_hash = expected_final_acc_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    ) + 1;
    let n_participants: Field = 16;

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        final_acc_hash,
        n_participants,
    );
}

#[test(should_fail)]
fn test_fail_zero_participants() {
    let ciphertext_hash: Field = 101;
    let plaintext_hash: Field = 202;
    let aggregate_pk_hash: Field = 303;
    let dkg_root: Field = 404;
    let epoch: Field = 9;
    let participant_set_hash: Field = 505;
    let d_commitment = expected_d_commitment(dkg_root, participant_set_hash);
    let final_acc_hash = expected_final_acc_hash(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
    );
    let n_participants: Field = 0;

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        final_acc_hash,
        n_participants,
    );
}
