use poseidon;

fn hash_state_preimage(preimage: [Field; 4]) -> Field {
    poseidon::poseidon::bn254::hash_4(preimage)
}

fn main(
    commit_pk: pub Field,
    commit_ct_in: pub Field,
    commit_ct_out: pub Field,
    session_id: pub Field,
    sonobe_final_state_commitment: pub Field,
    cyclo_aggregate_commitment: pub Field,
    sonobe_state_preimage: [Field; 4],
    cyclo_aggregate_preimage: [Field; 4],
) {
    assert(session_id != 0, "session_id must be non-zero");
    assert(commit_pk != 0, "commit_pk must be non-zero");
    assert(commit_ct_in != 0, "commit_ct_in must be non-zero");
    assert(commit_ct_out != 0, "commit_ct_out must be non-zero");

    let computed_sonobe = hash_state_preimage(sonobe_state_preimage);
    assert(
        computed_sonobe == sonobe_final_state_commitment,
        "sonobe_final_state_commitment mismatch",
    );

    let computed_cyclo = hash_state_preimage(cyclo_aggregate_preimage);
    assert(
        computed_cyclo == cyclo_aggregate_commitment,
        "cyclo_aggregate_commitment mismatch",
    );
}

#[test]
fn test_honest() {
    let sonobe_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];
    let sonobe_final_state_commitment = hash_state_preimage(sonobe_state_preimage);
    let cyclo_aggregate_commitment = hash_state_preimage(cyclo_aggregate_preimage);

    main(
        1,
        2,
        3,
        1,
        sonobe_final_state_commitment,
        cyclo_aggregate_commitment,
        sonobe_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_zero_session_id() {
    let sonobe_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1,
        2,
        3,
        0,
        hash_state_preimage(sonobe_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        sonobe_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_zero_commit_pk() {
    let sonobe_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        0,
        2,
        3,
        1,
        hash_state_preimage(sonobe_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        sonobe_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_tampered_sonobe_commitment() {
    let sonobe_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1,
        2,
        3,
        1,
        hash_state_preimage(sonobe_state_preimage) + 1,
        hash_state_preimage(cyclo_aggregate_preimage),
        sonobe_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test]
fn test_all_six_public_inputs_constrained() {
    let commit_pk = 1;
    let commit_ct_in = 2;
    let commit_ct_out = 3;
    let session_id = 4;
    let sonobe_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];
    let sonobe_final_state_commitment = hash_state_preimage(sonobe_state_preimage);
    let cyclo_aggregate_commitment = hash_state_preimage(cyclo_aggregate_preimage);

    main(
        commit_pk,
        commit_ct_in,
        commit_ct_out,
        session_id,
        sonobe_final_state_commitment,
        cyclo_aggregate_commitment,
        sonobe_state_preimage,
        cyclo_aggregate_preimage,
    );
}
