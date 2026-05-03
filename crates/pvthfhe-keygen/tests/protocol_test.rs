use pvthfhe_keygen::{
    BFVPublicKey, BlameProof, KeygenSession, Participant, PublicVerificationArtifact, Share,
};

fn sample_participants() -> Vec<Participant> {
    vec![
        Participant { id: 1 },
        Participant { id: 2 },
        Participant { id: 3 },
    ]
}

fn sample_session() -> KeygenSession {
    KeygenSession {
        session_id: "p4-session-alpha".to_owned(),
        threshold: 2,
    }
}

fn sample_share() -> Share {
    Share {
        session_id: "p4-session-alpha".to_owned(),
    }
}

fn sample_artifact() -> PublicVerificationArtifact {
    PublicVerificationArtifact {
        session_id: "p4-session-alpha".to_owned(),
    }
}

fn sample_blame() -> BlameProof {
    BlameProof {
        session_id: "p4-session-alpha".to_owned(),
        reason: "commitment_mismatch".to_owned(),
    }
}

fn sample_bfv_key() -> BFVPublicKey {
    BFVPublicKey {
        bytes: vec![0xde, 0xad, 0xbe, 0xef],
    }
}

#[test]
fn t1_honest_n_of_n_keygen_yields_valid_bfv_public_key() {
    let _participants = sample_participants();
    let _session = sample_session();
    let _share = sample_share();
    let _artifact = sample_artifact();
    let _key = sample_bfv_key();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t1_reconstruction_is_consistent_across_authorized_sets() {
    let _participants = sample_participants();
    let _session = sample_session();
    let _shares = vec![sample_share(), sample_share()];
    let _key = sample_bfv_key();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t2_reconstructed_key_does_not_expose_individual_shares() {
    let _session = sample_session();
    let _shares = vec![sample_share(), sample_share()];
    let _key = sample_bfv_key();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t2_corrupted_view_stays_bound_to_public_transcript() {
    let _session = sample_session();
    let _artifact = sample_artifact();
    let _share = sample_share();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t3_invalid_dealing_is_rejected_by_verify() {
    let _artifact = sample_artifact();
    let _session = sample_session();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t3_bad_commitment_transcript_does_not_verify() {
    let _artifact = sample_artifact();
    let _share = sample_share();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t4_cheating_dealer_produces_blame_proof() {
    let _blame = sample_blame();
    let _artifact = sample_artifact();
    let _session = sample_session();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t4_blame_proof_names_guilty_dealer_not_honest_party() {
    let _blame = sample_blame();
    let _session = sample_session();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t5_session_state_advances_through_protocol_steps() {
    let _session = sample_session();
    let _participants = sample_participants();
    let _artifact = sample_artifact();
    unimplemented!("TODO: implement in A.I.2");
}

#[test]
fn t5_aborted_session_preserves_transition_invariants() {
    let _session = sample_session();
    let _blame = sample_blame();
    let _share = sample_share();
    unimplemented!("TODO: implement in A.I.2");
}
