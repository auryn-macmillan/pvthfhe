#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use pvthfhe_keygen_spec::{
    compute_accepted_participant_set_hash, AggregatedESmShareCommitment,
    AggregatedSkShareCommitment, Commitment, DkgAnchorSet, HexBlob, SmudgeSlotPolicy,
};

fn c(hex: &str) -> Commitment {
    Commitment {
        scheme: "test-pedersen".into(),
        digest: HexBlob(hex.into()),
    }
}

fn sample_policy() -> SmudgeSlotPolicy {
    SmudgeSlotPolicy {
        slots_per_party: 16,
        pre_generated: true,
        policy_hash: HexBlob("policy-hash-01".into()),
    }
}

fn sample_anchor() -> DkgAnchorSet {
    DkgAnchorSet {
        session_id: "s1".into(),
        accepted_participant_ids: vec![1, 3, 5],
        participant_set_hash: compute_accepted_participant_set_hash(&[1, 3, 5])
            .expect("accepted set hash"),
        threshold: 4,
        individual_bfv_pk_commitments: vec![c("ibfvpk-1")],
        threshold_pk_contribution_commitments: vec![c("tpk-1")],
        sk_agg_commits: vec![AggregatedSkShareCommitment {
            recipient_id: 3,
            commitment: c("ask-3"),
        }],
        esm_agg_commits: vec![AggregatedESmShareCommitment {
            recipient_id: 3,
            slot_index: 0,
            commitment: c("aesm-3-0"),
        }],
        smudge_slot_policy: sample_policy(),
        aggregated_pk_commitment: c("pk-agg"),
        parameter_digest: HexBlob("pd-01".into()),
    }
}

#[test]
fn accepted_participant_hash_is_canonical_and_duplicate_rejecting() {
    let sorted = compute_accepted_participant_set_hash(&[1, 3, 5]).expect("sorted accepted set");
    let unsorted =
        compute_accepted_participant_set_hash(&[5, 1, 3]).expect("unsorted canonicalized");

    assert_eq!(
        sorted.0, unsorted.0,
        "accepted set hash must canonicalize ordering"
    );
    assert!(
        compute_accepted_participant_set_hash(&[1, 3, 3]).is_err(),
        "duplicate accepted participant ids must be rejected"
    );
    assert!(
        compute_accepted_participant_set_hash(&[1, 0, 3]).is_err(),
        "zero participant id must be rejected"
    );
}

#[test]
fn root_digest_changes_with_accepted_participant_membership() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.accepted_participant_ids = vec![1, 3];
    b.participant_set_hash = compute_accepted_participant_set_hash(&b.accepted_participant_ids)
        .expect("accepted set hash");

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(
        ra.0, rb.0,
        "omitting an accepted participant must change root"
    );
}

#[test]
fn root_digest_rejects_participant_set_hash_mismatch() {
    let mut anchor = sample_anchor();
    anchor.accepted_participant_ids = vec![1, 3, 5];
    anchor.participant_set_hash =
        compute_accepted_participant_set_hash(&[1, 3]).expect("wrong accepted set hash");

    let err = anchor
        .root_digest()
        .expect_err("mismatched accepted set rejected");
    assert!(err.message().contains("accepted participant set hash"));
}

#[test]
fn root_digest_rejects_noncanonical_accepted_participant_order() {
    let mut anchor = sample_anchor();
    anchor.accepted_participant_ids = vec![3, 1, 5];
    anchor.participant_set_hash =
        compute_accepted_participant_set_hash(&anchor.accepted_participant_ids)
            .expect("canonical hash allows unordered caller input");

    let err = anchor
        .root_digest()
        .expect_err("noncanonical explicit set rejected");
    assert!(err.message().contains("unique and sorted"));
}

#[test]
fn root_digest_changes_with_session_id() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.session_id = "s2".into();

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(
        ra.0, rb.0,
        "different session_id must produce different root"
    );
}

#[test]
fn root_digest_changes_with_participant_set_hash() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.accepted_participant_ids = vec![1, 3, 6];
    b.participant_set_hash = compute_accepted_participant_set_hash(&b.accepted_participant_ids)
        .expect("accepted set hash");

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(
        ra.0, rb.0,
        "different participant_set_hash must produce different root"
    );
}

#[test]
fn root_digest_stable_on_roundtrip() {
    let a = sample_anchor();
    let root1 = a.root_digest().expect("root 1");
    let root2 = a.root_digest().expect("root 2");
    assert_eq!(root1.0, root2.0, "same anchor must produce same root");
}

#[test]
fn root_digest_changes_with_esm_agg_commits() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.esm_agg_commits.push(AggregatedESmShareCommitment {
        recipient_id: 5,
        slot_index: 1,
        commitment: c("aesm-5-1"),
    });

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(ra.0, rb.0, "adding esm_agg_commits must change root");
}

#[test]
fn root_digest_changes_with_esm_agg_commit_content() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.esm_agg_commits[0].slot_index = 99;

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(
        ra.0, rb.0,
        "changing esm_agg_commits content must change root"
    );
}

#[test]
fn root_digest_changes_with_smudge_slot_policy() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.smudge_slot_policy = SmudgeSlotPolicy {
        slots_per_party: 32,
        pre_generated: false,
        policy_hash: HexBlob("different-policy".into()),
    };

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(ra.0, rb.0, "different smudge_slot_policy must change root");
}

#[test]
fn root_digest_changes_with_individual_bfv_pk_commitments() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.individual_bfv_pk_commitments = vec![c("ibfvpk-2"), c("ibfvpk-3")];

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(
        ra.0, rb.0,
        "different individual_bfv_pk_commitments must change root"
    );
}

#[test]
fn root_digest_changes_with_threshold_pk_contribution_commitments() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.threshold_pk_contribution_commitments = vec![c("tpk-2"), c("tpk-3")];

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(
        ra.0, rb.0,
        "different threshold_pk_contribution_commitments must change root"
    );
}

#[test]
fn root_digest_changes_with_parameter_digest() {
    let a = sample_anchor();
    let mut b = sample_anchor();
    b.parameter_digest = HexBlob("pd-99".into());

    let ra = a.root_digest().expect("root a");
    let rb = b.root_digest().expect("root b");
    assert_ne!(ra.0, rb.0, "different parameter_digest must change root");
}
