#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use pvthfhe_keygen_spec::{
    AggregatedESmShareCommitment, AggregatedSkShareCommitment, Commitment, DkgAnchorSet,
    ESmContributionCommitment, ESmShareCommitment, HexBlob, KeygenPhase, KeygenSession,
    SkContributionCommitment, SkShareCommitment, SmudgeSlotId,
};

fn rt<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let json = serde_json::to_string_pretty(value).expect("serialize");
    let out: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(out, *value);
    out
}

fn c(hex: &str) -> Commitment {
    Commitment {
        scheme: "test-pedersen".into(),
        digest: HexBlob(hex.into()),
    }
}

#[test]
fn old_one_track_session_cannot_represent_esm() {
    let session = KeygenSession {
        wire_version: 1,
        session_id: "no-esm".into(),
        epoch: 1,
        threshold: 4,
        participants: vec![],
        phase: KeygenPhase::SessionInit,
        transcript_domain: "td".into(),
    };

    let json = serde_json::to_string_pretty(&session).unwrap();
    assert!(!json.contains("e_sm"));
    assert!(!json.contains("esm_agg"));
    assert!(!json.contains("smudge_slot"));

    let back = rt(&session);
    assert_eq!(back.wire_version, 1);
}

#[test]
fn sk_contribution_commitment_roundtrip() {
    let v = SkContributionCommitment {
        dealer_id: 1,
        session_id: "s1".into(),
        commitment: c("cc-sk-01"),
    };
    let b = rt(&v);
    assert_eq!(b.dealer_id, 1);
    assert_eq!(b.session_id, "s1");
    assert_eq!(b.commitment.digest.0, "cc-sk-01");
}

#[test]
fn esm_contribution_commitment_roundtrip() {
    let v = ESmContributionCommitment {
        dealer_id: 2,
        session_id: "s1".into(),
        commitment: c("cc-esm-02"),
        slot_index: 0,
    };
    let b = rt(&v);
    assert_eq!(b.dealer_id, 2);
    assert_eq!(b.slot_index, 0);
    assert_eq!(b.commitment.digest.0, "cc-esm-02");
}

#[test]
fn sk_share_commitment_roundtrip() {
    let v = SkShareCommitment {
        dealer_id: 1,
        recipient_id: 3,
        commitment: c("sh-sk-01-03"),
    };
    let b = rt(&v);
    assert_eq!(b.dealer_id, 1);
    assert_eq!(b.recipient_id, 3);
    assert_eq!(b.commitment.digest.0, "sh-sk-01-03");
}

#[test]
fn esm_share_commitment_roundtrip() {
    let v = ESmShareCommitment {
        dealer_id: 2,
        recipient_id: 4,
        commitment: c("sh-esm-02-04"),
        slot_index: 1,
    };
    let b = rt(&v);
    assert_eq!(b.dealer_id, 2);
    assert_eq!(b.recipient_id, 4);
    assert_eq!(b.slot_index, 1);
    assert_eq!(b.commitment.digest.0, "sh-esm-02-04");
}

#[test]
fn aggregated_sk_share_commitment_roundtrip() {
    let v = AggregatedSkShareCommitment {
        recipient_id: 3,
        commitment: c("agg-sk-03"),
    };
    let b = rt(&v);
    assert_eq!(b.recipient_id, 3);
    assert_eq!(b.commitment.digest.0, "agg-sk-03");
}

#[test]
fn aggregated_esm_share_commitment_roundtrip() {
    let v = AggregatedESmShareCommitment {
        recipient_id: 4,
        slot_index: 2,
        commitment: c("agg-esm-04-s2"),
    };
    let b = rt(&v);
    assert_eq!(b.recipient_id, 4);
    assert_eq!(b.slot_index, 2);
    assert_eq!(b.commitment.digest.0, "agg-esm-04-s2");
}

#[test]
fn smudge_slot_id_roundtrip() {
    let v = SmudgeSlotId {
        session_id: "s1".into(),
        recipient_id: 5,
        slot_index: 3,
    };
    let b = rt(&v);
    assert_eq!(b.session_id, "s1");
    assert_eq!(b.recipient_id, 5);
    assert_eq!(b.slot_index, 3);
}

#[test]
fn dkg_anchor_set_roundtrip_empty() {
    let v = DkgAnchorSet {
        session_id: "s1".into(),
        participant_set_hash: HexBlob("h-abc".into()),
        threshold: 4,
        sk_agg_commits: vec![],
        esm_agg_commits: vec![],
        aggregated_pk_commitment: c("pk-agg"),
        parameter_digest: HexBlob("pd-01".into()),
    };
    let b = rt(&v);
    assert_eq!(b.session_id, "s1");
    assert_eq!(b.threshold, 4);
    assert!(b.sk_agg_commits.is_empty());
    assert!(b.esm_agg_commits.is_empty());
    assert_eq!(b.aggregated_pk_commitment.digest.0, "pk-agg");
}

#[test]
fn dkg_anchor_set_roundtrip_full() {
    let sk = vec![
        AggregatedSkShareCommitment {
            recipient_id: 3,
            commitment: c("ask-3"),
        },
        AggregatedSkShareCommitment {
            recipient_id: 4,
            commitment: c("ask-4"),
        },
    ];
    let esm = vec![
        AggregatedESmShareCommitment {
            recipient_id: 3,
            slot_index: 0,
            commitment: c("aesm-3-0"),
        },
        AggregatedESmShareCommitment {
            recipient_id: 3,
            slot_index: 1,
            commitment: c("aesm-3-1"),
        },
        AggregatedESmShareCommitment {
            recipient_id: 4,
            slot_index: 0,
            commitment: c("aesm-4-0"),
        },
    ];

    let v = DkgAnchorSet {
        session_id: "s-full".into(),
        participant_set_hash: HexBlob("full-h".into()),
        threshold: 2,
        sk_agg_commits: sk,
        esm_agg_commits: esm,
        aggregated_pk_commitment: c("pk-agg-full"),
        parameter_digest: HexBlob("pf".into()),
    };

    let b = rt(&v);
    assert_eq!(b.session_id, "s-full");
    assert_eq!(b.threshold, 2);
    assert_eq!(b.sk_agg_commits.len(), 2);
    assert_eq!(b.sk_agg_commits[0].recipient_id, 3);
    assert_eq!(b.esm_agg_commits.len(), 3);
    assert_eq!(b.esm_agg_commits[1].slot_index, 1);
    assert_eq!(b.aggregated_pk_commitment.digest.0, "pk-agg-full");
    assert_eq!(b.parameter_digest.0, "pf");
}

#[test]
fn wire_version_two_signals_two_track() {
    let session = KeygenSession {
        wire_version: 2,
        session_id: "v2".into(),
        epoch: 1,
        threshold: 4,
        participants: vec![],
        phase: KeygenPhase::SessionInit,
        transcript_domain: "td".into(),
    };

    let b = rt(&session);
    assert_eq!(b.wire_version, 2);

    let v1_json = r#"{
        "wire_version": 1,
        "session_id": "legacy",
        "epoch": 1,
        "threshold": 4,
        "participants": [],
        "phase": "session_init",
        "transcript_domain": "legacy-domain"
    }"#;

    let legacy: KeygenSession = serde_json::from_str(v1_json).expect("legacy must deserialize");
    assert_eq!(legacy.wire_version, 1);
    assert_ne!(legacy.wire_version, 2);
}
