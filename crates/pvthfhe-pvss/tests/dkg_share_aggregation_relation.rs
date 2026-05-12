//! Focused E.2 tests for recipient-side DKG share aggregation.

use ark_bn254::Fr;
use pvthfhe_keygen_spec::{
    compute_accepted_participant_set_hash, AggregatedESmShareCommitment,
    AggregatedSkShareCommitment, Commitment, DkgAnchorSet, HexBlob, SmudgeSlotPolicy,
};
use pvthfhe_pvss::dkg_aggregation::{
    compute_esm_aggregate_commitment, compute_esm_dealer_share_commitment,
    compute_sk_aggregate_commitment, compute_sk_dealer_share_commitment,
    verify_dkg_anchor_aggregate_outputs, verify_recipient_dkg_aggregation, DealerDkgShare,
    RecipientDkgAggregationStatement,
};

fn commitment(digest: impl Into<String>) -> Commitment {
    Commitment {
        scheme: "sha256-test".to_owned(),
        digest: HexBlob(digest.into()),
    }
}

fn eval(coeffs: &[Fr], x: u16) -> Fr {
    let x = Fr::from(u64::from(x));
    coeffs
        .iter()
        .rev()
        .fold(Fr::from(0u64), |acc, coeff| acc * x + coeff)
}

fn dealer_share(
    session_id: &[u8],
    dkg_root: &[u8],
    dealer_id: u16,
    recipient_id: u16,
    sk_coeffs: &[Fr],
    esm_coeffs: &[(u16, Vec<Fr>)],
) -> DealerDkgShare {
    DealerDkgShare {
        dealer_id,
        decrypted_sk_share: eval(sk_coeffs, recipient_id),
        sk_share_commitment: compute_sk_dealer_share_commitment(
            session_id,
            dkg_root,
            dealer_id,
            recipient_id,
            eval(sk_coeffs, recipient_id),
        ),
        decrypted_esm_shares: esm_coeffs
            .iter()
            .map(|(slot_index, coeffs)| (*slot_index, eval(coeffs, recipient_id)))
            .collect(),
        esm_share_commitments: esm_coeffs
            .iter()
            .map(|(slot_index, coeffs)| {
                (
                    *slot_index,
                    compute_esm_dealer_share_commitment(
                        session_id,
                        dkg_root,
                        dealer_id,
                        recipient_id,
                        *slot_index,
                        eval(coeffs, recipient_id),
                    ),
                )
            })
            .collect(),
    }
}

fn valid_statement() -> RecipientDkgAggregationStatement {
    let session_id = b"e2-session".to_vec();
    let dkg_root = b"e2-dkg-root".to_vec();
    let recipient_id = 3;
    let accepted_dealer_ids = vec![10, 11, 12];
    let dealer_inputs = vec![
        dealer_share(
            &session_id,
            &dkg_root,
            10,
            recipient_id,
            &[Fr::from(4u64), Fr::from(2u64)],
            &[
                (0, vec![Fr::from(7u64), Fr::from(1u64)]),
                (1, vec![Fr::from(9u64), Fr::from(2u64)]),
            ],
        ),
        dealer_share(
            &session_id,
            &dkg_root,
            11,
            recipient_id,
            &[Fr::from(5u64), Fr::from(3u64)],
            &[
                (0, vec![Fr::from(8u64), Fr::from(2u64)]),
                (1, vec![Fr::from(10u64), Fr::from(3u64)]),
            ],
        ),
        dealer_share(
            &session_id,
            &dkg_root,
            12,
            recipient_id,
            &[Fr::from(6u64), Fr::from(4u64)],
            &[
                (0, vec![Fr::from(11u64), Fr::from(3u64)]),
                (1, vec![Fr::from(12u64), Fr::from(4u64)]),
            ],
        ),
    ];

    let sk_sum = dealer_inputs
        .iter()
        .fold(Fr::from(0u64), |acc, input| acc + input.decrypted_sk_share);
    let esm0_sum = dealer_inputs.iter().fold(Fr::from(0u64), |acc, input| {
        acc + input.decrypted_esm_shares[0].1
    });
    let esm1_sum = dealer_inputs.iter().fold(Fr::from(0u64), |acc, input| {
        acc + input.decrypted_esm_shares[1].1
    });

    RecipientDkgAggregationStatement {
        session_id,
        dkg_root,
        recipient_id,
        accepted_dealer_ids,
        smudge_slot_indices: vec![0, 1],
        dealer_inputs,
        claimed_sk_aggregate: sk_sum,
        claimed_esm_aggregates: vec![(0, esm0_sum), (1, esm1_sum)],
        sk_agg_commit: compute_sk_aggregate_commitment(
            b"e2-session",
            b"e2-dkg-root",
            recipient_id,
            &[10, 11, 12],
            sk_sum,
        ),
        esm_agg_commits: vec![
            (
                0,
                compute_esm_aggregate_commitment(
                    b"e2-session",
                    b"e2-dkg-root",
                    recipient_id,
                    &[10, 11, 12],
                    0,
                    esm0_sum,
                ),
            ),
            (
                1,
                compute_esm_aggregate_commitment(
                    b"e2-session",
                    b"e2-dkg-root",
                    recipient_id,
                    &[10, 11, 12],
                    1,
                    esm1_sum,
                ),
            ),
        ],
    }
}

#[test]
fn rejects_sk_aggregate_commitment_mismatch() {
    let mut statement = valid_statement();
    statement.sk_agg_commit[0] ^= 0x80;

    let err = verify_recipient_dkg_aggregation(&statement).expect_err("bad sk aggregate rejected");

    assert!(err.to_string().contains("sk aggregate commitment"));
}

#[test]
fn rejects_esm_slot_aggregate_commitment_mismatch() {
    let mut statement = valid_statement();
    statement.esm_agg_commits[1].1[0] ^= 0x40;

    let err = verify_recipient_dkg_aggregation(&statement).expect_err("bad esm aggregate rejected");

    assert!(err.to_string().contains("e_sm slot 1 aggregate commitment"));
}

#[test]
fn rejects_omitted_dealer_contribution_from_sk_sum() {
    let mut statement = valid_statement();
    statement.claimed_sk_aggregate -= statement.dealer_inputs[2].decrypted_sk_share;
    statement.sk_agg_commit = compute_sk_aggregate_commitment(
        &statement.session_id,
        &statement.dkg_root,
        statement.recipient_id,
        &statement.accepted_dealer_ids,
        statement.claimed_sk_aggregate,
    );

    let err = verify_recipient_dkg_aggregation(&statement).expect_err("omitted sk dealer rejected");

    assert!(err.to_string().contains("sk aggregate sum"));
}

#[test]
fn rejects_tampered_esm_slot_share_even_with_matching_claimed_commitment() {
    let mut statement = valid_statement();
    statement.dealer_inputs[0].decrypted_esm_shares[0].1 += Fr::from(1u64);
    let recomputed = statement
        .dealer_inputs
        .iter()
        .fold(Fr::from(0u64), |acc, input| {
            acc + input.decrypted_esm_shares[0].1
        });
    statement.claimed_esm_aggregates[0].1 = recomputed;
    statement.esm_agg_commits[0].1 = compute_esm_aggregate_commitment(
        &statement.session_id,
        &statement.dkg_root,
        statement.recipient_id,
        &statement.accepted_dealer_ids,
        0,
        recomputed,
    );

    let err = verify_recipient_dkg_aggregation(&statement)
        .expect_err("tampered esm dealer share rejected");

    assert!(err
        .to_string()
        .contains("dealer e_sm slot 0 share commitment"));
}

#[test]
fn rejects_duplicate_accepted_dealer_ids() {
    let mut statement = valid_statement();
    statement.accepted_dealer_ids[2] = statement.accepted_dealer_ids[1];

    let err = verify_recipient_dkg_aggregation(&statement).expect_err("duplicate dealer rejected");

    assert!(err.to_string().contains("duplicate accepted dealer"));
}

#[test]
fn anchor_set_stores_checked_public_aggregate_commitments() {
    let statement = valid_statement();
    let checked = verify_recipient_dkg_aggregation(&statement).expect("valid aggregation");

    let anchor = DkgAnchorSet {
        session_id: "e2-session".to_owned(),
        accepted_participant_ids: statement.accepted_dealer_ids.clone(),
        participant_set_hash: compute_accepted_participant_set_hash(&statement.accepted_dealer_ids)
            .expect("accepted set hash"),
        threshold: 2,
        individual_bfv_pk_commitments: vec![],
        threshold_pk_contribution_commitments: vec![],
        sk_agg_commits: vec![AggregatedSkShareCommitment {
            recipient_id: statement.recipient_id,
            commitment: Commitment {
                scheme: checked.commitment_scheme.clone(),
                digest: HexBlob(checked.sk_agg_commit_hex.clone()),
            },
        }],
        esm_agg_commits: checked
            .esm_agg_commit_hexes
            .iter()
            .map(|(slot_index, digest)| AggregatedESmShareCommitment {
                recipient_id: statement.recipient_id,
                slot_index: *slot_index,
                commitment: Commitment {
                    scheme: checked.commitment_scheme.clone(),
                    digest: HexBlob(digest.clone()),
                },
            })
            .collect(),
        smudge_slot_policy: SmudgeSlotPolicy {
            slots_per_party: 2,
            pre_generated: true,
            policy_hash: HexBlob("bb".repeat(32)),
        },
        aggregated_pk_commitment: commitment("cc".repeat(32)),
        parameter_digest: HexBlob("dd".repeat(32)),
    };

    assert_eq!(
        anchor.sk_agg_commits[0].commitment.digest.0,
        checked.sk_agg_commit_hex
    );
    assert_eq!(anchor.esm_agg_commits.len(), 2);
    verify_dkg_anchor_aggregate_outputs(&anchor, statement.recipient_id, &checked)
        .expect("anchor stores outputs");
    assert!(anchor.root_digest().expect("root digest").0.len() == 64);
}

#[test]
fn anchor_verification_rejects_omitted_accepted_participant() {
    let statement = valid_statement();
    let checked = verify_recipient_dkg_aggregation(&statement).expect("valid aggregation");
    let mut anchor = DkgAnchorSet {
        session_id: "e2-session".to_owned(),
        accepted_participant_ids: vec![10, 11],
        participant_set_hash: compute_accepted_participant_set_hash(&[10, 11])
            .expect("accepted set hash"),
        threshold: 2,
        individual_bfv_pk_commitments: vec![],
        threshold_pk_contribution_commitments: vec![],
        sk_agg_commits: vec![AggregatedSkShareCommitment {
            recipient_id: statement.recipient_id,
            commitment: Commitment {
                scheme: checked.commitment_scheme.clone(),
                digest: HexBlob(checked.sk_agg_commit_hex.clone()),
            },
        }],
        esm_agg_commits: checked
            .esm_agg_commit_hexes
            .iter()
            .map(|(slot_index, digest)| AggregatedESmShareCommitment {
                recipient_id: statement.recipient_id,
                slot_index: *slot_index,
                commitment: Commitment {
                    scheme: checked.commitment_scheme.clone(),
                    digest: HexBlob(digest.clone()),
                },
            })
            .collect(),
        smudge_slot_policy: SmudgeSlotPolicy {
            slots_per_party: 2,
            pre_generated: true,
            policy_hash: HexBlob("bb".repeat(32)),
        },
        aggregated_pk_commitment: commitment("cc".repeat(32)),
        parameter_digest: HexBlob("dd".repeat(32)),
    };

    let err = verify_dkg_anchor_aggregate_outputs(&anchor, statement.recipient_id, &checked)
        .expect_err("omitted accepted participant rejected");
    assert!(err.to_string().contains("accepted participant set"));

    anchor.accepted_participant_ids = vec![10, 11, 12, 13];
    anchor.participant_set_hash =
        compute_accepted_participant_set_hash(&anchor.accepted_participant_ids)
            .expect("accepted set hash");
    let err = verify_dkg_anchor_aggregate_outputs(&anchor, statement.recipient_id, &checked)
        .expect_err("included failed participant rejected");
    assert!(err.to_string().contains("accepted participant set"));
}
