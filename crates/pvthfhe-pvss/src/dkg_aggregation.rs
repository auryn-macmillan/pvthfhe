//! Recipient-side DKG share decryption and aggregation checker.
//!
//! This E.2 relation deliberately stays on the public/opened DKG-share side of
//! the D.1 boundary.  It checks that decrypted/plain `sk` and `e_sm` share
//! values match the public commitments emitted by prior share-computation
//! outputs, then verifies the recipient aggregate values and aggregate
//! commitments over the accepted dealer set.  It does not claim an independent
//! verifier-checkable BFV decryption proof for encrypted DKG shares while the
//! D.1 BFV share-encryption relation remains fail-closed.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_keygen_spec::{
    compute_accepted_participant_set_hash, AggregatedESmShareCommitment,
    AggregatedSkShareCommitment, Commitment, DkgAnchorSet, HexBlob,
};
use sha2::{Digest, Sha256};

const DIGEST_LEN: usize = 32;
const COMMITMENT_SCHEME: &str = "pvthfhe-dkg-recipient-aggregation-sha256-v1";

/// One accepted dealer's decrypted DKG shares for a single recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealerDkgShare {
    /// Accepted dealer identifier.
    pub dealer_id: u16,
    /// Decrypted threshold secret-key share for the statement recipient.
    pub decrypted_sk_share: Fr,
    /// Prior public commitment to this dealer's `sk` contribution/share track.
    pub sk_share_commitment: [u8; DIGEST_LEN],
    /// Decrypted smudging shares by slot for the statement recipient.
    pub decrypted_esm_shares: Vec<(u16, Fr)>,
    /// Prior public commitments to this dealer's `e_sm` slot contribution/share tracks.
    pub esm_share_commitments: Vec<(u16, [u8; DIGEST_LEN])>,
}

/// Public statement checked for one recipient's DKG aggregate outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientDkgAggregationStatement {
    /// Session binding bytes.
    pub session_id: Vec<u8>,
    /// DKG transcript/anchor root binding this aggregation to one session.
    pub dkg_root: Vec<u8>,
    /// Recipient whose aggregate DKG shares are checked.
    pub recipient_id: u16,
    /// Exact accepted dealer set used for aggregation, in canonical order.
    pub accepted_dealer_ids: Vec<u16>,
    /// Smudging slots expected for each accepted dealer.
    pub smudge_slot_indices: Vec<u16>,
    /// Decrypted/plain shares received from accepted dealers.
    pub dealer_inputs: Vec<DealerDkgShare>,
    /// Claimed aggregate threshold secret-key share for this recipient.
    pub claimed_sk_aggregate: Fr,
    /// Claimed aggregate smudging share by slot for this recipient.
    pub claimed_esm_aggregates: Vec<(u16, Fr)>,
    /// Claimed public output commitment `sk_agg_commit[j]`.
    pub sk_agg_commit: [u8; DIGEST_LEN],
    /// Claimed public output commitments `esm_agg_commit[j][slot]`.
    pub esm_agg_commits: Vec<(u16, [u8; DIGEST_LEN])>,
}

/// Successful recipient aggregation check plus anchor-ready public outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedRecipientDkgAggregation {
    /// Exact accepted dealer set used for all checked aggregate commitments.
    pub accepted_dealer_ids: Vec<u16>,
    /// Commitment scheme string to store in keygen-spec anchors.
    pub commitment_scheme: String,
    /// Verified aggregate `sk` share value.
    pub sk_aggregate: Fr,
    /// Verified aggregate `e_sm` share values by slot.
    pub esm_aggregates: Vec<(u16, Fr)>,
    /// Lowercase-hex `sk_agg_commit[j]` digest.
    pub sk_agg_commit_hex: String,
    /// Lowercase-hex `esm_agg_commit[j][slot]` digests.
    pub esm_agg_commit_hexes: Vec<(u16, String)>,
}

/// Error returned by the recipient DKG aggregation checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgAggregationError {
    /// Statement metadata is malformed.
    InvalidStatement(&'static str),
    /// An accepted dealer input is missing, duplicated, or out of order.
    DealerSetMismatch,
    /// A dealer's decrypted share does not match its prior public commitment.
    DealerShareCommitmentMismatch {
        /// The dealer whose share commitment mismatched.
        dealer_id: u16,
        /// Track label whose dealer share commitment mismatched.
        track: String,
    },
    /// Claimed aggregate value is not the sum over accepted dealer inputs.
    AggregateSumMismatch {
        /// Track label whose aggregate sum mismatched.
        track: String,
    },
    /// Claimed aggregate public output commitment does not match the aggregate value.
    AggregateCommitmentMismatch {
        /// Track label whose aggregate commitment mismatched.
        track: String,
    },
    /// A `DkgAnchorSet` does not store the checked aggregate commitments.
    AnchorMismatch {
        /// Track label missing or mismatched in the DKG anchor.
        track: String,
    },
}

impl core::fmt::Display for DkgAggregationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidStatement(message) => {
                write!(f, "invalid DKG aggregation statement: {message}")
            }
            Self::DealerSetMismatch => f.write_str("accepted dealer set mismatch"),
            Self::DealerShareCommitmentMismatch { dealer_id, track } => {
                write!(f, "dealer {dealer_id} {track} share commitment mismatch")
            }
            Self::AggregateSumMismatch { track } => write!(f, "{track} aggregate sum mismatch"),
            Self::AggregateCommitmentMismatch { track } => {
                write!(f, "{track} aggregate commitment mismatch")
            }
            Self::AnchorMismatch { track } => write!(f, "DKG anchor {track} commitment mismatch"),
        }
    }
}

impl std::error::Error for DkgAggregationError {}

/// Compute the prior public commitment to one dealer's decrypted `sk` share for a recipient.
pub fn compute_sk_dealer_share_commitment(
    session_id: &[u8],
    dkg_root: &[u8],
    dealer_id: u16,
    recipient_id: u16,
    share_value: Fr,
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-dkg-sk-dealer-share-commitment-v1");
    h.update(session_id);
    h.update(dkg_root);
    h.update(dealer_id.to_be_bytes());
    h.update(recipient_id.to_be_bytes());
    h.update(b"sk");
    h.update(fr_bytes(&share_value));
    h.finalize().into()
}

/// Compute the prior public commitment to one dealer's decrypted `e_sm` slot share for a recipient.
pub fn compute_esm_dealer_share_commitment(
    session_id: &[u8],
    dkg_root: &[u8],
    dealer_id: u16,
    recipient_id: u16,
    slot_index: u16,
    share_value: Fr,
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-dkg-esm-dealer-share-commitment-v1");
    h.update(session_id);
    h.update(dkg_root);
    h.update(dealer_id.to_be_bytes());
    h.update(recipient_id.to_be_bytes());
    h.update(b"e_sm");
    h.update(slot_index.to_be_bytes());
    h.update(fr_bytes(&share_value));
    h.finalize().into()
}

/// Compute public output commitment `sk_agg_commit[j]`.
pub fn compute_sk_aggregate_commitment(
    session_id: &[u8],
    dkg_root: &[u8],
    recipient_id: u16,
    accepted_dealer_ids: &[u16],
    aggregate: Fr,
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-dkg-sk-aggregate-commitment-v1");
    absorb_common_aggregate_fields(
        &mut h,
        session_id,
        dkg_root,
        recipient_id,
        accepted_dealer_ids,
    );
    h.update(b"sk");
    h.update(fr_bytes(&aggregate));
    h.finalize().into()
}

/// Compute public output commitment `esm_agg_commit[j][slot]`.
pub fn compute_esm_aggregate_commitment(
    session_id: &[u8],
    dkg_root: &[u8],
    recipient_id: u16,
    accepted_dealer_ids: &[u16],
    slot_index: u16,
    aggregate: Fr,
) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"pvthfhe-dkg-esm-aggregate-commitment-v1");
    absorb_common_aggregate_fields(
        &mut h,
        session_id,
        dkg_root,
        recipient_id,
        accepted_dealer_ids,
    );
    h.update(b"e_sm");
    h.update(slot_index.to_be_bytes());
    h.update(fr_bytes(&aggregate));
    h.finalize().into()
}

/// Verify recipient-side aggregation over public decrypted/plain DKG shares.
pub fn verify_recipient_dkg_aggregation(
    statement: &RecipientDkgAggregationStatement,
) -> Result<CheckedRecipientDkgAggregation, DkgAggregationError> {
    validate_statement(statement)?;
    check_dealer_set(statement)?;
    check_dealer_commitments(statement)?;

    let sk_sum = statement
        .dealer_inputs
        .iter()
        .fold(Fr::ZERO, |acc, input| acc + input.decrypted_sk_share);
    if sk_sum != statement.claimed_sk_aggregate {
        return Err(DkgAggregationError::AggregateSumMismatch {
            track: "sk".to_owned(),
        });
    }
    let expected_sk_commit = compute_sk_aggregate_commitment(
        &statement.session_id,
        &statement.dkg_root,
        statement.recipient_id,
        &statement.accepted_dealer_ids,
        statement.claimed_sk_aggregate,
    );
    if expected_sk_commit != statement.sk_agg_commit {
        return Err(DkgAggregationError::AggregateCommitmentMismatch {
            track: "sk".to_owned(),
        });
    }

    let mut checked_esm = Vec::with_capacity(statement.smudge_slot_indices.len());
    let mut checked_esm_hexes = Vec::with_capacity(statement.smudge_slot_indices.len());
    for slot_index in &statement.smudge_slot_indices {
        let sum = statement
            .dealer_inputs
            .iter()
            .try_fold(Fr::ZERO, |acc, input| {
                lookup_fr(&input.decrypted_esm_shares, *slot_index)
                    .map(|value| acc + value)
                    .ok_or(DkgAggregationError::InvalidStatement(
                        "missing dealer e_sm slot",
                    ))
            })?;
        let claimed = lookup_fr(&statement.claimed_esm_aggregates, *slot_index).ok_or(
            DkgAggregationError::InvalidStatement("missing claimed e_sm aggregate"),
        )?;
        if claimed != sum {
            return Err(DkgAggregationError::AggregateSumMismatch {
                track: format!("e_sm slot {slot_index}"),
            });
        }
        let expected = compute_esm_aggregate_commitment(
            &statement.session_id,
            &statement.dkg_root,
            statement.recipient_id,
            &statement.accepted_dealer_ids,
            *slot_index,
            claimed,
        );
        let actual = lookup_digest(&statement.esm_agg_commits, *slot_index).ok_or(
            DkgAggregationError::InvalidStatement("missing e_sm aggregate commitment"),
        )?;
        if expected != actual {
            return Err(DkgAggregationError::AggregateCommitmentMismatch {
                track: format!("e_sm slot {slot_index}"),
            });
        }
        checked_esm.push((*slot_index, claimed));
        checked_esm_hexes.push((*slot_index, hex_encode(&expected)));
    }

    Ok(CheckedRecipientDkgAggregation {
        accepted_dealer_ids: statement.accepted_dealer_ids.clone(),
        commitment_scheme: COMMITMENT_SCHEME.to_owned(),
        sk_aggregate: statement.claimed_sk_aggregate,
        esm_aggregates: checked_esm,
        sk_agg_commit_hex: hex_encode(&statement.sk_agg_commit),
        esm_agg_commit_hexes: checked_esm_hexes,
    })
}

/// Verify that a DKG anchor stores checked aggregate commitments as public outputs.
pub fn verify_dkg_anchor_aggregate_outputs(
    anchor: &DkgAnchorSet,
    recipient_id: u16,
    checked: &CheckedRecipientDkgAggregation,
) -> Result<(), DkgAggregationError> {
    verify_anchor_accepted_set(anchor, checked)?;
    let sk = anchor
        .sk_agg_commits
        .iter()
        .find(|entry| entry.recipient_id == recipient_id)
        .ok_or(DkgAggregationError::AnchorMismatch {
            track: "sk aggregate".to_owned(),
        })?;
    if sk.commitment.scheme != checked.commitment_scheme
        || sk.commitment.digest.0 != checked.sk_agg_commit_hex
    {
        return Err(DkgAggregationError::AnchorMismatch {
            track: "sk aggregate".to_owned(),
        });
    }

    for (slot_index, digest) in &checked.esm_agg_commit_hexes {
        let esm = anchor
            .esm_agg_commits
            .iter()
            .find(|entry| entry.recipient_id == recipient_id && entry.slot_index == *slot_index)
            .ok_or(DkgAggregationError::AnchorMismatch {
                track: format!("e_sm slot {slot_index}"),
            })?;
        if esm.commitment.scheme != checked.commitment_scheme || esm.commitment.digest.0 != *digest
        {
            return Err(DkgAggregationError::AnchorMismatch {
                track: format!("e_sm slot {slot_index}"),
            });
        }
    }
    Ok(())
}

fn verify_anchor_accepted_set(
    anchor: &DkgAnchorSet,
    checked: &CheckedRecipientDkgAggregation,
) -> Result<(), DkgAggregationError> {
    if anchor.accepted_participant_ids != checked.accepted_dealer_ids {
        return Err(DkgAggregationError::AnchorMismatch {
            track: "accepted participant set".to_owned(),
        });
    }

    let expected = compute_accepted_participant_set_hash(&anchor.accepted_participant_ids)
        .map_err(|_| DkgAggregationError::AnchorMismatch {
            track: "accepted participant set".to_owned(),
        })?;
    if expected != anchor.participant_set_hash {
        return Err(DkgAggregationError::AnchorMismatch {
            track: "accepted participant set hash".to_owned(),
        });
    }
    Ok(())
}

/// Build the keygen-spec anchor entry for a checked `sk` aggregate commitment.
pub fn checked_sk_anchor_commitment(
    recipient_id: u16,
    checked: &CheckedRecipientDkgAggregation,
) -> AggregatedSkShareCommitment {
    AggregatedSkShareCommitment {
        recipient_id,
        commitment: Commitment {
            scheme: checked.commitment_scheme.clone(),
            digest: HexBlob(checked.sk_agg_commit_hex.clone()),
        },
    }
}

/// Build the keygen-spec anchor entries for checked `e_sm` aggregate commitments.
pub fn checked_esm_anchor_commitments(
    recipient_id: u16,
    checked: &CheckedRecipientDkgAggregation,
) -> Vec<AggregatedESmShareCommitment> {
    checked
        .esm_agg_commit_hexes
        .iter()
        .map(|(slot_index, digest)| AggregatedESmShareCommitment {
            recipient_id,
            slot_index: *slot_index,
            commitment: Commitment {
                scheme: checked.commitment_scheme.clone(),
                digest: HexBlob(digest.clone()),
            },
        })
        .collect()
}

fn validate_statement(
    statement: &RecipientDkgAggregationStatement,
) -> Result<(), DkgAggregationError> {
    if statement.session_id.is_empty() {
        return Err(DkgAggregationError::InvalidStatement("empty session_id"));
    }
    if statement.dkg_root.is_empty() {
        return Err(DkgAggregationError::InvalidStatement("empty dkg_root"));
    }
    if statement.recipient_id == 0 {
        return Err(DkgAggregationError::InvalidStatement(
            "recipient_id must be one-based",
        ));
    }
    if statement.accepted_dealer_ids.is_empty() || statement.dealer_inputs.is_empty() {
        return Err(DkgAggregationError::InvalidStatement(
            "missing accepted dealers",
        ));
    }
    if statement.accepted_dealer_ids.len() != statement.dealer_inputs.len() {
        return Err(DkgAggregationError::DealerSetMismatch);
    }
    validate_unique_sorted("duplicate accepted dealer", &statement.accepted_dealer_ids)?;
    validate_unique_sorted("duplicate smudge slot", &statement.smudge_slot_indices)?;
    validate_slots(
        &statement.claimed_esm_aggregates,
        &statement.smudge_slot_indices,
        "claimed e_sm aggregates",
    )?;
    validate_digest_slots(
        &statement.esm_agg_commits,
        &statement.smudge_slot_indices,
        "e_sm aggregate commitments",
    )?;
    Ok(())
}

fn check_dealer_set(
    statement: &RecipientDkgAggregationStatement,
) -> Result<(), DkgAggregationError> {
    for (expected_id, input) in statement
        .accepted_dealer_ids
        .iter()
        .zip(&statement.dealer_inputs)
    {
        if *expected_id != input.dealer_id {
            return Err(DkgAggregationError::DealerSetMismatch);
        }
        validate_slots(
            &input.decrypted_esm_shares,
            &statement.smudge_slot_indices,
            "dealer e_sm shares",
        )?;
        validate_digest_slots(
            &input.esm_share_commitments,
            &statement.smudge_slot_indices,
            "dealer e_sm commitments",
        )?;
    }
    Ok(())
}

fn check_dealer_commitments(
    statement: &RecipientDkgAggregationStatement,
) -> Result<(), DkgAggregationError> {
    for input in &statement.dealer_inputs {
        let expected_sk = compute_sk_dealer_share_commitment(
            &statement.session_id,
            &statement.dkg_root,
            input.dealer_id,
            statement.recipient_id,
            input.decrypted_sk_share,
        );
        if expected_sk != input.sk_share_commitment {
            return Err(DkgAggregationError::DealerShareCommitmentMismatch {
                dealer_id: input.dealer_id,
                track: "sk".to_owned(),
            });
        }
        for slot_index in &statement.smudge_slot_indices {
            let value = lookup_fr(&input.decrypted_esm_shares, *slot_index).ok_or(
                DkgAggregationError::InvalidStatement("missing dealer e_sm slot"),
            )?;
            let expected = compute_esm_dealer_share_commitment(
                &statement.session_id,
                &statement.dkg_root,
                input.dealer_id,
                statement.recipient_id,
                *slot_index,
                value,
            );
            let actual = lookup_digest(&input.esm_share_commitments, *slot_index).ok_or(
                DkgAggregationError::InvalidStatement("missing dealer e_sm commitment"),
            )?;
            if expected != actual {
                return Err(DkgAggregationError::DealerShareCommitmentMismatch {
                    dealer_id: input.dealer_id,
                    track: format!("e_sm slot {slot_index}"),
                });
            }
        }
    }
    Ok(())
}

fn validate_unique_sorted(
    message: &'static str,
    values: &[u16],
) -> Result<(), DkgAggregationError> {
    for window in values.windows(2) {
        if window[0] >= window[1] {
            return Err(DkgAggregationError::InvalidStatement(message));
        }
    }
    Ok(())
}

fn validate_slots(
    values: &[(u16, Fr)],
    expected: &[u16],
    label: &'static str,
) -> Result<(), DkgAggregationError> {
    if values.len() != expected.len() {
        return Err(DkgAggregationError::InvalidStatement(label));
    }
    for ((actual, _), expected_slot) in values.iter().zip(expected) {
        if actual != expected_slot {
            return Err(DkgAggregationError::InvalidStatement(label));
        }
    }
    Ok(())
}

fn validate_digest_slots(
    values: &[(u16, [u8; DIGEST_LEN])],
    expected: &[u16],
    label: &'static str,
) -> Result<(), DkgAggregationError> {
    if values.len() != expected.len() {
        return Err(DkgAggregationError::InvalidStatement(label));
    }
    for ((actual, _), expected_slot) in values.iter().zip(expected) {
        if actual != expected_slot {
            return Err(DkgAggregationError::InvalidStatement(label));
        }
    }
    Ok(())
}

fn lookup_fr(values: &[(u16, Fr)], slot_index: u16) -> Option<Fr> {
    values
        .iter()
        .find_map(|(slot, value)| (*slot == slot_index).then_some(*value))
}

fn lookup_digest(values: &[(u16, [u8; DIGEST_LEN])], slot_index: u16) -> Option<[u8; DIGEST_LEN]> {
    values
        .iter()
        .find_map(|(slot, value)| (*slot == slot_index).then_some(*value))
}

fn absorb_common_aggregate_fields(
    h: &mut Sha256,
    session_id: &[u8],
    dkg_root: &[u8],
    recipient_id: u16,
    accepted_dealer_ids: &[u16],
) {
    h.update(session_id);
    h.update(dkg_root);
    h.update(recipient_id.to_be_bytes());
    h.update((accepted_dealer_ids.len() as u64).to_be_bytes());
    for dealer_id in accepted_dealer_ids {
        h.update(dealer_id.to_be_bytes());
    }
}

fn fr_bytes(value: &Fr) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(LUT[(byte >> 4) as usize]));
        out.push(char::from(LUT[(byte & 0x0f) as usize]));
    }
    out
}
