//! Frozen interface types for the P4 Hermine-adapted keygen surface.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Result alias used by all spec traits.
pub type SpecResult<T> = Result<T, SpecError>;

/// Error returned by stub wire-format and derivation routines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecError {
    message: String,
}

impl SpecError {
    /// Creates a new spec error with a stable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the stable error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for SpecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SpecError {}

fn serialize_to_json<T: Serialize>(value: &T) -> SpecResult<String> {
    serde_json::to_string_pretty(value)
        .map_err(|error| SpecError::new(format!("serde_json serialization failed: {error}")))
}

fn deserialize_from_json<T: DeserializeOwned>(wire_json: &str) -> SpecResult<T> {
    serde_json::from_str(wire_json)
        .map_err(|error| SpecError::new(format!("serde_json deserialization failed: {error}")))
}

/// JSON-encoded lowercase-hex payload used throughout the frozen wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexBlob(pub String);

/// Session participant metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    /// Stable participant identifier in the keygen roster.
    pub participant_id: u16,
    /// Reference to the participant's public encryption material.
    pub encryption_key_ref: String,
}

/// Session lifecycle phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeygenPhase {
    /// Session announced but shares not yet posted.
    SessionInit,
    /// Dealer ciphertexts and commitments are available.
    ShareDistribution,
    /// Complaints and blame evidence may be published.
    ComplaintWindow,
    /// Public transcript finalized and accepted.
    Finalized,
    /// Session terminated due to a publicly verified fault.
    Aborted,
}

/// Frozen session object for Hermine-adapted PVSS keygen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeygenSession {
    /// Frozen wire version.
    pub wire_version: u16,
    /// Globally unique session identifier.
    pub session_id: String,
    /// Epoch or sequence number for replay protection.
    pub epoch: u64,
    /// Threshold parameter `t`.
    pub threshold: u16,
    /// Ordered participant roster.
    pub participants: Vec<Participant>,
    /// Current state of the public protocol instance.
    pub phase: KeygenPhase,
    /// Domain separator binding hashes and proofs to this protocol.
    pub transcript_domain: String,
}

/// Trait for the frozen keygen session interface.
pub trait KeygenSessionSpec: Sized + Serialize + DeserializeOwned {
    /// Returns the stable session identifier.
    fn session_id(&self) -> &str;

    /// Returns the roster bound to the session.
    fn participants(&self) -> &[Participant];

    /// Returns the threshold parameter.
    fn threshold(&self) -> u16;

    /// Returns the current session phase.
    fn phase(&self) -> &KeygenPhase;

    /// Encodes the session using the frozen JSON wire format.
    fn to_wire_json(&self) -> SpecResult<String>;

    /// Decodes the session from the frozen JSON wire format.
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

impl KeygenSessionSpec for KeygenSession {
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn participants(&self) -> &[Participant] {
        &self.participants
    }

    fn threshold(&self) -> u16 {
        self.threshold
    }

    fn phase(&self) -> &KeygenPhase {
        &self.phase
    }

    fn to_wire_json(&self) -> SpecResult<String> {
        serialize_to_json(self)
    }

    fn from_wire_json(wire_json: &str) -> SpecResult<Self> {
        deserialize_from_json(wire_json)
    }
}

impl KeygenSession {
    /// Current wire version signifying two-track (sk + e_sm) support.
    pub const CURRENT_WIRE_VERSION: u16 = 2;

    /// Returns true when the session advertises two-track capability.
    pub fn is_two_track(&self) -> bool {
        self.wire_version >= Self::CURRENT_WIRE_VERSION
    }
}

/// Public commitment to a share or transcript item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Commitment construction identifier.
    pub scheme: String,
    /// Digest over the committed payload.
    pub digest: HexBlob,
}

/// Frozen encrypted share object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// Frozen wire version.
    pub wire_version: u16,
    /// Session identifier that binds the share.
    pub session_id: String,
    /// Dealer publishing this share.
    pub dealer_id: u16,
    /// Intended share recipient.
    pub recipient_id: u16,
    /// Stable index within the session's publication order.
    pub share_index: u16,
    /// Encrypted share payload as lowercase hex.
    pub encrypted_share: HexBlob,
    /// Commitment that binds the dealer's claimed plaintext share.
    pub commitment: Commitment,
    /// Reference to the public proof statement that authenticates the share.
    pub proof_ref: String,
}

/// Trait for the frozen share interface.
pub trait ShareSpec: Sized + Serialize + DeserializeOwned {
    /// Returns the bound session identifier.
    fn session_id(&self) -> &str;

    /// Returns the dealer identity.
    fn dealer_id(&self) -> u16;

    /// Returns the intended recipient identity.
    fn recipient_id(&self) -> u16;

    /// Returns the share commitment.
    fn commitment(&self) -> &Commitment;

    /// Encodes the share using the frozen JSON wire format.
    fn to_wire_json(&self) -> SpecResult<String>;

    /// Decodes the share from the frozen JSON wire format.
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

impl ShareSpec for Share {
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn dealer_id(&self) -> u16 {
        self.dealer_id
    }

    fn recipient_id(&self) -> u16 {
        self.recipient_id
    }

    fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    fn to_wire_json(&self) -> SpecResult<String> {
        serialize_to_json(self)
    }

    fn from_wire_json(wire_json: &str) -> SpecResult<Self> {
        deserialize_from_json(wire_json)
    }
}

/// Commitment to a single party's threshold secret-key contribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkContributionCommitment {
    /// Dealer publishing this contribution.
    pub dealer_id: u16,
    /// Session identifier binding this commitment.
    pub session_id: String,
    /// Commitment to the dealer's secret-key contribution.
    pub commitment: Commitment,
}

/// Commitment to a single party's smudging-noise contribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ESmContributionCommitment {
    /// Dealer publishing this contribution.
    pub dealer_id: u16,
    /// Session identifier binding this commitment.
    pub session_id: String,
    /// Commitment to the dealer's smudging-noise contribution.
    pub commitment: Commitment,
    /// Which smudge slot batch this contribution belongs to.
    pub slot_index: u16,
}

/// Commitment to one recipient's sk share from one dealer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkShareCommitment {
    /// Dealer originating this share commitment.
    pub dealer_id: u16,
    /// Intended share recipient.
    pub recipient_id: u16,
    /// Commitment binding the sk share plaintext.
    pub commitment: Commitment,
}

/// Commitment to one recipient's e_sm share from one dealer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ESmShareCommitment {
    /// Dealer originating this share commitment.
    pub dealer_id: u16,
    /// Intended share recipient.
    pub recipient_id: u16,
    /// Commitment binding the e_sm share plaintext.
    pub commitment: Commitment,
    /// Which smudge slot batch this share belongs to.
    pub slot_index: u16,
}

/// Aggregated secret-key share commitment for one recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedSkShareCommitment {
    /// Recipient whose aggregated sk share this commitment binds.
    pub recipient_id: u16,
    /// Aggregated commitment for the recipient's sk share.
    pub commitment: Commitment,
}

/// Aggregated smudging-noise share commitment for one recipient in one slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedESmShareCommitment {
    /// Recipient whose aggregated e_sm share this commitment binds.
    pub recipient_id: u16,
    /// Which smudge slot batch this commitment is for.
    pub slot_index: u16,
    /// Aggregated commitment for the recipient's e_sm share in this slot.
    pub commitment: Commitment,
}

/// Identifier for one smudging-noise slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmudgeSlotId {
    /// Session identifier binding this slot.
    pub session_id: String,
    /// Recipient to whom this slot belongs.
    pub recipient_id: u16,
    /// Zero-based index within the recipient's slot vector.
    pub slot_index: u16,
}

/// Anchor set produced at DKG finalization, binding all commitments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgAnchorSet {
    /// Session identifier binding this anchor set.
    pub session_id: String,
    /// Exact accepted participant/dealer set used by DKG aggregation.
    ///
    /// The public verifier uses this canonical set to determine which C5/DKG
    /// aggregate outputs and later decryption shares are bound to the anchor.
    /// Values must be one-based, unique, and sorted in ascending order.
    pub accepted_participant_ids: Vec<u16>,
    /// Hash over the canonical accepted participant set.
    pub participant_set_hash: HexBlob,
    /// Threshold parameter t.
    pub threshold: u16,
    /// Commitments to each party's individual BFV public key.
    pub individual_bfv_pk_commitments: Vec<Commitment>,
    /// Commitments to each party's threshold pk contribution.
    pub threshold_pk_contribution_commitments: Vec<Commitment>,
    /// Aggregated sk share commitments per recipient.
    pub sk_agg_commits: Vec<AggregatedSkShareCommitment>,
    /// Aggregated e_sm share commitments per recipient per slot.
    pub esm_agg_commits: Vec<AggregatedESmShareCommitment>,
    /// Smudge slot policy governing the DKG session.
    pub smudge_slot_policy: SmudgeSlotPolicy,
    /// Commitment to the aggregated threshold public key.
    pub aggregated_pk_commitment: Commitment,
    /// Digest over the protocol parameters.
    pub parameter_digest: HexBlob,
}

impl DkgAnchorSet {
    /// Compute the deterministic DKG transcript root.
    ///
    /// The root is `SHA-256(canonical_json(self))` returned as lowercase hex.
    /// Canonical JSON uses `serde_json::to_string` (compact, no pretty-printing)
    /// and is the current-spec canonical form. Future batches may migrate to a
    /// canonical binary encoding without changing the digest semantics.
    pub fn root_digest(&self) -> SpecResult<HexBlob> {
        self.validate_accepted_participant_set_binding()?;
        let canonical = serde_json::to_string(self).map_err(|e| {
            SpecError::new(format!("DKG anchor canonical serialization failed: {e}"))
        })?;
        let hash: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        Ok(HexBlob(hex_encode(&hash)))
    }

    /// Validate that `participant_set_hash` matches the explicit accepted set.
    pub fn validate_accepted_participant_set_binding(&self) -> SpecResult<()> {
        validate_strictly_sorted_participant_ids(&self.accepted_participant_ids)?;
        let expected = compute_accepted_participant_set_hash(&self.accepted_participant_ids)?;
        if expected != self.participant_set_hash {
            return Err(SpecError::new(
                "accepted participant set hash does not match accepted_participant_ids",
            ));
        }
        Ok(())
    }
}

fn validate_strictly_sorted_participant_ids(participant_ids: &[u16]) -> SpecResult<()> {
    if participant_ids.is_empty() {
        return Err(SpecError::new("accepted participant set must be non-empty"));
    }
    if participant_ids[0] == 0 {
        return Err(SpecError::new("accepted participant ids must be one-based"));
    }
    for window in participant_ids.windows(2) {
        if window[1] == 0 {
            return Err(SpecError::new("accepted participant ids must be one-based"));
        }
        if window[0] >= window[1] {
            return Err(SpecError::new(
                "accepted participant ids must be unique and sorted",
            ));
        }
    }
    Ok(())
}

/// Compute the canonical accepted participant/dealer-set digest.
///
/// The input is canonicalized by sorting a copy before hashing. Duplicate ids
/// and the reserved zero id are rejected so callers cannot hide ambiguity in the
/// public accepted set. The digest uses the same SHA-256/lowercase-hex style as
/// [`DkgAnchorSet::root_digest`].
pub fn compute_accepted_participant_set_hash(participant_ids: &[u16]) -> SpecResult<HexBlob> {
    if participant_ids.is_empty() {
        return Err(SpecError::new("accepted participant set must be non-empty"));
    }

    let mut ids = participant_ids.to_vec();
    ids.sort_unstable();
    for id in &ids {
        if *id == 0 {
            return Err(SpecError::new("accepted participant ids must be one-based"));
        }
    }
    for window in ids.windows(2) {
        if window[0] == window[1] {
            return Err(SpecError::new("duplicate accepted participant id"));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-dkg-accepted-participant-set-v1");
    hasher.update((ids.len() as u64).to_be_bytes());
    for id in ids {
        hasher.update(id.to_be_bytes());
    }
    let hash: [u8; 32] = hasher.finalize().into();
    Ok(HexBlob(hex_encode(&hash)))
}

/// Lowercase hex encoding helper (no external crate needed).
fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(LUT[(byte >> 4) as usize]));
        out.push(char::from(LUT[(byte & 0x0f) as usize]));
    }
    out
}

/// Frozen public transcript used for third-party verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicVerificationArtifact {
    /// Frozen wire version.
    pub wire_version: u16,
    /// Session identifier that binds the artifact.
    pub session_id: String,
    /// Dealer whose publication is being verified.
    pub dealer_id: u16,
    /// Public commitments matching the per-recipient shares.
    pub share_commitments: Vec<Commitment>,
    /// Root digest over the ordered transcript.
    pub transcript_root: HexBlob,
    /// Human-readable identifier for the proof statement family.
    pub well_formedness_statement: String,
    /// Serialized proof bytes as lowercase hex.
    pub proof_bytes: HexBlob,
    /// Deterministic derivation label for the BFV key adapter.
    pub bfv_derivation_label: String,
}

/// Trait for the frozen public verification artifact interface.
pub trait PublicVerificationArtifactSpec: Sized + Serialize + DeserializeOwned {
    /// Returns the session identifier.
    fn session_id(&self) -> &str;

    /// Returns the dealer identity.
    fn dealer_id(&self) -> u16;

    /// Returns the share-commitment list.
    fn share_commitments(&self) -> &[Commitment];

    /// Encodes the artifact using the frozen JSON wire format.
    fn to_wire_json(&self) -> SpecResult<String>;

    /// Decodes the artifact from the frozen JSON wire format.
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

impl PublicVerificationArtifactSpec for PublicVerificationArtifact {
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn dealer_id(&self) -> u16 {
        self.dealer_id
    }

    fn share_commitments(&self) -> &[Commitment] {
        &self.share_commitments
    }

    fn to_wire_json(&self) -> SpecResult<String> {
        serialize_to_json(self)
    }

    fn from_wire_json(wire_json: &str) -> SpecResult<Self> {
        deserialize_from_json(wire_json)
    }
}

/// Named accused party in an abort-with-blame event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlameTarget {
    /// Dealer-side fault.
    Dealer {
        /// Dealer identifier.
        dealer_id: u16,
    },
    /// Recipient or verifier-side fault.
    Participant {
        /// Participant identifier.
        participant_id: u16,
    },
}

/// Publicly checkable reason code for an abort.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlameReason {
    /// Ciphertext does not match the committed witness.
    InvalidEncryptedShare,
    /// Commitment list does not match the published artifact.
    CommitmentMismatch,
    /// Required publication or acknowledgement is absent.
    MissingBroadcast,
    /// Transcript content was replayed from a different session or epoch.
    ReplayDetected,
}

/// Evidence element bundled into a blame proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Stable label for the evidence component.
    pub label: String,
    /// Digest of the evidence payload.
    pub digest: HexBlob,
    /// Serialized evidence bytes as lowercase hex.
    pub payload: HexBlob,
}

/// Frozen blame-proof object for public abort handling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlameProof {
    /// Frozen wire version.
    pub wire_version: u16,
    /// Session identifier that binds the blame event.
    pub session_id: String,
    /// Identifier of the complaining participant.
    pub accuser_id: u16,
    /// Publicly named accused party.
    pub accused: BlameTarget,
    /// Stable reason code for the blame event.
    pub reason: BlameReason,
    /// Ordered evidence bundle supporting the complaint.
    pub evidence: Vec<EvidenceItem>,
}

/// Trait for the frozen blame-proof interface.
pub trait BlameProofSpec: Sized + Serialize + DeserializeOwned {
    /// Returns the bound session identifier.
    fn session_id(&self) -> &str;

    /// Returns the accusing participant.
    fn accuser_id(&self) -> u16;

    /// Returns the accused party.
    fn accused(&self) -> &BlameTarget;

    /// Returns the reason code.
    fn reason(&self) -> &BlameReason;

    /// Encodes the blame proof using the frozen JSON wire format.
    fn to_wire_json(&self) -> SpecResult<String>;

    /// Decodes the blame proof from the frozen JSON wire format.
    fn from_wire_json(wire_json: &str) -> SpecResult<Self>;
}

impl BlameProofSpec for BlameProof {
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn accuser_id(&self) -> u16 {
        self.accuser_id
    }

    fn accused(&self) -> &BlameTarget {
        &self.accused
    }

    fn reason(&self) -> &BlameReason {
        &self.reason
    }

    fn to_wire_json(&self) -> SpecResult<String> {
        serialize_to_json(self)
    }

    fn from_wire_json(wire_json: &str) -> SpecResult<Self> {
        deserialize_from_json(wire_json)
    }
}

/// Provenance binding for a derived BFV public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfvKeyProvenance {
    /// Sorted participant identifiers contributing to the derivation.
    pub reconstructed_from_share_ids: Vec<u16>,
    /// Transcript root that binds the BFV key to the public transcript.
    pub transcript_root: HexBlob,
}

/// Frozen BFV public-key object emitted by the adapter boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BFVPublicKey {
    /// Frozen wire version.
    pub wire_version: u16,
    /// Session identifier that binds the key.
    pub session_id: String,
    /// BFV parameter-set identifier.
    pub params_id: String,
    /// RLWE dimension used by the downstream BFV backend.
    pub rlwe_dimension: u32,
    /// RNS modulus chain expected by the consumer backend.
    pub modulus_chain: Vec<u64>,
    /// Serialized BFV `a` component.
    pub public_component_a: HexBlob,
    /// Serialized BFV `b` component.
    pub public_component_b: HexBlob,
    /// Transcript provenance proving how the key was derived.
    pub provenance: BfvKeyProvenance,
}

/// Trait describing BFV public-key derivation from the frozen P4 transcript.
pub trait BfvPublicKeyDerivation {
    /// Derives a BFV-form public key from a finalized session transcript and share set.
    fn derive_bfv_public_key(
        &self,
        session: &KeygenSession,
        shares: &[Share],
    ) -> SpecResult<BFVPublicKey>;
}

/// Canonical BFV parameters TOML (mirrored from `pvthfhe-pvss/src/nizk_share.rs`
/// and `pvthfhe-fhe/src/mock_impl.rs`). Used for parameter binding in
/// `derive_bfv_public_key`.
const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Parse a simple `key = value` TOML-like section to extract RLWE parameters.
/// Returns `(degree, moduli, t_plain)` from the `[rlwe]` section, or an error.
fn parse_bfv_params_from_toml(toml: &str) -> SpecResult<(u32, Vec<u64>, u32)> {
    let mut n: Option<u32> = None;
    let mut moduli: Option<Vec<u64>> = None;
    let mut t_plain: Option<u32> = None;
    let mut in_rlwe = false;

    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[rlwe]" {
            in_rlwe = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_rlwe = false;
        }
        if !in_rlwe {
            continue;
        }
        if let Some(val) = trimmed.strip_prefix("n =") {
            n = val.trim().parse().ok();
        } else if let Some(val) = trimmed.strip_prefix("t_plain =") {
            t_plain = val.trim().parse().ok();
        } else if let Some(val) = trimmed.strip_prefix("moduli =") {
            let inner = val
                .trim()
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .map(|s| s.trim())
                .unwrap_or("");
            if inner.is_empty() {
                moduli = Some(Vec::new());
            } else {
                moduli = Some(
                    inner
                        .split(',')
                        .filter_map(|item| item.trim().parse::<u64>().ok())
                        .collect(),
                );
            }
        }
    }

    match (n, moduli, t_plain) {
        (Some(n), Some(moduli), Some(t_plain)) => Ok((n, moduli, t_plain)),
        _ => Err(SpecError::new("failed to parse BFV params from TOML")),
    }
}

impl BfvPublicKeyDerivation for PublicVerificationArtifact {
    fn derive_bfv_public_key(
        &self,
        session: &KeygenSession,
        shares: &[Share],
    ) -> SpecResult<BFVPublicKey> {
        if self.session_id != session.session_id {
            return Err(SpecError::new("artifact session_id does not match session"));
        }

        if shares.is_empty() {
            return Err(SpecError::new(
                "at least one share is required for derivation",
            ));
        }

        if shares
            .iter()
            .any(|share| share.session_id != session.session_id)
        {
            return Err(SpecError::new("share session_id does not match session"));
        }

        let mut ids: Vec<u16> = shares.iter().map(|share| share.recipient_id).collect();
        ids.sort_unstable();
        ids.dedup();

        let (degree, moduli, _t_plain) = parse_bfv_params_from_toml(CANONICAL_PARAMS_TOML)?;

        let params_hash_raw: [u8; 32] = Sha256::digest(CANONICAL_PARAMS_TOML.as_bytes()).into();
        let params_id = format!("bfv-{}", hex_encode(&params_hash_raw[..8]));

        Ok(BFVPublicKey {
            wire_version: 1,
            session_id: session.session_id.clone(),
            params_id,
            rlwe_dimension: degree,
            modulus_chain: moduli,
            public_component_a: HexBlob(format!("{}01", self.transcript_root.0)),
            public_component_b: HexBlob(format!("{}02", self.proof_bytes.0)),
            provenance: BfvKeyProvenance {
                reconstructed_from_share_ids: ids,
                transcript_root: self.transcript_root.clone(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Smudge-slot policy and registry (Batch C.2)
// ---------------------------------------------------------------------------

/// Error when a smudge slot has already been consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmudgeSlotError {
    /// The requested slot was consumed in a prior operation and is not reusable.
    SlotAlreadyConsumed {
        /// Session the slot belongs to.
        session_id: String,
        /// Party that owns the slot.
        party_id: u16,
        /// Index of the slot within the party's allocation.
        slot_index: u16,
    },
}

impl core::fmt::Display for SmudgeSlotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SlotAlreadyConsumed {
                session_id,
                party_id,
                slot_index,
            } => {
                write!(
                    f,
                    "smudge slot already consumed: session={session_id}, party={party_id}, slot={slot_index}"
                )
            }
        }
    }
}

impl std::error::Error for SmudgeSlotError {}

/// Tracks consumed smudge slots to enforce one-time-use.
///
/// Keyed by `(session_id, party_id, slot_index)`, stored internally as
/// `"{session_id}:{party_id}:{slot_index}"`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SmudgeSlotRegistry {
    /// Consumed slots. Each entry: "session_id:party_id:slot_index".
    consumed: HashSet<String>,
}

impl SmudgeSlotRegistry {
    fn slot_key(session_id: &str, party_id: u16, slot_index: u16) -> String {
        format!("{session_id}:{party_id}:{slot_index}")
    }

    /// Returns `true` if the slot has NOT been consumed yet.
    pub fn is_fresh(&self, session_id: &str, party_id: u16, slot_index: u16) -> bool {
        !self.is_consumed(session_id, party_id, slot_index)
    }

    /// Returns `true` if the slot has already been consumed.
    pub fn is_consumed(&self, session_id: &str, party_id: u16, slot_index: u16) -> bool {
        self.consumed
            .contains(&Self::slot_key(session_id, party_id, slot_index))
    }

    /// Mark a slot as consumed. Returns `Err(SmudgeSlotError)` if the slot was
    /// already consumed.
    pub fn consume(
        &mut self,
        session_id: &str,
        party_id: u16,
        slot_index: u16,
    ) -> Result<(), SmudgeSlotError> {
        let key = Self::slot_key(session_id, party_id, slot_index);
        if !self.consumed.insert(key) {
            return Err(SmudgeSlotError::SlotAlreadyConsumed {
                session_id: session_id.to_string(),
                party_id,
                slot_index,
            });
        }
        Ok(())
    }
}

/// Policy governing how many smudge slots each party pre-generates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmudgeSlotPolicy {
    /// Number of smudge slots per party.
    pub slots_per_party: u16,
    /// Whether slots are pre-generated during DKG (`true`) or allocated on
    /// demand (`false`).
    pub pre_generated: bool,
    /// Hash of the slot allocation strategy for binding into the DKG root.
    pub policy_hash: HexBlob,
}
