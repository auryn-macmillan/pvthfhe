//! Frozen interface types for the P4 Hermine-adapted keygen surface.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

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

        Ok(BFVPublicKey {
            wire_version: 1,
            session_id: session.session_id.clone(),
            params_id: self.bfv_derivation_label.clone(),
            rlwe_dimension: 4096,
            modulus_chain: vec![0xffff_ee01, 0xffff_c401],
            public_component_a: HexBlob(format!("{}01", self.transcript_root.0)),
            public_component_b: HexBlob(format!("{}02", self.proof_bytes.0)),
            provenance: BfvKeyProvenance {
                reconstructed_from_share_ids: ids,
                transcript_root: self.transcript_root.clone(),
            },
        })
    }
}
