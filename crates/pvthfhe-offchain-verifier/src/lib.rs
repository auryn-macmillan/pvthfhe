//! # ⚠️ INTENTIONALLY MINIMAL

pub mod attestation;

use std::collections::HashMap;

/// DKG public anchor values stored by the public verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgPublicAnchors {
    /// DKG transcript root shared by DKG and decryption proofs.
    pub dkg_root: [u8; 32],
    /// Public commitment to the aggregated BFV public key.
    pub aggregated_pk_commit: [u8; 32],
    /// Public hash of the accepted DKG participant set.
    pub participant_set_hash: [u8; 32],
    /// Public root of aggregated secret-key share commitments.
    pub sk_agg_commits_root: [u8; 32],
    /// Public root of aggregated committed-smudge commitments.
    pub esm_agg_commits_root: [u8; 32],
    /// Public hash of the smudge-slot allocation policy.
    pub smudge_slot_policy_hash: [u8; 32],
}

/// Public decryption verifier result awaiting final plaintext acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDecryption {
    /// DKG transcript root claimed by the decryption proof.
    pub dkg_root: [u8; 32],
    /// Hash of the ciphertext being decrypted.
    pub ciphertext_hash: [u8; 32],
    /// Expected DKG aggregate secret-key commitment root.
    pub expected_sk_commits_root: [u8; 32],
    /// Expected DKG aggregate committed-smudge commitment root.
    pub expected_esm_commits_root: [u8; 32],
    /// Public committed-smudge slot identifier.
    pub slot_id: u64,
    /// Public decryption round identifier.
    pub decrypt_round: u64,
    /// Hash of the decoded plaintext.
    pub plaintext_hash: [u8; 32],
    /// Plaintext bytes returned only after proof and compact anchor checks pass.
    pub plaintext: Vec<u8>,
    /// Whether the underlying proof verification already accepted.
    pub proof_verified: bool,
}

/// Public-anchor acceptance errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicAnchorError {
    /// No stored DKG anchors exist for the requested root.
    UnknownDkgRoot,
    /// Stored DKG anchors do not match decryption proof anchors.
    AnchorMismatch,
    /// Underlying proof verification did not accept.
    ProofNotVerified,
}

impl std::fmt::Display for PublicAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDkgRoot => write!(f, "unknown DKG root"),
            Self::AnchorMismatch => write!(f, "public anchor mismatch"),
            Self::ProofNotVerified => write!(f, "proof was not verified"),
        }
    }
}

impl std::error::Error for PublicAnchorError {}

/// In-memory DKG public-anchor store for off-chain public verification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InMemoryDkgAnchorStore {
    anchors_by_root: HashMap<[u8; 32], DkgPublicAnchors>,
}

impl InMemoryDkgAnchorStore {
    /// Store compact public DKG anchors keyed by their DKG root.
    pub fn store_dkg_anchors(
        &mut self,
        anchors: DkgPublicAnchors,
    ) -> Result<(), PublicAnchorError> {
        self.anchors_by_root.insert(anchors.dkg_root, anchors);
        Ok(())
    }

    /// Load compact public DKG anchors for a DKG root.
    pub fn load_dkg_anchors(&self, dkg_root: &[u8; 32]) -> Option<&DkgPublicAnchors> {
        self.anchors_by_root.get(dkg_root)
    }
}

/// Check stored DKG anchors against decryption anchors.
pub fn verify_public_anchors(
    dkg: &DkgPublicAnchors,
    decrypt: &VerifiedDecryption,
) -> Result<(), PublicAnchorError> {
    if dkg.dkg_root != decrypt.dkg_root
        || dkg.sk_agg_commits_root != decrypt.expected_sk_commits_root
        || dkg.esm_agg_commits_root != decrypt.expected_esm_commits_root
    {
        return Err(PublicAnchorError::AnchorMismatch);
    }
    Ok(())
}

/// Accept plaintext only after proof verification and compact public-anchor checks pass.
pub fn accept_verified_plaintext<'a>(
    store: &InMemoryDkgAnchorStore,
    decrypt: &'a VerifiedDecryption,
) -> Result<&'a [u8], PublicAnchorError> {
    let dkg = store
        .load_dkg_anchors(&decrypt.dkg_root)
        .ok_or(PublicAnchorError::UnknownDkgRoot)?;
    verify_public_anchors(dkg, decrypt)?;
    if !decrypt.proof_verified {
        return Err(PublicAnchorError::ProofNotVerified);
    }
    Ok(&decrypt.plaintext)
}

/// Error returned when the compressor SRS hash does not match the on-chain registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsMismatch {
    /// Expected SRS hash loaded from the public registry.
    pub expected: [u8; 32],
    /// Actual SRS hash advertised by the compressor/verifier key.
    pub actual: [u8; 32],
}

impl std::fmt::Display for SrsMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SRS hash mismatch: expected 0x{}.., got 0x{}..",
            hex::encode(&self.expected[..4]),
            hex::encode(&self.actual[..4])
        )
    }
}

impl std::error::Error for SrsMismatch {}

/// Verify that a compressor's SRS hash matches the expected on-chain registry value.
pub fn check_srs_hash(
    compressor_srs_hash: &[u8; 32],
    onchain_srs_hash: &[u8; 32],
) -> Result<(), SrsMismatch> {
    if compressor_srs_hash == onchain_srs_hash {
        Ok(())
    } else {
        Err(SrsMismatch {
            expected: *onchain_srs_hash,
            actual: *compressor_srs_hash,
        })
    }
}
