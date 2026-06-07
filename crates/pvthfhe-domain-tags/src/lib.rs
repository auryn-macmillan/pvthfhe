//! Single source of truth for all `pvthfhe/...` domain-separation tags.
//!
//! R0.4 GREEN. Adding a new tag requires:
//!   1. Add a `Tag` variant + match arms in `as_bytes` and `all_literals`.
//!   2. Use `Tag::<Variant>.as_bytes()` at the callsite (no raw `pvthfhe/...` literals).
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Tag {
    /// `pvthfhe/finalize/v1` — aggregator finalize-phase transcript.
    Finalize,
    /// `pvthfhe/keygen-simulator/session/v1` — keygen simulator session label.
    KeygenSimulatorSession,
    /// `pvthfhe/proof-tag/v1` — aggregator e2e_real test fixture proof tag.
    ProofTag,
    /// `pvthfhe/nova/toy-step/v1` — Nova surrogate toy-step circuit.
    NovaToyStep,
    /// `pvthfhe/nova/cyclo-fold/v1` — Nova Cyclo fold step circuit (R5.2).
    NovaCycloFold,
    /// `pvthfhe/nova/srs/v1` — Nova SRS domain separator.
    NovaSrs,
    /// `pvthfhe/wire/test-payload/v1` — pvthfhe-wire canonicality tests.
    WireTestPayload,
    /// `pvthfhe/wire/fhe-keygen-share/v1` — FHE keygen-share wire payload.
    WireFheKeygenShare,
    /// `pvthfhe/wire/fhe-public-key/v1` — FHE public-key wire payload.
    WireFhePublicKey,
    /// `pvthfhe/wire/fhe-decrypt-share/v1` — FHE decrypt-share wire payload.
    WireFheDecryptShare,
    /// `pvthfhe/wire/pvss-share-opened-proof/v1` — PVSS share proof envelope.
    WirePvssShareOpenedProof,
    /// `pvthfhe/wire/pvss-decrypt-opened-proof/v1` — PVSS decrypt proof envelope.
    WirePvssDecryptOpenedProof,
    /// `pvthfhe/cyclo-ajtai-binding/v1` — Cyclo Ajtai commitment binding domain tag.
    CycloAjtaiBinding,
    /// `pvthfhe/pvss/batched-dkg-share-encryption/v1` — batched DKG share-encryption transcript.
    PvssBatchedDkgShareEncryption,
    /// `pvthfhe/pvss/batched-dkg-share-encryption/sk-track/v1` — threshold secret-key track.
    PvssBatchedDkgShareEncryptionSkTrack,
    /// `pvthfhe/pvss/batched-dkg-share-encryption/e-sm-track/v1` — committed smudge-noise track.
    PvssBatchedDkgShareEncryptionESmTrack,
    /// `pvthfhe/pvss/smudge-slot-batch/v1` — smudge slot/batch identity binding.
    PvssSmudgeSlotBatch,
    /// `pvthfhe/pvss/transcript-root-binding/v1` — transcript-root replay binding.
    PvssTranscriptRootBinding,
    /// `pvthfhe/pvss/c7-decrypt-aggregation/v1` — C7 decryption aggregation step circuit.
    PvssC7DecryptAggregation,
    /// `pvthfhe/pvss/c7-merkle-decrypt-aggregation/v1` — C7 decryption aggregation with in-circuit Merkle verification.
    PvssC7MerkleDecryptAggregation,
    /// `pvthfhe/p3/fold-verifier/v1` — P3 LatticeFold+ terminal verifier step circuit.
    PvssFoldVerifier,
    /// `pvthfhe/nova/ring-verifier/v1` — Nova ring equation verifier circuit (G1).
    NovaRingVerifier,
    /// `pvthfhe/nova/fhe-compute/v1` — Nova FHE compute step circuit (E3 Compute Provider).
    NovaFheCompute,
    /// `pvthfhe/nova/bootstrap-step/v1` — Nova TFHE bootstrap step circuit (T6 Bootstrap Proofs).
    NovaBootstrapStep,
    /// `pvthfhe-sk-binding/v1` — sigma protocol secret-key binding hash domain.
    SigmaSkBinding,
    /// `pvthfhe/sigma-scalar-challenge/v2` — sigma protocol scalar-challenge Fiat-Shamir domain.
    SigmaScalarChallenge,
    /// `pvthfhe-sz-gamma-v3` — sigma protocol sz-gamma derivation domain.
    SigmaSzGamma,
    /// `pvthfhe/cyclo-ajtai-d2/v1/` — Fiat-Shamir transcript domain separator prefix.
    FiatShamirDomainPrefix,
    /// `pvthfhe-bfv-sigma-challenge-v1` — BFV sigma protocol challenge derivation domain.
    BfvSigmaChallenge,
    /// `pvthfhe/bootstrap-sigma-ch/v1` — bootstrap sigma protocol challenge derivation domain.
    BootstrapSigmaChallenge,
    /// `pvthfhe-bootstrap-result/v1` — bootstrap result hash binding domain.
    BootstrapResult,
    /// `pvthfhe/schnorr-challenge/v2` — Schnorr signature Fiat-Shamir challenge domain.
    SchnorrChallenge,
    /// `pvthfhe-greyhound-pcs-v1` — Greyhound PCS matrix generation domain.
    GreyhoundPcs,
    /// `pvthfhe-greyhound-challenge-v1` — Greyhound PCS challenge derivation domain.
    GreyhoundChallenge,
    /// `pvthfhe-ajtai-crs/v1` — Ajtai commitment CRS seed derivation domain.
    AjtaiCrs,
    /// `pvthfhe/sigma-session-binding/v1` — sigma protocol session binding domain separator.
    SigmaSessionBinding,
    /// `pvthfhe/cyclo-fold-challenge/v2` — Cyclo fold challenge derivation domain separator.
    CycloFoldChallengeV2,
    /// `pvthfhe/pvss-decrypt-binding/v1` — PVSS decryption binding domain separator.
    PvssDecryptBindingV1,
    /// `pvthfhe-schnorr-pop-v1` — Schnorr proof-of-possession domain separator.
    SchnorrPop,
    /// `pvthfhe/lazer-session-binding/v1` — LaZer proof session/participant binding domain.
    LazerSessionBinding,
    /// `pvthfhe-d2-hash-bridge/v1` — D2 hash-bridge commitment domain (H9 consolidation).
    HashBridgeCommit,
    /// `greyhound-A` — Greyhound PCS matrix A generation domain (H9 consolidation).
    GreyhoundA,
    /// `greyhound-B` — Greyhound PCS matrix B generation domain (H9 consolidation).
    GreyhoundB,
    /// `greyhound-D` — Greyhound PCS matrix D generation domain (H9 consolidation).
    GreyhoundD,
    /// `pvthfhe/` — protocol-level domain prefix for hash construction.
    ProtocolPrefix,
    /// `pvthfhe/ajtai-commit/v1` — Ajtai commitment domain separator.
    AjtaiCommit,
    /// `pvthfhe/bfv-encryption-snapshot/v1` — BFV encryption snapshot circuit domain.
    BfvEncryptionSnapshot,
    /// `pvthfhe/bfv-encryption/v1` — BFV encryption step circuit domain.
    BfvEncryption,
    /// `pvthfhe/ciphertext-v/v1` — ciphertext-v PVSS NIZK share domain.
    CiphertextV,
    /// `pvthfhe/cyclo-fold-arecibo/v1` — Cyclo fold Arecibo circuit domain.
    CycloFoldArecibo,
    /// `pvthfhe/dealer-parity/v2` — dealer parity step circuit domain.
    DealerParity,
    /// `pvthfhe/decrypt-nizk-proofs/v1` — decrypt NIZK proofs hash domain.
    DecryptNizkProofs,
    /// `pvthfhe/dkg-agg/v1` — DKG aggregation step circuit domain.
    DkgAgg,
    /// `pvthfhe/lagrange-fold/v1` — Lagrange fold step circuit domain.
    LagrangeFold,
    /// `pvthfhe/micronova/heterogeneous-step-circuit/v1` — Micronova heterogeneous step circuit.
    MicronovaHeterogeneousStepCircuit,
    /// `pvthfhe/micronova/internal-fold-verifier/v1` — Micronova internal fold verifier v1.
    MicronovaInternalFoldVerifierV1,
    /// `pvthfhe/micronova/internal-fold-verifier/v3` — Micronova internal fold verifier v3.
    MicronovaInternalFoldVerifierV3,
    /// `pvthfhe/micronova/lagrange-fold/v1` — Micronova Lagrange fold circuit domain.
    MicronovaLagrangeFold,
    /// `pvthfhe/micronova/leaf-ring-verifier/v1` — Micronova leaf ring verifier.
    MicronovaLeafRingVerifier,
    /// `pvthfhe/micronova/party` — Micronova per-party proof label.
    MicronovaParty,
    /// `pvthfhe/micronova/pk` — Micronova public key label.
    MicronovaPk,
    /// `pvthfhe/micronova/share` — Micronova share label.
    MicronovaShare,
    /// `pvthfhe/nova/ajtai-commitment/v1` — Nova Ajtai commitment step circuit domain.
    NovaAjtaiCommitment,
    /// `pvthfhe/participant-set/v1` — participant set hash domain.
    ParticipantSet,
    /// `pvthfhe/per_node/c7` — per-node C7 challenge domain.
    PerNodeC7,
    /// `pvthfhe/pk-aggregation/v1` — public-key aggregation step circuit domain.
    PkAggregation,
    /// `pvthfhe/pk-contribution/v1` — public-key contribution step circuit domain.
    PkContribution,
    /// `pvthfhe/pvss/share-verify-sigma/v1` — PVSS share-verify sigma proof domain.
    PvssShareVerifySigma,
    /// `pvthfhe/scheme-switch/v1` — scheme switch step circuit domain.
    SchemeSwitch,
    /// `pvthfhe/session-id/v1` — session ID hash domain.
    SessionId,
    /// `pvthfhe/transcript/v1` — transcript hash domain.
    Transcript,
}

impl Tag {
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Tag::Finalize => b"pvthfhe/finalize/v1",
            Tag::KeygenSimulatorSession => b"pvthfhe/keygen-simulator/session/v1",
            Tag::ProofTag => b"pvthfhe/proof-tag/v1",
            Tag::NovaToyStep => b"pvthfhe/nova/toy-step/v1",
            Tag::NovaCycloFold => b"pvthfhe/nova/cyclo-fold/v1",
            Tag::NovaSrs => b"pvthfhe/nova/srs/v1",
            Tag::WireTestPayload => b"pvthfhe/wire/test-payload/v1",
            Tag::WireFheKeygenShare => b"pvthfhe/wire/fhe-keygen-share/v1",
            Tag::WireFhePublicKey => b"pvthfhe/wire/fhe-public-key/v1",
            Tag::WireFheDecryptShare => b"pvthfhe/wire/fhe-decrypt-share/v1",
            Tag::WirePvssShareOpenedProof => b"pvthfhe/wire/pvss-share-opened-proof/v1",
            Tag::WirePvssDecryptOpenedProof => b"pvthfhe/wire/pvss-decrypt-opened-proof/v1",
            Tag::CycloAjtaiBinding => b"pvthfhe/cyclo-ajtai-binding/v1",
            Tag::PvssBatchedDkgShareEncryption => b"pvthfhe/pvss/batched-dkg-share-encryption/v1",
            Tag::PvssBatchedDkgShareEncryptionSkTrack => {
                b"pvthfhe/pvss/batched-dkg-share-encryption/sk-track/v1"
            }
            Tag::PvssBatchedDkgShareEncryptionESmTrack => {
                b"pvthfhe/pvss/batched-dkg-share-encryption/e-sm-track/v1"
            }
            Tag::PvssSmudgeSlotBatch => b"pvthfhe/pvss/smudge-slot-batch/v1",
            Tag::PvssTranscriptRootBinding => b"pvthfhe/pvss/transcript-root-binding/v1",
            Tag::PvssC7DecryptAggregation => b"pvthfhe/pvss/c7-decrypt-aggregation/v1",
            Tag::PvssC7MerkleDecryptAggregation => b"pvthfhe/pvss/c7-merkle-decrypt-aggregation/v1",
            Tag::PvssFoldVerifier => b"pvthfhe/p3/fold-verifier/v1",
            Tag::NovaRingVerifier => b"pvthfhe/nova/ring-verifier/v1",
            Tag::NovaFheCompute => b"pvthfhe/nova/fhe-compute/v1",
            Tag::NovaBootstrapStep => b"pvthfhe/nova/bootstrap-step/v1",
            Tag::SigmaSkBinding => b"pvthfhe-sk-binding/v1",
            Tag::SigmaScalarChallenge => b"pvthfhe/sigma-scalar-challenge/v2",
            Tag::SigmaSzGamma => b"pvthfhe-sz-gamma-v3",
            Tag::FiatShamirDomainPrefix => b"pvthfhe/cyclo-ajtai-d2/v1/",
            Tag::BfvSigmaChallenge => b"pvthfhe-bfv-sigma-challenge-v1",
            Tag::BootstrapSigmaChallenge => b"pvthfhe/bootstrap-sigma-ch/v1",
            Tag::BootstrapResult => b"pvthfhe-bootstrap-result/v1",
            Tag::SchnorrChallenge => b"pvthfhe/schnorr-challenge/v2",
            Tag::GreyhoundPcs => b"pvthfhe-greyhound-pcs-v1",
            Tag::GreyhoundChallenge => b"pvthfhe-greyhound-challenge-v1",
            Tag::AjtaiCrs => b"pvthfhe-ajtai-crs/v1",
            Tag::SigmaSessionBinding => b"pvthfhe/sigma-session-binding/v1",
            Tag::CycloFoldChallengeV2 => b"pvthfhe/cyclo-fold-challenge/v2",
            Tag::PvssDecryptBindingV1 => b"pvthfhe/pvss-decrypt-binding/v1",
            Tag::SchnorrPop => b"pvthfhe-schnorr-pop-v1",
            Tag::LazerSessionBinding => b"pvthfhe/lazer-session-binding/v1",
            Tag::HashBridgeCommit => b"pvthfhe-d2-hash-bridge/v1",
            Tag::GreyhoundA => b"greyhound-A",
            Tag::GreyhoundB => b"greyhound-B",
            Tag::GreyhoundD => b"greyhound-D",
            Tag::ProtocolPrefix => b"pvthfhe/",
            Tag::AjtaiCommit => b"pvthfhe/ajtai-commit/v1",
            Tag::BfvEncryptionSnapshot => b"pvthfhe/bfv-encryption-snapshot/v1",
            Tag::BfvEncryption => b"pvthfhe/bfv-encryption/v1",
            Tag::CiphertextV => b"pvthfhe/ciphertext-v/v1",
            Tag::CycloFoldArecibo => b"pvthfhe/cyclo-fold-arecibo/v1",
            Tag::DealerParity => b"pvthfhe/dealer-parity/v2",
            Tag::DecryptNizkProofs => b"pvthfhe/decrypt-nizk-proofs/v1",
            Tag::DkgAgg => b"pvthfhe/dkg-agg/v1",
            Tag::LagrangeFold => b"pvthfhe/lagrange-fold/v1",
            Tag::MicronovaHeterogeneousStepCircuit => {
                b"pvthfhe/micronova/heterogeneous-step-circuit/v1"
            }
            Tag::MicronovaInternalFoldVerifierV1 => b"pvthfhe/micronova/internal-fold-verifier/v1",
            Tag::MicronovaInternalFoldVerifierV3 => b"pvthfhe/micronova/internal-fold-verifier/v3",
            Tag::MicronovaLagrangeFold => b"pvthfhe/micronova/lagrange-fold/v1",
            Tag::MicronovaLeafRingVerifier => b"pvthfhe/micronova/leaf-ring-verifier/v1",
            Tag::MicronovaParty => b"pvthfhe/micronova/party",
            Tag::MicronovaPk => b"pvthfhe/micronova/pk",
            Tag::MicronovaShare => b"pvthfhe/micronova/share",
            Tag::NovaAjtaiCommitment => b"pvthfhe/nova/ajtai-commitment/v1",
            Tag::ParticipantSet => b"pvthfhe/participant-set/v1",
            Tag::PerNodeC7 => b"pvthfhe/per_node/c7",
            Tag::PkAggregation => b"pvthfhe/pk-aggregation/v1",
            Tag::PkContribution => b"pvthfhe/pk-contribution/v1",
            Tag::PvssShareVerifySigma => b"pvthfhe/pvss/share-verify-sigma/v1",
            Tag::SchemeSwitch => b"pvthfhe/scheme-switch/v1",
            Tag::SessionId => b"pvthfhe/session-id/v1",
            Tag::Transcript => b"pvthfhe/transcript/v1",
        }
    }

    pub const fn all_literals() -> &'static [&'static [u8]] {
        const ALL: [&[u8]; 71] = [
            Tag::Finalize.as_bytes(),
            Tag::KeygenSimulatorSession.as_bytes(),
            Tag::ProofTag.as_bytes(),
            Tag::NovaToyStep.as_bytes(),
            Tag::NovaCycloFold.as_bytes(),
            Tag::NovaSrs.as_bytes(),
            Tag::WireTestPayload.as_bytes(),
            Tag::WireFheKeygenShare.as_bytes(),
            Tag::WireFhePublicKey.as_bytes(),
            Tag::WireFheDecryptShare.as_bytes(),
            Tag::WirePvssShareOpenedProof.as_bytes(),
            Tag::WirePvssDecryptOpenedProof.as_bytes(),
            Tag::CycloAjtaiBinding.as_bytes(),
            Tag::PvssBatchedDkgShareEncryption.as_bytes(),
            Tag::PvssBatchedDkgShareEncryptionSkTrack.as_bytes(),
            Tag::PvssBatchedDkgShareEncryptionESmTrack.as_bytes(),
            Tag::PvssSmudgeSlotBatch.as_bytes(),
            Tag::PvssTranscriptRootBinding.as_bytes(),
            Tag::PvssC7DecryptAggregation.as_bytes(),
            Tag::PvssC7MerkleDecryptAggregation.as_bytes(),
            Tag::PvssFoldVerifier.as_bytes(),
            Tag::NovaRingVerifier.as_bytes(),
            Tag::NovaFheCompute.as_bytes(),
            Tag::NovaBootstrapStep.as_bytes(),
            Tag::SigmaSkBinding.as_bytes(),
            Tag::SigmaScalarChallenge.as_bytes(),
            Tag::SigmaSzGamma.as_bytes(),
            Tag::FiatShamirDomainPrefix.as_bytes(),
            Tag::BfvSigmaChallenge.as_bytes(),
            Tag::BootstrapSigmaChallenge.as_bytes(),
            Tag::BootstrapResult.as_bytes(),
            Tag::SchnorrChallenge.as_bytes(),
            Tag::GreyhoundPcs.as_bytes(),
            Tag::GreyhoundChallenge.as_bytes(),
            Tag::AjtaiCrs.as_bytes(),
            Tag::SigmaSessionBinding.as_bytes(),
            Tag::CycloFoldChallengeV2.as_bytes(),
            Tag::PvssDecryptBindingV1.as_bytes(),
            Tag::SchnorrPop.as_bytes(),
            Tag::LazerSessionBinding.as_bytes(),
            Tag::HashBridgeCommit.as_bytes(),
            Tag::GreyhoundA.as_bytes(),
            Tag::GreyhoundB.as_bytes(),
            Tag::GreyhoundD.as_bytes(),
            Tag::ProtocolPrefix.as_bytes(),
            Tag::AjtaiCommit.as_bytes(),
            Tag::BfvEncryptionSnapshot.as_bytes(),
            Tag::BfvEncryption.as_bytes(),
            Tag::CiphertextV.as_bytes(),
            Tag::CycloFoldArecibo.as_bytes(),
            Tag::DealerParity.as_bytes(),
            Tag::DecryptNizkProofs.as_bytes(),
            Tag::DkgAgg.as_bytes(),
            Tag::LagrangeFold.as_bytes(),
            Tag::MicronovaHeterogeneousStepCircuit.as_bytes(),
            Tag::MicronovaInternalFoldVerifierV1.as_bytes(),
            Tag::MicronovaInternalFoldVerifierV3.as_bytes(),
            Tag::MicronovaLagrangeFold.as_bytes(),
            Tag::MicronovaLeafRingVerifier.as_bytes(),
            Tag::MicronovaParty.as_bytes(),
            Tag::MicronovaPk.as_bytes(),
            Tag::MicronovaShare.as_bytes(),
            Tag::NovaAjtaiCommitment.as_bytes(),
            Tag::ParticipantSet.as_bytes(),
            Tag::PerNodeC7.as_bytes(),
            Tag::PkAggregation.as_bytes(),
            Tag::PkContribution.as_bytes(),
            Tag::PvssShareVerifySigma.as_bytes(),
            Tag::SchemeSwitch.as_bytes(),
            Tag::SessionId.as_bytes(),
            Tag::Transcript.as_bytes(),
        ];
        &ALL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_domain_tags_are_declared() {
        let tags = Tag::all_literals();
        assert!(!tags.is_empty(), "tag list must not be empty");

        // Every tag must be non-empty.
        for (i, tag) in tags.iter().enumerate() {
            assert!(!tag.is_empty(), "tag at index {i} is empty");
        }

        // All tags must be pairwise distinct.
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(
                    tags[i],
                    tags[j],
                    "tags at indices {i} and {j} collide: {:?}",
                    String::from_utf8_lossy(tags[i])
                );
            }
        }
    }
}
