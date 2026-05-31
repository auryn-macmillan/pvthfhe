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
        }
    }

    pub const fn all_literals() -> &'static [&'static [u8]] {
        const ALL: [&[u8]; 24] = [
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
        ];
        &ALL
    }
}
