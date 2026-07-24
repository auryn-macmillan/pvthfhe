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
    /// `pvthfhe-final-decrypt-aggregation-v1` — final decryption aggregation transcript domain.
    FinalDecryptAggregation,
    /// `pvthfhe-final-plaintext-hash-v1` — final plaintext hash binding domain.
    FinalPlaintextHash,
    /// `pvthfhe-decrypt-dkg-anchored-binding-v2` — DKG-anchored decryption binding domain.
    DecryptDkgAnchoredBindingV2,
    /// `pvthfhe-c5-pop/v1` — C5 proof-of-possession hashing domain.
    C5Pop,
    /// `pvthfhe-c5-proof-root/v1` — C5 proof root hash domain.
    C5ProofRoot,
    /// `pvthfhe-dkg-commit-reveal/v2` — DKG round-1 commit-reveal binding domain.
    DkgCommitRevealV2,
    /// `pvthfhe-sim-keygen-v1` — keygen simulator per-party key derivation domain.
    SimKeygen,
    /// `pvthfhe-sim-schnorr-v1` — keygen simulator Schnorr keypair derivation domain.
    SimSchnorr,
    /// `pvthfhe-sim-nonequiv-rng-v1` — keygen simulator NonEquiv RNG seed domain.
    SimNonEquivRng,
    /// `pvthfhe-sim-share-v1` — keygen simulator share derivation domain.
    SimShare,
    /// `pvthfhe-sim-encrypt-v1` — keygen simulator share-encryption seed domain.
    SimEncrypt,
    /// `pvthfhe-sim-nizk-rng-v1` — keygen simulator NIZK RNG seed domain.
    SimNizkRng,
    /// `pvthfhe-sim-witness-poly-v1` — keygen simulator witness-poly derivation domain.
    SimWitnessPoly,
    /// `pvthfhe-sim-nizk-error-v1` — keygen simulator NIZK error-poly derivation domain.
    SimNizkError,
    /// `pvthfhe-leader-election/v1` — weak leader election rank domain.
    LeaderElection,
    /// `pvthfhe-verification-proof-v1` — IVC verification proof binding domain.
    VerificationProof,
    /// `pvthfhe-cli/nizk-error-demo/v1` — CLI demo NIZK error-poly derivation domain.
    CliNizkErrorDemo,
    /// `pvthfhe-ring-challenge/v1` — ring-equation ternary challenge domain.
    RingChallenge,
    /// `pvthfhe-ring-d-statement/v1` — ring d-statement derivation domain.
    RingDStatement,
    /// `pvthfhe-node-schnorr-commit/v1` — per-node Schnorr commitment message domain.
    NodeSchnorrCommit,
    /// `pvthfhe-e2e/keygen_nizk/v1` — e2e keygen NIZK session binding domain.
    E2eKeygenNizk,
    /// `pvthfhe-nizk-adapter/v1` — NIZK adapter pipeline hash domain.
    NizkAdapter,
    /// `pvthfhe-dkg-precompute/v1` — DKG precompute deal-seed domain.
    DkgPrecompute,
    /// `pvthfhe-cyclo-params-v1` — Cyclo parameter digest domain.
    CycloParams,
    /// `pvthfhe-cyclo-public-io-binding-v1` — Cyclo public-IO binding domain.
    CycloPublicIoBinding,
    /// `pvthfhe-cyclo-batch-io-v1` — Cyclo batched fold public-IO domain.
    CycloBatchIo,
    /// `pvthfhe-cyclo-batch-beta-v1` — Cyclo batched fold beta derivation domain.
    CycloBatchBeta,
    /// `pvthfhe-cyclo-ext-ajtai-v1` — Cyclo extension Ajtai hash domain.
    CycloExtAjtai,
    /// `pvthfhe-cyclo-fs-v1` — Cyclo Fiat-Shamir v1 challenge domain.
    CycloFsV1,
    /// `pvthfhe-cyclo-fs-v2` — Cyclo Fiat-Shamir v2 challenge domain (binds params digest).
    CycloFsV2,
    /// `pvthfhe-cyclo-fold-v1` — Cyclo fold commitment hash domain.
    CycloFoldCommitment,
    /// `pvthfhe-cyclo-fold-io-v1` — Cyclo fold public-IO hash domain.
    CycloFoldIo,
    /// `pvthfhe-cyclo-init-v1` — Cyclo init commitment hash domain.
    CycloInit,
    /// `pvthfhe-cyclo-init-io-v1` — Cyclo init public-IO hash domain.
    CycloInitIo,
    /// `pvthfhe-fold-track-sk-v1` — fold track secret-key label.
    FoldTrackSk,
    /// `pvthfhe-fold-track-e-sm-v1` — fold track committed-smudge label.
    FoldTrackESm,
    /// `pvthfhe-fold-track-encryption-witness-v1` — fold track encryption-witness label.
    FoldTrackEncryptionWitness,
    /// `pvthfhe-cyclo-multitrack-fold-v1` — multi-track fold metadata encoding domain.
    CycloMultitrackFold,
    /// `pvthfhe-esm-noise-v1` — smudge-noise derivation domain.
    EsmNoise,
    /// `pvthfhe-share-rng-seed-v2` — Shamir share RNG seed domain.
    ShareRngSeedV2,
    /// `pvthfhe-verification-stmt-v1` — verification statement V1 domain separator.
    VerificationStmt,
    /// `pvthfhe-fuzz-seed-v1` — fuzz harness RNG seed domain.
    FuzzSeed,
    /// `pvthfhe-ajtai-d2-commitment-v1` — Ajtai D2 commitment digest domain.
    AjtaiD2Commitment,
    /// `pvthfhe-non-equiv/v1` — NonEquiv protocol domain separator.
    NonEquiv,
    /// `pvthfhe-avid/v1` — AVID dispersal domain separator.
    Avid,
    /// `pvthfhe-dkg-sk-dealer-share-commitment-v1` — DKG sk dealer-share commitment domain.
    DkgSkDealerShareCommitment,
    /// `pvthfhe-dkg-esm-dealer-share-commitment-v1` — DKG e_sm dealer-share commitment domain.
    DkgEsmDealerShareCommitment,
    /// `pvthfhe-dkg-sk-aggregate-commitment-v1` — DKG sk aggregate commitment domain.
    DkgSkAggregateCommitment,
    /// `pvthfhe-dkg-esm-aggregate-commitment-v1` — DKG e_sm aggregate commitment domain.
    DkgEsmAggregateCommitment,
    /// `pvthfhe-key-escrow/v1` — key escrow protocol domain separator.
    KeyEscrow,
    /// `pvthfhe-dkg-accepted-participant-set-v1` — DKG accepted-participant-set hash domain.
    DkgAcceptedParticipantSet,
    /// `pvthfhe-bfv-crp-v1` — BFV common random polynomial domain.
    BfvCrp,
    /// `pvthfhe-bfv-b-poly-v1` — BFV public component b polynomial domain.
    BfvBPoly,
    /// `pvthfhe-dealer-index-v1` — dealer index derivation domain.
    DealerIndex,
    /// `pvthfhe-decrypt-ciphertext-hash-v1` — committed-smudge decrypt ciphertext hash domain.
    DecryptCiphertextHash,
    /// `pvthfhe-decrypt-party-binding-v1` — decrypt party binding derivation domain.
    DecryptPartyBinding,
    /// `pvthfhe-committed-smudge-slot-v1` — committed-smudge slot binding domain.
    CommittedSmudgeSlot,
    /// `pvthfhe-keygen-dcommit/v1` — keygen d-commitment hash domain.
    KeygenDcommit,
    /// `pvthfhe-share-relation-binding-v2` — share relation binding domain.
    ShareRelationBindingV2,
    /// `pvthfhe-d2-ajtai-matrix-v1` — D2 Ajtai matrix seed domain.
    D2AjtaiMatrix,
    /// `pvthfhe-bfv-params-v1` — canonical BFV parameters digest domain.
    BfvParams,
    /// `pvthfhe-share-dcommit/v1` — share d-commitment hash domain.
    ShareDcommit,
    /// `pvthfhe-share-sigma-witness-digest-v1` — share sigma witness digest domain.
    ShareSigmaWitnessDigest,
    /// `pvthfhe-share-sigma-c-rns-v1` — share sigma c_rns derivation domain.
    ShareSigmaCRns,
    /// `pvthfhe-share-bfv-sigma-binding-v5` — share BFV sigma binding domain.
    ShareBfvSigmaBindingV5,
    /// `pvthfhe-norm-witness-v1` — parity norm-witness hash domain.
    NormWitness,
    /// `pvthfhe-encryption-validity-v1` — parity encryption-validity hash domain.
    EncryptionValidity,
    /// `pvthfhe-share-computation-sk-commitment-v1` — share-computation sk commitment domain.
    ShareComputationSkCommitment,
    /// `pvthfhe-share-computation-esm-commitment-v1` — share-computation e_sm commitment domain.
    ShareComputationEsmCommitment,
    /// `pvthfhe-share-computation-public-instance-v1` — share-computation public-instance commitment domain.
    ShareComputationPublicInstance,
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
            Tag::FinalDecryptAggregation => b"pvthfhe-final-decrypt-aggregation-v1",
            Tag::FinalPlaintextHash => b"pvthfhe-final-plaintext-hash-v1",
            Tag::DecryptDkgAnchoredBindingV2 => b"pvthfhe-decrypt-dkg-anchored-binding-v2",
            Tag::C5Pop => b"pvthfhe-c5-pop/v1",
            Tag::C5ProofRoot => b"pvthfhe-c5-proof-root/v1",
            Tag::DkgCommitRevealV2 => b"pvthfhe-dkg-commit-reveal/v2",
            Tag::SimKeygen => b"pvthfhe-sim-keygen-v1",
            Tag::SimSchnorr => b"pvthfhe-sim-schnorr-v1",
            Tag::SimNonEquivRng => b"pvthfhe-sim-nonequiv-rng-v1",
            Tag::SimShare => b"pvthfhe-sim-share-v1",
            Tag::SimEncrypt => b"pvthfhe-sim-encrypt-v1",
            Tag::SimNizkRng => b"pvthfhe-sim-nizk-rng-v1",
            Tag::SimWitnessPoly => b"pvthfhe-sim-witness-poly-v1",
            Tag::SimNizkError => b"pvthfhe-sim-nizk-error-v1",
            Tag::LeaderElection => b"pvthfhe-leader-election/v1",
            Tag::VerificationProof => b"pvthfhe-verification-proof-v1",
            Tag::CliNizkErrorDemo => b"pvthfhe-cli/nizk-error-demo/v1",
            Tag::RingChallenge => b"pvthfhe-ring-challenge/v1",
            Tag::RingDStatement => b"pvthfhe-ring-d-statement/v1",
            Tag::NodeSchnorrCommit => b"pvthfhe-node-schnorr-commit/v1",
            Tag::E2eKeygenNizk => b"pvthfhe-e2e/keygen_nizk/v1",
            Tag::NizkAdapter => b"pvthfhe-nizk-adapter/v1",
            Tag::DkgPrecompute => b"pvthfhe-dkg-precompute/v1",
            Tag::CycloParams => b"pvthfhe-cyclo-params-v1",
            Tag::CycloPublicIoBinding => b"pvthfhe-cyclo-public-io-binding-v1",
            Tag::CycloBatchIo => b"pvthfhe-cyclo-batch-io-v1",
            Tag::CycloBatchBeta => b"pvthfhe-cyclo-batch-beta-v1",
            Tag::CycloExtAjtai => b"pvthfhe-cyclo-ext-ajtai-v1",
            Tag::CycloFsV1 => b"pvthfhe-cyclo-fs-v1",
            Tag::CycloFsV2 => b"pvthfhe-cyclo-fs-v2",
            Tag::CycloFoldCommitment => b"pvthfhe-cyclo-fold-v1",
            Tag::CycloFoldIo => b"pvthfhe-cyclo-fold-io-v1",
            Tag::CycloInit => b"pvthfhe-cyclo-init-v1",
            Tag::CycloInitIo => b"pvthfhe-cyclo-init-io-v1",
            Tag::FoldTrackSk => b"pvthfhe-fold-track-sk-v1",
            Tag::FoldTrackESm => b"pvthfhe-fold-track-e-sm-v1",
            Tag::FoldTrackEncryptionWitness => b"pvthfhe-fold-track-encryption-witness-v1",
            Tag::CycloMultitrackFold => b"pvthfhe-cyclo-multitrack-fold-v1",
            Tag::EsmNoise => b"pvthfhe-esm-noise-v1",
            Tag::ShareRngSeedV2 => b"pvthfhe-share-rng-seed-v2",
            Tag::VerificationStmt => b"pvthfhe-verification-stmt-v1",
            Tag::FuzzSeed => b"pvthfhe-fuzz-seed-v1",
            Tag::AjtaiD2Commitment => b"pvthfhe-ajtai-d2-commitment-v1",
            Tag::NonEquiv => b"pvthfhe-non-equiv/v1",
            Tag::Avid => b"pvthfhe-avid/v1",
            Tag::DkgSkDealerShareCommitment => b"pvthfhe-dkg-sk-dealer-share-commitment-v1",
            Tag::DkgEsmDealerShareCommitment => b"pvthfhe-dkg-esm-dealer-share-commitment-v1",
            Tag::DkgSkAggregateCommitment => b"pvthfhe-dkg-sk-aggregate-commitment-v1",
            Tag::DkgEsmAggregateCommitment => b"pvthfhe-dkg-esm-aggregate-commitment-v1",
            Tag::KeyEscrow => b"pvthfhe-key-escrow/v1",
            Tag::DkgAcceptedParticipantSet => b"pvthfhe-dkg-accepted-participant-set-v1",
            Tag::BfvCrp => b"pvthfhe-bfv-crp-v1",
            Tag::BfvBPoly => b"pvthfhe-bfv-b-poly-v1",
            Tag::DealerIndex => b"pvthfhe-dealer-index-v1",
            Tag::DecryptCiphertextHash => b"pvthfhe-decrypt-ciphertext-hash-v1",
            Tag::DecryptPartyBinding => b"pvthfhe-decrypt-party-binding-v1",
            Tag::CommittedSmudgeSlot => b"pvthfhe-committed-smudge-slot-v1",
            Tag::KeygenDcommit => b"pvthfhe-keygen-dcommit/v1",
            Tag::ShareRelationBindingV2 => b"pvthfhe-share-relation-binding-v2",
            Tag::D2AjtaiMatrix => b"pvthfhe-d2-ajtai-matrix-v1",
            Tag::BfvParams => b"pvthfhe-bfv-params-v1",
            Tag::ShareDcommit => b"pvthfhe-share-dcommit/v1",
            Tag::ShareSigmaWitnessDigest => b"pvthfhe-share-sigma-witness-digest-v1",
            Tag::ShareSigmaCRns => b"pvthfhe-share-sigma-c-rns-v1",
            Tag::ShareBfvSigmaBindingV5 => b"pvthfhe-share-bfv-sigma-binding-v5",
            Tag::NormWitness => b"pvthfhe-norm-witness-v1",
            Tag::EncryptionValidity => b"pvthfhe-encryption-validity-v1",
            Tag::ShareComputationSkCommitment => b"pvthfhe-share-computation-sk-commitment-v1",
            Tag::ShareComputationEsmCommitment => b"pvthfhe-share-computation-esm-commitment-v1",
            Tag::ShareComputationPublicInstance => b"pvthfhe-share-computation-public-instance-v1",
        }
    }

    pub const fn all_literals() -> &'static [&'static [u8]] {
        const ALL: [&[u8]; 141] = [
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
            Tag::FinalDecryptAggregation.as_bytes(),
            Tag::FinalPlaintextHash.as_bytes(),
            Tag::DecryptDkgAnchoredBindingV2.as_bytes(),
            Tag::C5Pop.as_bytes(),
            Tag::C5ProofRoot.as_bytes(),
            Tag::DkgCommitRevealV2.as_bytes(),
            Tag::SimKeygen.as_bytes(),
            Tag::SimSchnorr.as_bytes(),
            Tag::SimNonEquivRng.as_bytes(),
            Tag::SimShare.as_bytes(),
            Tag::SimEncrypt.as_bytes(),
            Tag::SimNizkRng.as_bytes(),
            Tag::SimWitnessPoly.as_bytes(),
            Tag::SimNizkError.as_bytes(),
            Tag::LeaderElection.as_bytes(),
            Tag::VerificationProof.as_bytes(),
            Tag::CliNizkErrorDemo.as_bytes(),
            Tag::RingChallenge.as_bytes(),
            Tag::RingDStatement.as_bytes(),
            Tag::NodeSchnorrCommit.as_bytes(),
            Tag::E2eKeygenNizk.as_bytes(),
            Tag::NizkAdapter.as_bytes(),
            Tag::DkgPrecompute.as_bytes(),
            Tag::CycloParams.as_bytes(),
            Tag::CycloPublicIoBinding.as_bytes(),
            Tag::CycloBatchIo.as_bytes(),
            Tag::CycloBatchBeta.as_bytes(),
            Tag::CycloExtAjtai.as_bytes(),
            Tag::CycloFsV1.as_bytes(),
            Tag::CycloFsV2.as_bytes(),
            Tag::CycloFoldCommitment.as_bytes(),
            Tag::CycloFoldIo.as_bytes(),
            Tag::CycloInit.as_bytes(),
            Tag::CycloInitIo.as_bytes(),
            Tag::FoldTrackSk.as_bytes(),
            Tag::FoldTrackESm.as_bytes(),
            Tag::FoldTrackEncryptionWitness.as_bytes(),
            Tag::CycloMultitrackFold.as_bytes(),
            Tag::EsmNoise.as_bytes(),
            Tag::ShareRngSeedV2.as_bytes(),
            Tag::VerificationStmt.as_bytes(),
            Tag::FuzzSeed.as_bytes(),
            Tag::AjtaiD2Commitment.as_bytes(),
            Tag::NonEquiv.as_bytes(),
            Tag::Avid.as_bytes(),
            Tag::DkgSkDealerShareCommitment.as_bytes(),
            Tag::DkgEsmDealerShareCommitment.as_bytes(),
            Tag::DkgSkAggregateCommitment.as_bytes(),
            Tag::DkgEsmAggregateCommitment.as_bytes(),
            Tag::KeyEscrow.as_bytes(),
            Tag::DkgAcceptedParticipantSet.as_bytes(),
            Tag::BfvCrp.as_bytes(),
            Tag::BfvBPoly.as_bytes(),
            Tag::DealerIndex.as_bytes(),
            Tag::DecryptCiphertextHash.as_bytes(),
            Tag::DecryptPartyBinding.as_bytes(),
            Tag::CommittedSmudgeSlot.as_bytes(),
            Tag::KeygenDcommit.as_bytes(),
            Tag::ShareRelationBindingV2.as_bytes(),
            Tag::D2AjtaiMatrix.as_bytes(),
            Tag::BfvParams.as_bytes(),
            Tag::ShareDcommit.as_bytes(),
            Tag::ShareSigmaWitnessDigest.as_bytes(),
            Tag::ShareSigmaCRns.as_bytes(),
            Tag::ShareBfvSigmaBindingV5.as_bytes(),
            Tag::NormWitness.as_bytes(),
            Tag::EncryptionValidity.as_bytes(),
            Tag::ShareComputationSkCommitment.as_bytes(),
            Tag::ShareComputationEsmCommitment.as_bytes(),
            Tag::ShareComputationPublicInstance.as_bytes(),
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
