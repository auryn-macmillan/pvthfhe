// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./generated/HonkVerifier.sol";
import "./SessionRegistry.sol";
import "./VerificationStatementV1.sol";

/// @notice EIP-712 attestation bundle emitted by the off-chain Nova verifier.
struct AttestationBundle {
    bytes32 novaStateCommitment;
    bytes32 cycloAggregateCommitment;
    bytes32 sessionId;
    address signer;
    bytes signature;
}

/// @notice IVC proof binding data for on-chain verification (P4 + P1.5 + S6).
struct IvcBinding {
    bytes32 ivcProofHash;
    bytes32 ivcVkHash;
    bytes32 ivcPpHash;
    bytes32 z0Commitment;
    bytes32 ziCommitment;
    uint64 ivcSteps;
    bytes32 shareVerificationHash;
    bytes32 decryptNizkHash;
    bytes32 dkgTranscriptHash;
    /// C5 aggregate public-key formation proof root (SHA-256).
    /// Binds the per-participant PoP proofs and the pk_agg = Σ pk_i relation.
    bytes32 c5ProofRoot;
    bytes32 novaFinalStateCommitment;
    /// DEPRECATED: ivcVerifyResult is ignored ABI baggage and never gates acceptance.
    uint64 ivcVerifyResult;
    /// T6: Bootstrap result hash (binds TFHE bootstrapping integrity).
    /// Must be non-zero when bootstrapping is used.
    bytes32 bootstrapResultHash;
}

/// @title ISessionRegistry
interface ISessionRegistry {
    function sessions(bytes32 dkgRoot)
        external
        view
        returns (uint32 n, uint32 t, bytes32 rosterHash, bool registered, bool aborted, uint64 runId);
    function isEpochConsumed(bytes32 dkgRoot, bytes32 sessionId, uint64 epoch) external view returns (bool);
    function getRunId(bytes32 dkgRoot) external view returns (uint64);
    function markEpochConsumed(bytes32 dkgRoot, bytes32 sessionId, uint64 epoch) external;
    function recordSmudgeSlotUse(
        bytes32 dkgRoot, bytes32 sessionId,
        uint32 partyId,
        uint32 slot,
        bytes32 ciphertextHash,
        uint64 decryptRound
    ) external;
}

/// @title IIvcDeciderVerifier
interface IIvcDeciderVerifier {
    function verify(
        bytes calldata proof,
        bytes32 statementHash,
        bytes32 vkHash,
        bytes32 ppHash,
        bytes32 z0,
        bytes32 zi,
        uint64 steps,
        bytes32 ivcProofHash
    ) external returns (bool);
}

/// @title IPvthfheVerifier
interface IPvthfheVerifier {
    function verify(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external view returns (bool valid);

    function verifyWithIvc(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        IvcBinding calldata ivcBinding,
        bytes calldata proof
    ) external view returns (bool valid);

    function verifyWithAttestation(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        AttestationBundle calldata attestation
    ) external view returns (bool valid);

    function threshold() external view returns (uint32);

    function verifyAndConsume(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external returns (bool valid);

    function verifyAndConsumeWithIvc(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        IvcBinding calldata ivcBinding,
        bytes calldata proof
    ) external returns (bool valid);

    function verifyAndConsumeWithSmudgeSlots(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof,
        uint32[] calldata partyIds,
        uint32[] calldata slots,
        uint64 decryptRound
    ) external returns (bool valid);

    function rlweDegree() external view returns (uint32);
}

/// @title PvtFheVerifier
/// @notice On-chain verifier for PVTHFHE threshold decryption results.
///
/// @dev R6.1: verify() delegates to HonkVerifier (BB-generated UltraHonk verifier).
///      P4: verifyWithIvc() extends verify() with IVC proof binding data.
///
/// Calldata layout (per T22 spec):
///   ciphertextHash    bytes32  32 B
///   plaintextHash     bytes32  32 B
///   aggregatePkHash   bytes32  32 B
///   dkgRoot           bytes32  32 B
///   epoch             uint64    8 B
///   participantSetHash bytes32  32 B
///   dCommitment       bytes32  32 B
///   proof             bytes    ~14 KB (dynamic)
///   Total on-chain calldata: ~14.2 KB -> ~227,200 gas (well within 5M budget)
contract PvtFheVerifier is IPvthfheVerifier {
    uint32 private constant _RLWE_DEGREE = 8192;

    error AnchorMismatch();

    struct DkgPublicAnchors {
        bytes32 dkgRoot;
        bytes32 aggregatedPkCommit;
        bytes32 participantSetHash;
        bytes32 skAggCommitsRoot;
        bytes32 esmAggCommitsRoot;
        bytes32 smudgeSlotPolicyHash;
    }

    struct DecryptionPublicAnchors {
        bytes32 dkgRoot;
        bytes32 ciphertextHash;
        bytes32 expectedSkCommitsRoot;
        bytes32 expectedEsmCommitsRoot;
        uint64 slotId;
        uint64 decryptRound;
        bytes32 plaintextHash;
    }

    HonkVerifier private immutable _honkVerifier;
    ISessionRegistry public immutable registry;
    address public immutable timelock;
    address public ivcDeciderVerifier;
    mapping(address => bool) public attestors;

    /// @notice EIP-712 domain separator for attestation signature verification.
    /// @dev Computed once at construction to avoid recomputation; matches EIP-712 spec.
    bytes32 private immutable DOMAIN_SEPARATOR;

    /// @notice EIP-712 type hash for Attestation struct.
    /// @dev keccak256("Attestation(bytes32 novaStateCommitment,bytes32 cycloAggregateCommitment,bytes32 sessionId,address signer)")
    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "Attestation(bytes32 novaStateCommitment,bytes32 cycloAggregateCommitment,bytes32 sessionId,address signer)"
    );
    mapping(bytes32 => DkgPublicAnchors) private _dkgPublicAnchors;
    mapping(bytes32 => bool) private _dkgPublicAnchorsStored;

    /// P4: IVC proof binding records for on-chain replay of IVC state.
    /// Maps dkgRoot => epoch => ivcProofHash to prevent IVC proof replay.
    mapping(bytes32 => mapping(uint64 => bytes32)) private _ivcProofConsumed;

    event IvcProofConsumed(bytes32 indexed dkgRoot, uint64 indexed epoch, bytes32 ivcProofHash);

    constructor(address registry_, address timelock_) {
        _honkVerifier = new HonkVerifier();
        registry = ISessionRegistry(registry_);
        timelock = timelock_;
        // EIP-712 domain separator: committed at construction for phish-resistance
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("PVTHFHE")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // -------------------------------------------------------------------------
    // IPvthfheVerifier implementation
    //
    // GAP-5 NOTE (MPC-AUDIT-2026-06-12): verify() and verifyAndConsume() do NOT
    // validate IVC binding fields and do NOT call the IVC decider.  Callers
    // requiring full Nova IVC chain verification must use verifyWithIvc() or
    // verifyAndConsumeWithIvc().
    // -------------------------------------------------------------------------

    function verify(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external view override returns (bool) {
        _requireSessionValid(dkgRoot, sessionId, epoch);
        // HonkVerifier VK expects 7 public inputs (15 VK - 8 pairing points).
        // sessionId is checked via _requireSessionValid; not bound to the proof.
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = ciphertextHash;
        publicInputs[1] = plaintextHash;
        publicInputs[2] = aggregatePkHash;
        publicInputs[3] = dkgRoot;
        publicInputs[4] = bytes32(uint256(epoch));
        publicInputs[5] = participantSetHash;
        publicInputs[6] = dCommitment;
        return _honkVerifier.verify(proof, publicInputs);
    }

    /// P4: verify with IVC proof binding data.
    /// The IVC fields bind the Nova IVC proof to the on-chain verification,
    /// replacing the Poseidon hash shortcut. All IVC fields must be non-zero
    /// and the ivcProofHash must not have been consumed for this dkgRoot+epoch.
    function verifyWithIvc(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        IvcBinding calldata ivcBinding,
        bytes calldata proof
    ) public view override returns (bool) {
        require(ivcDeciderVerifier != address(0), "PVTHFHE: IVC decider not configured");
        require(proof.length != 0, "PVTHFHE: empty IVC proof");
        _requireSessionValid(dkgRoot, sessionId, epoch);
        _requireIvcBindingValid(ivcBinding);
        require(ivcBinding.shareVerificationHash != bytes32(0), "PVTHFHE: shareVerificationHash zero");

        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = ciphertextHash;
        publicInputs[1] = plaintextHash;
        publicInputs[2] = aggregatePkHash;
        publicInputs[3] = dkgRoot;
        publicInputs[4] = bytes32(uint256(epoch));
        publicInputs[5] = participantSetHash;
        publicInputs[6] = dCommitment;
        if (!_honkVerifier.verify(proof, publicInputs)) {
            return false;
        }

        bytes32 statementHash = _computeIvcStatementHash(
            ciphertextHash, plaintextHash, aggregatePkHash, dkgRoot, sessionId, epoch, participantSetHash, dCommitment, ivcBinding
        );
        return _verifyIvcDeciderStatic(proof, statementHash, ivcBinding);
    }

    function verifyAndConsume(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external override returns (bool) {
        _requireSessionValid(dkgRoot, sessionId, epoch);
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = ciphertextHash;
        publicInputs[1] = plaintextHash;
        publicInputs[2] = aggregatePkHash;
        publicInputs[3] = dkgRoot;
        publicInputs[4] = bytes32(uint256(epoch));
        publicInputs[5] = participantSetHash;
        publicInputs[6] = dCommitment;

        bool proofValid = _honkVerifier.verify(proof, publicInputs);
        if (!proofValid) {
            return false;
        }
        registry.markEpochConsumed(dkgRoot, sessionId, epoch);
        return true;
    }

    /// P4: verifyAndConsume with IVC proof binding.
    /// Atomically verifies the proof AND records the IVC proof hash consumption.
    function verifyAndConsumeWithIvc(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        IvcBinding calldata ivcBinding,
        bytes calldata proof
    ) external override returns (bool) {
        require(ivcDeciderVerifier != address(0), "PVTHFHE: IVC decider not configured");
        require(proof.length != 0, "PVTHFHE: empty IVC proof");
        _requireSessionValid(dkgRoot, sessionId, epoch);
        _requireIvcBindingValid(ivcBinding);
        require(ivcBinding.shareVerificationHash != bytes32(0), "PVTHFHE: shareVerificationHash zero");
        if (!_ivcProofConsumedValid(dkgRoot, sessionId, epoch, ivcBinding.ivcProofHash)) {
            revert("PVTHFHE: IVC proof replay");
        }

        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = ciphertextHash;
        publicInputs[1] = plaintextHash;
        publicInputs[2] = aggregatePkHash;
        publicInputs[3] = dkgRoot;
        publicInputs[4] = bytes32(uint256(epoch));
        publicInputs[5] = participantSetHash;
        publicInputs[6] = dCommitment;
        if (!_honkVerifier.verify(proof, publicInputs)) {
            return false;
        }

        bytes32 statementHash = _computeIvcStatementHash(
            ciphertextHash, plaintextHash, aggregatePkHash, dkgRoot, sessionId, epoch, participantSetHash, dCommitment, ivcBinding
        );
        bool proofValid = _verifyIvcDecider(proof, statementHash, ivcBinding);
        if (!proofValid) {
            return false;
        }

        _consumeIvcProof(dkgRoot, sessionId, epoch, ivcBinding.ivcProofHash);
        registry.markEpochConsumed(dkgRoot, sessionId, epoch);
        return true;
    }

    function verifyAndConsumeWithPublicAnchors(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof,
        DecryptionPublicAnchors memory decryptAnchors
    ) external returns (bool) {
        _requireSessionValid(dkgRoot, sessionId, epoch);
        if (
            decryptAnchors.dkgRoot != dkgRoot || decryptAnchors.ciphertextHash != ciphertextHash
                || decryptAnchors.plaintextHash != plaintextHash
        ) {
            revert AnchorMismatch();
        }

        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = ciphertextHash;
        publicInputs[1] = plaintextHash;
        publicInputs[2] = aggregatePkHash;
        publicInputs[3] = dkgRoot;
        publicInputs[4] = bytes32(uint256(epoch));
        publicInputs[5] = participantSetHash;
        publicInputs[6] = dCommitment;

        bool proofValid = _honkVerifier.verify(proof, publicInputs);
        if (!proofValid) {
            return false;
        }

        verifyStoredPublicAnchors(decryptAnchors);
        registry.markEpochConsumed(dkgRoot, sessionId, epoch);
        return true;
    }

    function verifyAndConsumeWithSmudgeSlots(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof,
        uint32[] calldata partyIds,
        uint32[] calldata slots,
        uint64 decryptRound
    ) external override returns (bool) {
        if (partyIds.length == 0 || partyIds.length != slots.length) {
            revert("PVTHFHE: malformed smudge slots");
        }
        _requireSessionValid(dkgRoot, sessionId, epoch);

        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = ciphertextHash;
        publicInputs[1] = plaintextHash;
        publicInputs[2] = aggregatePkHash;
        publicInputs[3] = dkgRoot;
        publicInputs[4] = bytes32(uint256(epoch));
        publicInputs[5] = participantSetHash;
        publicInputs[6] = dCommitment;

        bool proofValid = _honkVerifier.verify(proof, publicInputs);
        if (!proofValid) {
            return false;
        }

        for (uint256 i = 0; i < partyIds.length; i++) {
            registry.recordSmudgeSlotUse(dkgRoot, sessionId, partyIds[i], slots[i], ciphertextHash, decryptRound);
        }
        registry.markEpochConsumed(dkgRoot, sessionId, epoch);
        return true;
    }

    function verifyWithAttestation(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        AttestationBundle calldata attestation
    ) external view override returns (bool) {
        if (!attestors[attestation.signer]) {
            revert("InvalidAttestor");
        }
        if (publicInputs.length < 6) {
            revert("CommitmentMismatch");
        }
        if (
            publicInputs[4] != attestation.novaStateCommitment
                || publicInputs[5] != attestation.cycloAggregateCommitment
        ) {
            revert("CommitmentMismatch");
        }

        // EIP-712 typed structured data hashing (L3 fix)
        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                attestation.novaStateCommitment,
                attestation.cycloAggregateCommitment,
                attestation.sessionId,
                attestation.signer
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        _verifyAttestationSignature(digest, attestation.signature, attestation.signer);

        bool proofValid = _honkVerifier.verify(proof, publicInputs);
        if (!proofValid) {
            revert("InvalidProof");
        }
        return true;
    }

    function threshold() external pure override returns (uint32) {
        return 0;
    }

    function registeredThreshold(bytes32 dkgRoot) external view returns (uint32) {
        (, uint32 t,,,,) = registry.sessions(dkgRoot);
        return t;
    }

    function rlweDegree() external pure override returns (uint32) {
        return _RLWE_DEGREE;
    }

    /// P4: Check if an IVC proof has been consumed for a given dkgRoot+epoch.
    function isIvcProofConsumed(bytes32 dkgRoot, bytes32 sessionId, uint64 epoch, bytes32 ivcProofHash) external view returns (bool) {
        return _ivcProofConsumed[dkgRoot][epoch] == ivcProofHash;
    }

    function verifyPublicAnchors(DkgPublicAnchors memory dkg, DecryptionPublicAnchors memory decrypt)
        public
        pure
        returns (bool)
    {
        if (
            dkg.dkgRoot != decrypt.dkgRoot || dkg.skAggCommitsRoot != decrypt.expectedSkCommitsRoot
                || dkg.esmAggCommitsRoot != decrypt.expectedEsmCommitsRoot
        ) {
            revert AnchorMismatch();
        }
        return true;
    }

    function storeDkgPublicAnchors(DkgPublicAnchors memory dkg) external {
        if (_dkgPublicAnchorsStored[dkg.dkgRoot]) {
            DkgPublicAnchors memory stored = _dkgPublicAnchors[dkg.dkgRoot];
            if (
                stored.aggregatedPkCommit != dkg.aggregatedPkCommit
                    || stored.participantSetHash != dkg.participantSetHash
                    || stored.skAggCommitsRoot != dkg.skAggCommitsRoot
                    || stored.esmAggCommitsRoot != dkg.esmAggCommitsRoot
                    || stored.smudgeSlotPolicyHash != dkg.smudgeSlotPolicyHash
            ) {
                revert AnchorMismatch();
            }
            return;
        }
        _dkgPublicAnchors[dkg.dkgRoot] = dkg;
        _dkgPublicAnchorsStored[dkg.dkgRoot] = true;
    }

    function loadDkgPublicAnchors(bytes32 dkgRoot) external view returns (DkgPublicAnchors memory) {
        if (!_dkgPublicAnchorsStored[dkgRoot]) {
            revert AnchorMismatch();
        }
        return _dkgPublicAnchors[dkgRoot];
    }

    function verifyStoredPublicAnchors(DecryptionPublicAnchors memory decrypt) public view returns (bool) {
        if (!_dkgPublicAnchorsStored[decrypt.dkgRoot]) {
            revert AnchorMismatch();
        }
        return verifyPublicAnchors(_dkgPublicAnchors[decrypt.dkgRoot], decrypt);
    }

    function addAttestor(address attestor) external {
        require(msg.sender == timelock, "Unauthorized");
        attestors[attestor] = true;
    }

    function removeAttestor(address attestor) external {
        require(msg.sender == timelock, "Unauthorized");
        attestors[attestor] = false;
    }

    function setIvcDeciderVerifier(address verifier) external {
        require(msg.sender == timelock, "Unauthorized");
        ivcDeciderVerifier = verifier;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    function _requireSessionValid(bytes32 dkgRoot, bytes32 sessionId, uint64 epoch) internal view {
        (,,, bool registered, bool aborted,) = registry.sessions(dkgRoot);
        if (!registered || aborted) {
            revert("PVTHFHE: unknown dkg root");
        }
        if (registry.isEpochConsumed(dkgRoot, sessionId, epoch)) {
            revert("PVTHFHE: epoch replay");
        }
    }

    /// P4+P1.5+S6: Verify IVC binding data is well-formed (all fields non-zero, steps positive).
    function _requireIvcBindingValid(IvcBinding calldata ivcBinding) internal pure {
        require(ivcBinding.ivcProofHash != bytes32(0), "PVTHFHE: ivcProofHash zero");
        require(ivcBinding.ivcVkHash != bytes32(0), "PVTHFHE: ivcVkHash zero");
        require(ivcBinding.ivcPpHash != bytes32(0), "PVTHFHE: ivcPpHash zero");
        require(ivcBinding.z0Commitment != bytes32(0), "PVTHFHE: z0Commitment zero");
        require(ivcBinding.ziCommitment != bytes32(0), "PVTHFHE: ziCommitment zero");
        require(ivcBinding.ivcSteps > 0, "PVTHFHE: ivcSteps zero");
        require(ivcBinding.decryptNizkHash != bytes32(0), "PVTHFHE: decryptNizkHash zero");
        require(ivcBinding.dkgTranscriptHash != bytes32(0), "PVTHFHE: dkgTranscriptHash zero");
        require(ivcBinding.c5ProofRoot != bytes32(0), "PVTHFHE: c5ProofRoot zero");
        require(ivcBinding.novaFinalStateCommitment != bytes32(0), "PVTHFHE: novaFinalStateCommitment zero");
        // F1: caller-supplied verify result is NOT trusted; real decider verification lands in Phase 2.
        require(ivcBinding.bootstrapResultHash != bytes32(0), "PVTHFHE: bootstrapResultHash zero");
    }

    /// P4: Check if IVC proof has not been consumed. Returns true if it's available.
    function _ivcProofConsumedValid(bytes32 dkgRoot, bytes32 sessionId, uint64 epoch, bytes32 ivcProofHash) internal view returns (bool) {
        return _ivcProofConsumed[dkgRoot][epoch] == bytes32(0)
            || _ivcProofConsumed[dkgRoot][epoch] == ivcProofHash;
    }

    function _computeIvcStatementHash(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        IvcBinding calldata ivcBinding
    ) internal pure returns (bytes32) {
        // Delegate struct construction to a pure helper to avoid stack-too-deep with 23-field Statement.
        VerificationStatementV1.Statement memory stmt = _buildIvcStatement(
            ciphertextHash, plaintextHash, aggregatePkHash, dkgRoot, sessionId,
            epoch, participantSetHash, dCommitment, ivcBinding
        );
        return VerificationStatementV1.computeStatementHashBytes32(stmt);
    }

    function _buildIvcStatement(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        IvcBinding calldata ivcBinding
    ) private pure returns (VerificationStatementV1.Statement memory stmt) {
        stmt.protocolVersion = 1;
        stmt.contextId = keccak256(abi.encode(dkgRoot, epoch, "pvthfhe/v1"));
        stmt.dkgRoot = dkgRoot;
        stmt.epoch = epoch;
        stmt.participantSetHash = participantSetHash;
        stmt.aggregatePkHash = aggregatePkHash;
        stmt.ciphertextHash = ciphertextHash;
        stmt.plaintextHash = plaintextHash;
        stmt.dCommitment = dCommitment;
        stmt.c5ProofRoot = ivcBinding.c5ProofRoot;
        stmt.c6ProofSetRoot = bytes32(0);
        stmt.cycloAccumulatorRoot = bytes32(0);
        stmt.ivcVkHash = ivcBinding.ivcVkHash;
        stmt.ivcPpHash = ivcBinding.ivcPpHash;
        stmt.ivcProofHash = ivcBinding.ivcProofHash;
        stmt.z0Commitment = ivcBinding.z0Commitment;
        stmt.ziCommitment = ivcBinding.ziCommitment;
        stmt.ivcSteps = ivcBinding.ivcSteps;
        stmt.bootstrapResultHash = ivcBinding.bootstrapResultHash;
        stmt.shareVerificationHash = ivcBinding.shareVerificationHash;
        stmt.decryptNizkHash = ivcBinding.decryptNizkHash;
        stmt.dkgTranscriptHash = ivcBinding.dkgTranscriptHash;
        stmt.novaFinalStateCommitment = ivcBinding.novaFinalStateCommitment;
    }

    /// NOTE (GAP-2 — MPC-AUDIT-2026-06-12): Uses `staticcall` and is therefore
    /// only compatible with VIEW (non-mutating) IVC deciders.  The
    /// `IvcChainDecider` requires the `verifyAndConsumeWithIvc()` path because
    /// its `verify()` function writes to the `consumed` mapping.
    /// Deciders intended for the `verifyWithIvc()` path must be view-compatible.
    function _verifyIvcDeciderStatic(bytes calldata proof, bytes32 statementHash, IvcBinding calldata ivcBinding)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory returndata) = ivcDeciderVerifier.staticcall(
            abi.encodeCall(
                IIvcDeciderVerifier.verify,
                (
                    proof,
                    statementHash,
                    ivcBinding.ivcVkHash,
                    ivcBinding.ivcPpHash,
                    ivcBinding.z0Commitment,
                    ivcBinding.ziCommitment,
                    ivcBinding.ivcSteps,
                    ivcBinding.ivcProofHash
                )
            )
        );
        if (!ok || returndata.length != 32) {
            return false;
        }
        return abi.decode(returndata, (bool));
    }

    function _verifyIvcDecider(bytes calldata proof, bytes32 statementHash, IvcBinding calldata ivcBinding)
        internal
        returns (bool)
    {
        try IIvcDeciderVerifier(ivcDeciderVerifier).verify(
            proof,
            statementHash,
            ivcBinding.ivcVkHash,
            ivcBinding.ivcPpHash,
            ivcBinding.z0Commitment,
            ivcBinding.ziCommitment,
            ivcBinding.ivcSteps,
            ivcBinding.ivcProofHash
        ) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// P4: Record consumption of an IVC proof.
    function _consumeIvcProof(bytes32 dkgRoot, bytes32 sessionId, uint64 epoch, bytes32 ivcProofHash) internal {
        _ivcProofConsumed[dkgRoot][epoch] = ivcProofHash;
        emit IvcProofConsumed(dkgRoot, epoch, ivcProofHash);
    }

    /// L3: Uses raw ecrecover (assembly) instead of EIP-712 typed structured data.
    /// EIP-712 would provide phishing resistance and signature clarity via domain
    /// separator + typed message hashing. Tracked as migration milestone:
    ///   - Phase 3 gate: upgrade attestation verification to EIP-712.
    ///   - Requires Solidity typed data hashing (structHash + domainSeparator).
    function _verifyAttestationSignature(bytes32 hash, bytes calldata signature, address expectedSigner) internal pure {
        require(signature.length == 65, "InvalidAttestationSignature");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "InvalidAttestationSignature");

        address recovered = ecrecover(hash, v, r, s);
        require(recovered == expectedSigner, "InvalidAttestationSignature");
    }

    function _touchInputs(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot, bytes32 sessionId,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) internal pure {
        bytes32 sink = ciphertextHash ^ plaintextHash ^ aggregatePkHash ^ dkgRoot ^ bytes32(uint256(epoch))
            ^ participantSetHash ^ dCommitment;
        uint256 proofLen = proof.length;
        assembly {
            pop(sink)
            pop(proofLen)
        }
    }
}
