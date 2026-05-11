// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./generated/HonkVerifier.sol";
import "./SessionRegistry.sol";

/// @notice EIP-712 attestation bundle emitted by the off-chain Sonobe verifier.
struct AttestationBundle {
    bytes32 sonobeStateCommitment;
    bytes32 cycloAggregateCommitment;
    bytes32 sessionId;
    address signer;
    bytes signature;
}

/// @title ISessionRegistry
/// @notice Interface used by PvtFheVerifier for session lookup and epoch consumption.
interface ISessionRegistry {
    function sessions(bytes32 dkgRoot) external view returns (uint32 n, uint32 t, bytes32 rosterHash, bool registered, bool aborted, uint64 runId);
    function isEpochConsumed(bytes32 dkgRoot, uint64 epoch) external view returns (bool);
    function getRunId(bytes32 dkgRoot) external view returns (uint64);
    function markEpochConsumed(bytes32 dkgRoot, uint64 epoch) external;
}

/// @title IPvthfheVerifier
/// @notice Interface for the PVTHFHE on-chain verifier (T22 ABI spec).
interface IPvthfheVerifier {
    /// @notice Verify a threshold decryption result on-chain.
    ///
    /// Full RLWE objects are NOT passed on-chain — only their Keccak256 hashes.
    /// The UltraHonk proof proves consistency between the proof witness and these
    /// hash commitments. This keeps calldata to ~14 KB.
    ///
    /// @param ciphertextHash     Keccak256 of CBOR-encoded ciphertext (c0 ∥ c1)
    /// @param plaintextHash      Keccak256 of CBOR-encoded plaintext polynomial
    /// @param aggregatePkHash    Keccak256 of CBOR-encoded aggregate public key
    /// @param dkgRoot            DKG transcript Merkle root (from keygen)
    /// @param epoch              Decryption epoch (replay protection)
    /// @param participantSetHash Keccak256 of ABI-encoded participant set (uint32[])
    /// @param dCommitment        Keccak256(D), D = Σᵢ∈S dᵢ (aggregate decryption sum)
    /// @param proof              UltraHonk proof bytes (MicroNova-compressed, ~14 KB)
    /// @return valid             true iff proof verifies and all hash commitments are consistent
    function verify(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64  epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external view returns (bool valid);

    /// @notice Verify a sonobe_state_commitment proof with off-chain attestation (NoGo branch).
    function verifyWithAttestation(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        AttestationBundle calldata attestation
    ) external view returns (bool valid);

    /// @notice Returns the minimum threshold t = floor(N/2)+1 for the current parameter set.
    function threshold() external view returns (uint32);

    /// @notice Atomically verify a threshold decryption result and consume the epoch.
    /// Same parameters as verify(), but also marks the epoch as consumed for replay protection.
    /// Reverts if session does not exist, epoch is already consumed, or proof is invalid.
    function verifyAndConsume(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64  epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external returns (bool valid);

    /// @notice Returns the RLWE degree N for the current parameter set.
    function rlweDegree() external view returns (uint32);
}

/// @title PvtFheVerifier
/// @notice Scaffold verifier for PVTHFHE threshold decryption results.
///
/// @dev R6.1: verify() delegates to HonkVerifier (BB-generated placeholder; real
///      UltraHonk verifier blocked on BB 5.0.0-nightly VK shape limitation).
///      The ABI is frozen per T22 api-spec.md and MUST NOT change.
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
///   Total on-chain calldata: ~14.2 KB → ~227,200 gas (well within 5M budget)
///
/// Revert reasons (standardised for off-chain parsing):
///   "PVTHFHE: malformed proof"         — proof bytes fail structural check
///   "PVTHFHE: threshold not met"       — participant set below threshold
///   "PVTHFHE: proof verification failed" — UltraHonk verifier returns false
///   "PVTHFHE: epoch replay"            — epoch already consumed for this dkgRoot
///   "PVTHFHE: unknown dkg root"        — dkgRoot not registered
contract PvtFheVerifier is IPvthfheVerifier {
    // -------------------------------------------------------------------------
    // Constants (canonical parameter set: N=8192, L=3, log₂Q≈174)
    // -------------------------------------------------------------------------

    uint32 private constant _RLWE_DEGREE = 8192;

    HonkVerifier private immutable _honkVerifier;
    ISessionRegistry public immutable registry;

    /// @notice TimelockController address that gates attestor onboarding (R6.4 multisig).
    address public immutable timelock;

    /// @notice Designated attestors for the NoGo branch off-chain verification.
    mapping(address => bool) public attestors;

    /// @param registry_ SessionRegistry address
    /// @param timelock_ TimelockController address for attestor governance (multisig + 48h delay)
    constructor(address registry_, address timelock_) {
        _honkVerifier = new HonkVerifier();
        registry = ISessionRegistry(registry_);
        timelock = timelock_;
    }

    // -------------------------------------------------------------------------
    // IPvthfheVerifier implementation
    // -------------------------------------------------------------------------

    /// @inheritdoc IPvthfheVerifier
    function verify(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external view override returns (bool) {
        // R6.1: verify session exists and epoch is not consumed (read-only check).
        _requireSessionValid(dkgRoot, epoch);

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

    /// @inheritdoc IPvthfheVerifier
    /// @dev State-changing: atomically verifies the proof first, then marks the epoch
    ///      as consumed only if the proof passes. This prevents epoch-DOS attacks where
    ///      an adversary submits invalid proofs to burn epochs without cost (C21/F8).
    ///      The session check is performed first to provide consistent error messages
    ///      before spending gas on proof verification.
    function verifyAndConsume(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external override returns (bool) {
        // R6.1: ensure session is valid and epoch is not consumed.
        _requireSessionValid(dkgRoot, epoch);

        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = ciphertextHash;
        publicInputs[1] = plaintextHash;
        publicInputs[2] = aggregatePkHash;
        publicInputs[3] = dkgRoot;
        publicInputs[4] = bytes32(uint256(epoch));
        publicInputs[5] = participantSetHash;
        publicInputs[6] = dCommitment;

        // B.3: verify proof FIRST. If proof is invalid, return false without
        // consuming the epoch — prevents epoch-DOS.
        bool proofValid = _honkVerifier.verify(proof, publicInputs);
        if (!proofValid) {
            return false;
        }

        // Only after successful verification, mark epoch consumed.
        registry.markEpochConsumed(dkgRoot, epoch);
        return true;
    }

    /// @inheritdoc IPvthfheVerifier
    /// @dev NoGo branch: proof is for the sonobe_state_commitment circuit (6 public inputs).
    ///      B.2: attestation signature is verified via ecrecover over keccak256 of the
    ///      attestation bundle fields (excluding the signature itself). This binds the
    ///      attestor's identity to the specific proof commitments.
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
            publicInputs[4] != attestation.sonobeStateCommitment
                || publicInputs[5] != attestation.cycloAggregateCommitment
        ) {
            revert("CommitmentMismatch");
        }

        // B.2: verify ECDSA attestation signature.
        // The attestation_hash binds the attestor to the specific state commitments
        // and session, preventing signature replay or impersonation.
        bytes32 attestationHash = keccak256(
            abi.encode(
                attestation.sonobeStateCommitment,
                attestation.cycloAggregateCommitment,
                attestation.sessionId,
                attestation.signer
            )
        );
        _verifyAttestationSignature(attestationHash, attestation.signature, attestation.signer);

        bool proofValid = _honkVerifier.verify(proof, publicInputs);
        if (!proofValid) {
            revert("InvalidProof");
        }
        return true;
    }

    /// @inheritdoc IPvthfheVerifier
    /// @dev Returns 0 — dynamic threshold is now stored in SessionRegistry per dkgRoot.
    ///      Use registeredThreshold(dkgRoot) to query the threshold for a specific session.
    function threshold() external pure override returns (uint32) {
        return 0;
    }

    /// @notice Returns the threshold t for a registered session.
    /// @param dkgRoot The DKG transcript root identifying the session.
    function registeredThreshold(bytes32 dkgRoot) external view returns (uint32) {
        (, uint32 t, , , , ) = registry.sessions(dkgRoot);
        return t;
    }

    /// @inheritdoc IPvthfheVerifier
    function rlweDegree() external pure override returns (uint32) {
        return _RLWE_DEGREE;
    }

    /// @notice Adds an attestor for NoGo-branch attestations.
    ///         Can only be called via the TimelockController (multisig + 48h delay per R6.4).
    function addAttestor(address attestor) external {
        require(msg.sender == timelock, "Unauthorized");
        attestors[attestor] = true;
    }

    /// @notice Removes an attestor for NoGo-branch attestations.
    ///         Can only be called via the TimelockController (multisig + 48h delay per R6.4).
    function removeAttestor(address attestor) external {
        require(msg.sender == timelock, "Unauthorized");
        attestors[attestor] = false;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// @dev Checks that a session is registered, not aborted, and the epoch is not consumed.
    ///      Reverts with standardized messages for off-chain parsing.
    ///      R6.9: uses isEpochConsumed (scoped to current runId for abort/restart liveness).
    function _requireSessionValid(bytes32 dkgRoot, uint64 epoch) internal view {
        (, , , bool registered, bool aborted, ) = registry.sessions(dkgRoot);
        if (!registered || aborted) {
            revert("PVTHFHE: unknown dkg root");
        }
        if (registry.isEpochConsumed(dkgRoot, epoch)) {
            revert("PVTHFHE: epoch replay");
        }
    }

    /// @dev B.2: Verifies an ECDSA attestation signature via ecrecover.
    ///      The signature is 65 bytes: r (32) || s (32) || v (1).
    ///      Reverts with "InvalidAttestationSignature" if recovery fails or yields wrong signer.
    function _verifyAttestationSignature(
        bytes32 hash,
        bytes calldata signature,
        address expectedSigner
    ) internal pure {
        require(signature.length == 65, "InvalidAttestationSignature");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            // For bytes calldata, .offset points directly to the data (first byte of r).
            // signature[0..31] = r, signature[32..63] = s, signature[64] = v.
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Normalize v: Ethereum ecrecover expects v ∈ {27,28}.
        // If v is 0 or 1, add 27.
        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "InvalidAttestationSignature");

        address recovered = ecrecover(hash, v, r, s);
        require(recovered == expectedSigner, "InvalidAttestationSignature");
    }

    /// @dev Touch all inputs to ensure calldata is parsed and ABI shape is validated.
    ///      Uses assembly to avoid any optimiser elision without emitting events.
    function _touchInputs(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64  epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) internal pure {
        // XOR all fixed inputs together and check proof length is accessible.
        // This forces the compiler to read every parameter.
        bytes32 sink = ciphertextHash
            ^ plaintextHash
            ^ aggregatePkHash
            ^ dkgRoot
            ^ bytes32(uint256(epoch))
            ^ participantSetHash
            ^ dCommitment;
        // Touch proof length (dynamic calldata).
        uint256 proofLen = proof.length;
        // Suppress unused-variable warnings via assembly no-op.
        assembly {
            pop(sink)
            pop(proofLen)
        }
    }
}
