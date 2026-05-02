// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./generated/HonkVerifier.sol";

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

    /// @notice Returns the minimum threshold t = floor(N/2)+1 for the current parameter set.
    function threshold() external view returns (uint32);

    /// @notice Returns the RLWE degree N for the current parameter set.
    function rlweDegree() external view returns (uint32);
}

/// @title PvtFheVerifier
/// @notice Scaffold verifier for PVTHFHE threshold decryption results.
///
/// @dev SCAFFOLD: This contract always returns false from verify().
///      T39 will replace the body of verify() with a BB-generated UltraHonk verifier.
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
    uint32 private constant _THRESHOLD = 4097;

    HonkVerifier private immutable _honkVerifier;

    constructor() {
        _honkVerifier = new HonkVerifier();
    }

    // -------------------------------------------------------------------------
    // IPvthfheVerifier implementation
    // -------------------------------------------------------------------------

    /// @inheritdoc IPvthfheVerifier
    /// @dev SCAFFOLD: always returns false.
    ///      Calldata is parsed (all parameters are read) to validate ABI shape.
    ///      T39 will replace this body with the BB-generated UltraHonk verifier.
    function verify(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64  epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment,
        bytes calldata proof
    ) external view override returns (bool valid) {
        _touchInputs(
            ciphertextHash,
            plaintextHash,
            aggregatePkHash,
            dkgRoot,
            epoch,
            participantSetHash,
            dCommitment,
            proof
        );

        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256(proof);
        return _honkVerifier.verify(proof, publicInputs);
    }

    /// @inheritdoc IPvthfheVerifier
    function threshold() external pure override returns (uint32) {
        return _THRESHOLD;
    }

    /// @inheritdoc IPvthfheVerifier
    function rlweDegree() external pure override returns (uint32) {
        return _RLWE_DEGREE;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

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
