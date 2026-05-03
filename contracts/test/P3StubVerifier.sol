// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IP3Verifier
/// @notice Frozen P3 on-chain verifier interface (D.D.1).
///         `proof`        — opaque backend envelope (≤14 KB)
///         `publicInputs` — exactly 200 bytes: 6×32-byte hashes + 8-byte epoch
interface IP3Verifier {
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        returns (bool);
}

/// @title P3StubVerifier
/// @notice Surrogate verifier that always reverts with "unimplemented".
///         This stub exists solely so RED tests can compile and then fail
///         at runtime — it MUST be replaced by the real UltraHonk verifier
///         in D.I.2 (green phase).
///
///         DO NOT modify HonkVerifier.sol. This stub is separate.
contract P3StubVerifier is IP3Verifier {
    function verify(bytes calldata, bytes calldata)
        external
        pure
        override
        returns (bool)
    {
        revert("unimplemented");
    }
}

/// @title P3ProofRouter
/// @notice Minimal non-view router that wraps IP3Verifier, routing failures
///         to a `ProofRejected` event.  Used by test_blame_event_on_rejection.
///         The router does NOT use try/catch so that a reverting stub also
///         causes the router call to revert, keeping all tests RED.
contract P3ProofRouter {
    IP3Verifier public immutable verifier;

    event ProofRejected(
        bytes32 indexed publicInputsHash,
        bytes32 indexed proofHash,
        uint8 reasonCode
    );

    constructor(address verifier_) {
        verifier = IP3Verifier(verifier_);
    }

    /// @notice Submit a proof for verification; emits ProofRejected on failure.
    ///         The stub reverts so this call also reverts, keeping the test RED.
    function submitProof(bytes calldata proof, bytes calldata publicInputs)
        external
    {
        bool ok = verifier.verify(proof, publicInputs);
        if (!ok) {
            emit ProofRejected(
                keccak256(publicInputs),
                keccak256(proof),
                3 // reasonCode 3 = verifier returned false
            );
        }
    }
}
