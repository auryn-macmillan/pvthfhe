// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @title BaseVerifierTest
/// @notice Common fixtures for PVTHFHE on-chain verifier tests.
///         Populated with real proof data in T38 (Solidity verifier task).
abstract contract BaseVerifierTest is Test {
    /// @notice Sample 32-byte hash (placeholder until T38 generates real proofs)
    bytes32 internal constant SAMPLE_HASH = keccak256("pvthfhe-test-fixture");

    /// @notice Sample epoch
    uint64 internal constant SAMPLE_EPOCH = 1;

    /// @notice HonkVerifier (LOG_N=16) proof — 7776 bytes (243 fields × 32 bytes).
    bytes internal sampleProof;

    function setUp() public virtual {
        // HonkVerifier expects exactly calculateProofSize(16)*32 = 7776 bytes.
        sampleProof = new bytes(7776);
    }
}
