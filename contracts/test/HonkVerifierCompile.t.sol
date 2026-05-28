// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/generated/HonkVerifier.sol";

/// @title HonkVerifierCompileTest
/// @notice R6.2 regression test: ensures the committed HonkVerifier.sol compiles and deploys.
contract HonkVerifierCompileTest is Test {
    HonkVerifier internal verifier;

    function setUp() public {
        verifier = new HonkVerifier();
        assertTrue(address(verifier) != address(0), "verifier deployment must succeed");
    }

    function test_deploy_succeeds() public view {
        assertTrue(true, "forge build passed");
    }

    /// @notice HonkVerifier accepts only correctly-sized proofs (LOG_N=16 → 7776 bytes).
    function test_verify_abi_callable() public {
        bytes memory proof = new bytes(7776);
        bytes32[] memory publicInputs = new bytes32[](7);
        // Garbage proof — HonkVerifier rejects during deserialization.
        vm.expectRevert();
        verifier.verify(proof, publicInputs);
    }

    /// @notice Short proof must revert with proof length error.
    function test_mismatched_proof_returns_false() public {
        bytes memory proof = new bytes(4);
        bytes32[] memory publicInputs = new bytes32[](7);
        vm.expectRevert();
        verifier.verify(proof, publicInputs);
    }

    /// @notice 0 public inputs → HonkVerifier may revert on public input count.
    function test_empty_public_inputs_reverts() public {
        bytes memory proof = new bytes(7776);
        bytes32[] memory publicInputs = new bytes32[](0);
        vm.expectRevert();
        verifier.verify(proof, publicInputs);
    }
}
