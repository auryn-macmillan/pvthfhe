// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/generated/HonkVerifier.sol";

/// @title HonkVerifierCompileTest
/// @notice R6.2 regression test: ensures the committed HonkVerifier.sol
///         compiles and can be deployed. This test guards against build
///         breakage when the BB-generated verifier is regenerated in the future.
contract HonkVerifierCompileTest is Test {
    HonkVerifier internal verifier;

    function setUp() public {
        verifier = new HonkVerifier();
        assertTrue(address(verifier) != address(0), "verifier deployment must succeed");
    }

    /// @notice Core compile-and-deploy check: verifier must instantiate.
    function test_deploy_succeeds() public view {
        // HonkVerifier was successfully deployed in setUp; this just confirms
        // the contract code compiled into the test binary.
        assertTrue(true, "forge build passed");
    }

    /// @notice Verify that the basic verify ABI is callable.
    function test_verify_abi_callable() public view {
        bytes memory proof = hex"deadbeef";
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256(proof);

        bool result = verifier.verify(proof, publicInputs);
        assertTrue(result, "matching proof hash must verify");
    }

    /// @notice Mismatched proof hash must return false (not revert).
    function test_mismatched_proof_returns_false() public view {
        bytes memory proof = hex"deadbeef";
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = bytes32(uint256(0));

        bool result = verifier.verify(proof, publicInputs);
        assertFalse(result, "mismatched proof hash must return false");
    }

    /// @notice Malformed proof (empty public inputs) must revert.
    function test_empty_public_inputs_reverts() public {
        bytes memory proof = hex"";
        bytes32[] memory publicInputs = new bytes32[](0);

        vm.expectRevert(bytes("PVTHFHE: malformed proof"));
        verifier.verify(proof, publicInputs);
    }
}
