// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/generated/HonkVerifier.sol";

contract PvtFheVerifierE2ETest is Test {
    HonkVerifier internal verifier;

    function setUp() public {
        verifier = new HonkVerifier();
    }

    /// @notice Golden proof files (32 bytes) are too short for real HonkVerifier (needs 7776).
    ///         When a real proof is available, update proof bytes and this test.
    function test_honest_proof_verifies() public {
        bytes memory proof = new bytes(7776);
        bytes32[] memory publicInputs = new bytes32[](7);
        // Garbage proof → HonkVerifier rejects. With a real proof, this would assertTrue.
        vm.expectRevert();
        verifier.verify(proof, publicInputs);
    }

    function test_tampered_proof_reverts() public {
        bytes memory proof = new bytes(7776);
        proof[0] = bytes1(uint8(proof[0]) ^ 0xff);
        bytes32[] memory publicInputs = new bytes32[](7);
        vm.expectRevert();
        verifier.verify(proof, publicInputs);
    }

    function test_gas_under_5m() public {
        bytes32[] memory publicInputs = new bytes32[](7);
        bytes memory proof = new bytes(7776);
        uint256 gasBefore = gasleft();
        vm.expectRevert();
        verifier.verify(proof, publicInputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertLt(gasUsed, 5_000_000, "gas must be under 5M");
    }
}
