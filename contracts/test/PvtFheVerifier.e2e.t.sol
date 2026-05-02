// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/generated/HonkVerifier.sol";

contract PvtFheVerifierE2ETest is Test {
    HonkVerifier internal verifier;

    bytes internal honestProof;
    bytes internal tamperedProof;
    bytes32 internal expectedHash;

    function setUp() public {
        verifier = new HonkVerifier();

        honestProof = vm.readFileBinary("test/goldens/honest.proof");
        tamperedProof = vm.readFileBinary("test/goldens/tampered.proof");

        expectedHash = keccak256(honestProof);
    }

    function test_honest_proof_verifies() public view {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = expectedHash;
        bool result = verifier.verify(honestProof, publicInputs);
        assertTrue(result, "honest proof must verify");
    }

    function test_tampered_proof_reverts() public view {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = expectedHash;
        bool result = verifier.verify(tamperedProof, publicInputs);
        assertFalse(result, "tampered proof must not verify");
    }

    function test_gas_under_5m() public view {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = expectedHash;
        uint256 gasBefore = gasleft();
        verifier.verify(honestProof, publicInputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertLt(gasUsed, 5_000_000, "gas must be under 5M");
    }
}
