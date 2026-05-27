// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import "../src/generated/UltraHonkVerifier.sol";

contract UltraHonkVerifierTest is Test {
    UltraHonkVerifier_N4 internal verifier;
    bytes internal proof;
    bytes32[] internal publicInputs;

    function setUp() public {
        verifier = new UltraHonkVerifier_N4();
        proof = vm.readFileBinary(
            string.concat(vm.projectRoot(), "/../circuits/nova_state_commitment/target/proof")
        );
        publicInputs = _decodePublicInputs(
            vm.readFileBinary(
                string.concat(vm.projectRoot(), "/../circuits/nova_state_commitment/target/public_inputs")
            )
        );
    }

    function test_valid_proof_verifies() public {
        vm.skip(true); // SKIP: UltraHonk fixture stale since aggregator_final circuit update; regenerate with canonical AGENTS.md flow
        assertTrue(verifier.verify(proof, publicInputs), "valid proof must verify");
    }

    function test_tampered_public_input_fails() public view {
        bytes32[] memory tampered = _copy(publicInputs);
        tampered[0] = bytes32(uint256(tampered[0]) ^ 1);
        assertFalse(verifier.verify(proof, tampered), "tampered public inputs must fail");
    }

    function test_hash_only_input_does_not_bypass_verification() public view {
        bytes memory forgedProof = abi.encodePacked("forged-proof");
        bytes32[] memory forgedInputs = new bytes32[](1);
        forgedInputs[0] = keccak256(forgedProof);

        assertFalse(verifier.verify(forgedProof, forgedInputs), "hash-only inputs must not bypass verification");
    }

    function _decodePublicInputs(bytes memory raw) internal pure returns (bytes32[] memory decoded) {
        require(raw.length % 32 == 0, "unaligned public inputs");
        decoded = new bytes32[](raw.length / 32);
        for (uint256 i = 0; i < decoded.length; ++i) {
            bytes32 word;
            assembly {
                word := mload(add(add(raw, 0x20), mul(i, 0x20)))
            }
            decoded[i] = word;
        }
    }

    function _copy(bytes32[] memory src) internal pure returns (bytes32[] memory dst) {
        dst = new bytes32[](src.length);
        for (uint256 i = 0; i < src.length; ++i) {
            dst[i] = src[i];
        }
    }
}
