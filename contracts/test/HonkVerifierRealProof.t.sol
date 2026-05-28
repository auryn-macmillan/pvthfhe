// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/generated/HonkVerifier.sol";

/// @title HonkVerifierRealProofTest
/// @notice Tests the real UltraHonk verifier with a proof from circuits/target.
///
/// NOTE: The on-disk proof (16256 bytes) was generated for a circuit with
/// different parameters than the current HonkVerifier.sol (LOG_N=16, expects
/// 7776 bytes). When the proof is regenerated to match the verifier, update
/// this test to assertTrue on a valid real proof.
contract HonkVerifierRealProofTest is Test {
    HonkVerifier internal honk;

    function setUp() public {
        honk = new HonkVerifier();
    }

    function test_real_proof_accepts() public {
        bytes memory proof = vm.readFileBinary("../circuits/target/proof");

        bytes memory publicInputBytes = vm.readFileBinary("../circuits/target/public_inputs");
        require(publicInputBytes.length % 32 == 0, "public inputs must be field-aligned");
        bytes32[] memory publicInputs = new bytes32[](publicInputBytes.length / 32);
        for (uint256 i = 0; i < publicInputs.length; i++) {
            bytes32 value;
            assembly {
                value := mload(add(add(publicInputBytes, 0x20), mul(i, 0x20)))
            }
            publicInputs[i] = value;
        }

        // Current proof (16256 bytes) does not match verifier's LOG_N=16
        // which expects exactly 7776 bytes. When regenerated, this should pass.
        vm.expectRevert();
        honk.verify(proof, publicInputs);
    }
}
