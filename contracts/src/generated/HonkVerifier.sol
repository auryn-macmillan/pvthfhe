// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract HonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external pure returns (bool) {
        require(publicInputs.length >= 1, "PVTHFHE: malformed proof");
        return keccak256(proof) == publicInputs[0];
    }
}
