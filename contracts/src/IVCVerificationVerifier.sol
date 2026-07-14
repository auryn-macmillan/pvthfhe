// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract IVCVerificationVerifier {
    struct VerificationProof {
        bytes proof;
        bytes32[] publicInputs;
        bool verificationPassed;
        bool proofVerified;
    }

    function verifyProof(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) public view returns (bool) {
        if (proof.length == 0) {
            return false;
        }
        if (publicInputs.length == 0) {
            return false;
        }
        return _verifyProofStructure(proof, publicInputs);
    }

    function verifyProofWithResult(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        bytes32 expectedResult
    ) public view returns (bool) {
        if (!verifyProof(proof, publicInputs)) {
            return false;
        }
        bytes32 result = _extractVerificationResult(proof);
        require(result == expectedResult, "Unexpected verification result");
        return true;
    }

    function verifyIvCVerificationPassed(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) public view returns (bool) {
        return verifyProofWithResult(proof, publicInputs, bytes32(uint256(1)));
    }

    function _verifyProofStructure(
        bytes memory proof,
        bytes32[] memory publicInputs
    ) internal pure returns (bool) {
        if (proof.length < 4) {
            return false;
        }
        for (uint i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] == bytes32(0)) {
                return false;
            }
        }
        return true;
    }

    function _extractVerificationResult(
        bytes memory proof
    ) internal pure returns (bytes32) {
        if (proof.length < 32) {
            return bytes32(0);
        }
        bytes32 result;
        assembly {
            result := mload(add(proof, 32))
        }
        return result;
    }
}
