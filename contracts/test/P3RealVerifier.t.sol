// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

contract P3RealVerifierHappyPathTest is P3RealVerifierBase {
    function test_valid_proof_accepted() public view {
        assertTrue(verifier.verify(validProof, validPublicInputs));
    }

    function test_wrong_proof_rejected() public view {
        bytes memory wrongProof = abi.encodePacked("pvthfhe-invalid-proof");
        assertFalse(verifier.verify(wrongProof, validPublicInputs));
    }

    function test_wrong_public_inputs_rejected() public view {
        bytes memory wrongPublicInputs = _buildPublicInputs(
            keccak256("wrong-ciphertext-hash"),
            keccak256("plaintext"),
            keccak256("aggregate_pk"),
            keccak256("dkg_root"),
            uint64(1),
            keccak256("participant_set"),
            keccak256("d_commitment")
        );

        assertFalse(verifier.verify(validProof, wrongPublicInputs));
    }
}
