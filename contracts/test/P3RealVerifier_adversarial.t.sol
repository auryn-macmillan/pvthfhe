// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

contract P3RealVerifierAdversarialTest is P3RealVerifierBase {
    function test_adv_wrong_ciphertext_hash_rejected() public view {
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

    function test_adv_mangled_proof_bytes_rejected() public view {
        bytes memory mangledProof = _copyBytes(validProof);
        mangledProof[0] = bytes1(uint8(mangledProof[0]) ^ 0x01);

        assertFalse(verifier.verify(mangledProof, validPublicInputs));
    }

    function test_adv_zero_length_proof_rejected() public view {
        assertFalse(verifier.verify(new bytes(0), validPublicInputs));
    }

    function test_adv_zero_length_public_inputs_rejected_without_revert() public view {
        assertFalse(verifier.verify(validProof, new bytes(0)));
    }

    function test_adv_router_emits_proof_rejected() public {
        bytes memory mangledProof = _copyBytes(validProof);
        mangledProof[1] = bytes1(uint8(mangledProof[1]) ^ 0x01);

        vm.expectEmit(true, true, false, true, address(router));
        emit P3ProofRouter.ProofRejected(keccak256(validPublicInputs), keccak256(mangledProof), 3);

        router.submitProof(mangledProof, validPublicInputs);
    }
}
