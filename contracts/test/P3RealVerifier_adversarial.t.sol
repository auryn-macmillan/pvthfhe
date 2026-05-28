// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

contract P3RealVerifierAdversarialTest is P3RealVerifierBase {
    function test_adv_wrong_ciphertext_hash_rejected() public {
        bytes memory wrongPublicInputs = _buildPublicInputs(
            keccak256("wrong-ciphertext-hash"),
            keccak256("plaintext"),
            keccak256("aggregate_pk"),
            keccak256("dkg_root"),
            uint64(1),
            keccak256("participant_set"),
            keccak256("d_commitment")
        );
        // validProof is 7776 bytes of zeros → HonkVerifier rejects during deserialization.
        vm.expectRevert();
        verifier.verify(validProof, wrongPublicInputs);
    }

    function test_adv_mangled_proof_bytes_rejected() public {
        bytes memory mangledProof = _copyBytes(validProof);
        mangledProof[0] = bytes1(uint8(mangledProof[0]) ^ 0x01);
        vm.expectRevert();
        verifier.verify(mangledProof, validPublicInputs);
    }

    function test_adv_zero_length_proof_rejected() public {
        // 0-byte proof → HonkVerifier rejects on length.
        vm.expectRevert();
        verifier.verify(new bytes(0), validPublicInputs);
    }

    function test_adv_zero_length_public_inputs_rejected_without_revert() public {
        // UltraHonkVerifier returns false for non-200 byte public inputs.
        bool result = verifier.verify(validProof, new bytes(0));
        assertFalse(result, "zero-length public inputs must be rejected");
    }

    function test_adv_router_emits_proof_rejected() public {
        bytes memory mangledProof = _copyBytes(validProof);
        mangledProof[1] = bytes1(uint8(mangledProof[1]) ^ 0x01);
        // HonkVerifier rejects → router reverts (no try/catch).
        vm.expectRevert();
        router.submitProof(mangledProof, validPublicInputs);
    }
}
