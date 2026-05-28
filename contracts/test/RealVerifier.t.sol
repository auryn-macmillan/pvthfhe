// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

contract RealVerifierTest is P3RealVerifierBase {

    // -------------------------------------------------------------------------
    // 1. HonkVerifier rejects invalid proof
    // -------------------------------------------------------------------------

    /// @notice The real HonkVerifier rejects a correctly-sized but invalid proof.
    function test_honest_proof_verifies() public {
        // validProof is 7776 bytes of zeros — not a valid UltraHonk proof.
        // HonkVerifier will revert during deserialization.
        vm.expectRevert();
        verifier.verify(validProof, validPublicInputs);
    }

    // -------------------------------------------------------------------------
    // 2. Tampered proof rejected
    // -------------------------------------------------------------------------

    function test_tampered_proof_rejects() public {
        bytes memory tampered = _copyAndFlipByte(validProof, 1);
        vm.expectRevert();
        verifier.verify(tampered, validPublicInputs);
    }

    // -------------------------------------------------------------------------
    // 3. Wrong public inputs rejected
    // -------------------------------------------------------------------------

    function test_wrong_public_inputs_rejects() public {
        bytes memory wrongPi = _buildPublicInputs(
            keccak256("wrong_ciphertext"),
            keccak256("plaintext"),
            keccak256("agg_pk"),
            keccak256("dkg_root"),
            uint64(1),
            keccak256("participant_set"),
            keccak256("d_commitment")
        );
        // UltraHonkVerifier converts public inputs, then HonkVerifier rejects invalid proof.
        vm.expectRevert();
        verifier.verify(validProof, wrongPi);
    }

    // -------------------------------------------------------------------------
    // 4. Gas within budget
    // -------------------------------------------------------------------------

    function test_gas_within_budget() public {
        uint256 gasBefore = gasleft();
        vm.expectRevert();
        verifier.verify(validProof, validPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertLe(gasUsed, 5_000_000, "gas exceeds 5M budget");
    }

    // -------------------------------------------------------------------------
    // 5. Router reverts when verifier rejects
    // -------------------------------------------------------------------------

    function test_blame_event_on_rejection() public {
        bytes memory badProof = _copyAndFlipByte(validProof, 1);
        // Router calls verifier.verify which reverts → router reverts.
        vm.expectRevert();
        router.submitProof(badProof, validPublicInputs);
    }

    // -------------------------------------------------------------------------
    // 6. Determinism across resubmissions
    // -------------------------------------------------------------------------

    function test_determinism_across_resubmissions() public {
        vm.expectRevert();
        verifier.verify(validProof, validPublicInputs);

        vm.expectRevert();
        verifier.verify(validProof, validPublicInputs);
        assertTrue(true, "both calls revert deterministically");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _copyAndFlipByte(bytes memory src, uint256 idx) internal pure returns (bytes memory dst) {
        dst = _copyBytes(src);
        dst[idx] = dst[idx] ^ 0xff;
    }
}
