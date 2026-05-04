// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

contract RealVerifierTest is P3RealVerifierBase {

    // -------------------------------------------------------------------------
    // 1. Honest proof verifies
    // -------------------------------------------------------------------------

    /// @notice An honest P2 final proof with correct public inputs MUST return true.
    function test_honest_proof_verifies() public view {
        bool ok = verifier.verify(validProof, validPublicInputs);
        assertTrue(ok, "honest proof must verify");
    }

    // -------------------------------------------------------------------------
    // 2. Tampered proof rejected
    // -------------------------------------------------------------------------

    /// @notice A single-byte tamper to the proof payload MUST return false (not true).
    function test_tampered_proof_rejects() public view {
        bytes memory tampered = _copyAndFlipByte(validProof, 1);
        bool ok = verifier.verify(tampered, validPublicInputs);
        assertFalse(ok, "tampered proof must not verify");
    }

    // -------------------------------------------------------------------------
    // 3. Wrong public inputs rejected
    // -------------------------------------------------------------------------

    /// @notice Submitting proof against wrong publicInputs MUST return false.
    function test_wrong_public_inputs_rejects() public view {
        bytes memory wrongPi = _buildPublicInputs(
            keccak256("wrong_ciphertext"),
            keccak256("plaintext"),
            keccak256("agg_pk"),
            keccak256("dkg_root"),
            uint64(1),
            keccak256("participant_set"),
            keccak256("d_commitment")
        );
        bool ok = verifier.verify(validProof, wrongPi);
        assertFalse(ok, "proof against wrong publicInputs must not verify");
    }

    // -------------------------------------------------------------------------
    // 4. Gas within budget
    // -------------------------------------------------------------------------

    /// @notice Gas consumed by verify() MUST be ≤5,000,000.
    function test_gas_within_budget() public view {
        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(validProof, validPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertTrue(ok, "honest proof must verify before measuring gas");
        assertLe(gasUsed, 5_000_000, "gas exceeds 5M budget");
    }

    // -------------------------------------------------------------------------
    // 5. ProofRejected event on rejection
    // -------------------------------------------------------------------------

    /// @notice Router MUST emit ProofRejected when the verifier rejects a proof.
    function test_blame_event_on_rejection() public {
        bytes memory badProof = _copyAndFlipByte(validProof, 1);

        vm.expectEmit(true, true, false, true, address(router));
        emit P3ProofRouter.ProofRejected(
            keccak256(validPublicInputs),
            keccak256(badProof),
            3
        );

        router.submitProof(badProof, validPublicInputs);
    }

    // -------------------------------------------------------------------------
    // 6. Determinism across resubmissions
    // -------------------------------------------------------------------------

    /// @notice Calling verify() twice with identical inputs MUST return the same result.
    function test_determinism_across_resubmissions() public view {
        bool r1 = verifier.verify(validProof, validPublicInputs);
        bool r2 = verifier.verify(validProof, validPublicInputs);
        assertEq(r1, r2, "verify must be deterministic");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _copyAndFlipByte(bytes memory src, uint256 idx) internal pure returns (bytes memory dst) {
        dst = _copyBytes(src);
        dst[idx] = dst[idx] ^ 0xff;
    }
}
