// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

contract RealVerifierAdversarial is P3RealVerifierBase {

    // =========================================================================
    // Adversarial test 1: empty proof bytes (length < 65) → returns false
    // =========================================================================

    /// @notice A zero-length proof must be rejected.
    function test_adv_empty_proof_rejected() public view {
        bytes memory emptyProof = new bytes(0);
        bool ok = verifier.verify(emptyProof, validPublicInputs);
        assertFalse(ok, "empty proof must be rejected");
    }

    /// @notice A non-matching proof must be rejected.
    function test_adv_non_matching_proof_rejected() public view {
        bytes memory wrongProof = abi.encodePacked("proof-not-bound-to-hash");
        bool ok = verifier.verify(wrongProof, validPublicInputs);
        assertFalse(ok, "wrong proof must be rejected");
    }

    // =========================================================================
    // Adversarial test 3: wrong public input length → returns false
    // =========================================================================

    /// @notice 199-byte publicInputs must be rejected.
    function test_adv_wrong_pubinputs_length_rejected() public view {
        bytes memory shortPi = new bytes(199);
        bool ok = verifier.verify(validProof, shortPi);
        assertFalse(ok, "199-byte publicInputs must be rejected");
    }

    // =========================================================================
    // Adversarial test 4: 201-byte publicInputs → false
    // =========================================================================

    /// @notice 201-byte publicInputs must also be rejected.
    function test_adv_too_long_pubinputs_rejected() public view {
        bytes memory longPi = new bytes(201);
        bool ok = verifier.verify(validProof, longPi);
        assertFalse(ok, "201-byte publicInputs must be rejected");
    }

    // =========================================================================
    // Adversarial test 5: replay is deterministic
    // =========================================================================

    function test_adv_replay_deterministic() public view {
        bool r1 = verifier.verify(validProof, validPublicInputs);
        bool r2 = verifier.verify(validProof, validPublicInputs);
        assertTrue(r1, "first call must succeed");
        assertEq(r1, r2, "replay must return same result (deterministic)");
    }

    // =========================================================================
    // Adversarial test 6: gas griefing — large proof → returns false, ≤5M gas
    // =========================================================================

    /// @notice Oversized proof of garbage must return false without excessive gas.
    function test_adv_gas_griefing_large_proof() public view {
        bytes memory hugeProof = new bytes(14_336); // 14 KB
        for (uint256 i = 0; i < hugeProof.length; i++) {
            hugeProof[i] = bytes1(uint8(i & 0xff) | 0x01);
        }
        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(hugeProof, validPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertFalse(ok, "garbage 14KB proof must be rejected");
        assertLe(gasUsed, 5_000_000, "gas must not exceed 5M");
    }

    // =========================================================================
    // Adversarial test 7: MEV cross-input — valid proof for A used against B
    // =========================================================================

    /// @notice Proof valid for publicInputs_A must not verify against publicInputs_B.
    function test_adv_cross_input_reuse_rejected() public view {
        // Build a second, different public-inputs blob
        bytes memory piB = _buildPublicInputs(
            keccak256("different_cipher"),
            keccak256("different_plain"),
            keccak256("agg_pk"),
            keccak256("dkg"),
            uint64(43),
            keccak256("participants"),
            keccak256("d_commit")
        );
        // validProof was generated for validPublicInputs, not piB
        bool ok = verifier.verify(validProof, piB);
        assertFalse(ok, "proof for A must not verify against B");
    }

    // =========================================================================
    // Adversarial test 8: tampered proof byte
    // =========================================================================

    /// @notice Single-byte tamper to the proof must cause rejection.
    function test_adv_tampered_r_rejected() public view {
        bytes memory tampered = _copyBytes(validProof);
        tampered[0] = tampered[0] ^ 0xff;
        bool ok = verifier.verify(tampered, validPublicInputs);
        assertFalse(ok, "tampered proof must be rejected");
    }

    // =========================================================================
    // Bonus test 9: router emits ProofRejected when real verifier returns false
    // =========================================================================

    /// @notice When the real verifier rejects, the router MUST emit ProofRejected.
    function test_adv_router_emits_proof_rejected() public {
        bytes memory badProof = _copyBytes(validProof);
        badProof[0] ^= 0xff; // corrupt r

        vm.expectEmit(true, true, false, true, address(router));
        emit P3ProofRouter.ProofRejected(
            keccak256(validPublicInputs),
            keccak256(badProof),
            3
        );
        router.submitProof(badProof, validPublicInputs);
    }

}
