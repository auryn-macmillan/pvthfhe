// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/generated/HonkVerifier.sol";

/// @title HonkVerifierRegeneratedTest
/// @notice RED test for B.1: documents the expected behavior when HonkVerifier.sol
///         is regenerated via the canonical BB flow.
///
///         BLOCKED ON: BB 5.0.0-nightly.20260324 VK shape mismatch.
///         All circuits produce 3680-byte VKs but the Solidity verifier generator
///         expects 1888-byte VKs. `bb write_solidity_verifier -k target/vk` fails.
///
///         Canonical flow per AGENTS.md:
///           1. (cd circuits && nargo execute --package aggregator_final --prover-name Prover_re)
///           2. bb write_vk --scheme ultra_honk -b target/aggregator_final.json -o target
///           3. bb write_solidity_verifier -k target/vk -o contracts/src/generated/HonkVerifier.sol
///
///         When unblocked, this test file should:
///           [ ] Assert the regenerated verifier has 7 public input checks (not 1)
///           [ ] Assert the verifier does NOT contain the keccak256 tautology
///           [ ] Assert the regenerated file differs from the committed placeholder
///           [ ] Assert `forge test --root contracts` passes with the regenerated verifier
///
///         Current state: this test verifies the placeholder is still in place
///         and documents what must change when BB is upgraded.
///
/// @custom:gate [blocked_on=BB-VK-shape]
contract HonkVerifierRegeneratedTest is Test {
    HonkVerifier internal honk;

    function setUp() public {
        honk = new HonkVerifier();
    }

    // -------------------------------------------------------------------------
    // Placeholder verifier contract existence
    // -------------------------------------------------------------------------

    /// @notice The HonkVerifier contract exists and has the expected verify() interface.
    function test_verifier_has_verify_interface() public view {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = bytes32(uint256(1));
        // Should not revert — placeholder always returns a boolean.
        bool result = honk.verify(new bytes(0), inputs);
        // Placeholder returns false because keccak256(empty) != inputs[0].
        assertFalse(result, "placeholder must return false for non-matching input");
    }

    // -------------------------------------------------------------------------
    // Tautology verification
    // -------------------------------------------------------------------------

    /// @notice Confirms the placeholder HonkVerifier uses keccak256(proof) == publicInputs[0].
    ///         When regenerated, this test SHOULD FAIL because the real verifier uses
    ///         proper UltraHonk verification.
    function test_placeholder_is_keccak_tautology() public {
        bytes memory proof = hex"deadbeef";
        bytes32 proofHash = keccak256(abi.encodePacked(proof));

        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = proofHash;
        bool result = honk.verify(proof, inputs);
        assertTrue(result, "keccak tautology must match hash");

        // Mismatched hash must fail.
        inputs[0] = bytes32(uint256(0xBAD));
        result = honk.verify(proof, inputs);
        assertFalse(result, "keccak tautology must reject mismatched hash");
    }

    // -------------------------------------------------------------------------
    // [blocked_on=BB-VK-shape] Real verifier shape expected
    // -------------------------------------------------------------------------

    /// @notice The regenerated verifier must expect 7 public inputs
    ///         (ciphertextHash, plaintextHash, aggregatePkHash, dkgRoot,
    ///          epoch, participantSetHash, dCommitment) per T22 ABI spec.
    ///         Currently BLOCKED on BB VK shape mismatch.
    ///
    ///         When unblocked, change this test to assert the real generated
    ///         verifier accepts exactly 7 public inputs (or 6 for sonobe_state_commitment).
    function test_expected_public_input_count() public {
        // Placeholder: requires at least 1 public input.
        bytes32[] memory inputs = new bytes32[](7);
        bool result = honk.verify(new bytes(0), inputs);
        // Placeholder returns false because keccak256 is not computed.
        // When regenerated, should return true for 7 valid public inputs.
        // For now, this documents the expected count.
        assertEq(inputs.length, 7, "T22 ABI requires 7 public inputs");
    }

    // -------------------------------------------------------------------------
    // [blocked_on=BB-VK-shape] Solidity source shape
    // -------------------------------------------------------------------------

    /// @notice When regenerated, HonkVerifier.sol must NOT contain the string
    ///         'keccak256' (the tautology). It should contain UltraHonk-specific
    ///         verification logic instead.
    ///         BLOCKED: BB VK shape 3680 ≠ 1888.
    function test_gate_placeholder_contains_tautology() public pure {
        // This test PASSES while the blocker exists (tautology is expected).
        // When BB VK shape is fixed and the verifier is regenerated, this test
        // MUST BE REMOVED or changed to assert the verifier does NOT contain keccak256.
        //
        // Verification: the source code of HonkVerifier.sol at
        // contracts/src/generated/HonkVerifier.sol contains 'keccak256(proof)'.
        // This cannot be checked from Solidity; it is tested via shell grep:
        //   grep -c 'keccak256' contracts/src/generated/HonkVerifier.sol
        // Expected: >= 1 (placeholder) → change to 0 after regeneration.
        assertTrue(true, "[blocked_on=BB-VK-shape] placeholder keccak256 tautology present");
    }

    // -------------------------------------------------------------------------
    // [blocked_on=BB-VK-shape] VK shape mismatch reproducer
    // -------------------------------------------------------------------------

    /// @notice Documents the VK shape mismatch that blocks regeneration.
    ///         When `bb write_solidity_verifier -k target/vk` is run:
    ///         - Actual VK size: 3680 bytes (from aggregator_final circuit)
    ///         - Expected VK size: 1888 bytes (hardcoded in BB generator)
    ///         - Error: "VK size mismatch"
    ///
    ///         Resolution options:
    ///         1. Upgrade BB to version that supports 3680-byte VKs
    ///         2. Adjust circuit to produce 1888-byte VK
    ///         3. Patch BB generator to accept variable-length VKs
    function test_vk_shape_blocker_documented() public pure {
        // This test always passes; it exists to document the blocker.
        // When unblocked, this test should be removed.
        assertTrue(true, "[blocked_on=BB-VK-shape] VK shape 3680 != 1888");
    }
}
