// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title EpochConsumptionAtomicityTest
/// @notice RED test for B.3: verifyAndConsume() must verify the proof FIRST,
///         then mark the epoch consumed. Currently, markEpochConsumed is called
///         before proof verification — an invalid proof consumes the epoch
///         regardless, enabling a cheap epoch-DOS attack (C21 / F8).
///
///         This RED test is written BEFORE the green implementation.
///         Expected failures:
///           test_invalid_proof_does_not_consume_epoch — SHOULD FAIL (epoch consumed anyway)
///
///         After GREEN: reorder verifyAndConsume to verify proof first, then
///         mark consumed. Invalid proofs will NOT consume epochs.
contract EpochConsumptionAtomicityTest is Test {
    PvtFheVerifier internal verifier;
    SessionRegistry internal reg;

    bytes32 internal constant DKG_ROOT = keccak256("dkgRoot");
    bytes32 internal constant ROSTER_HASH = keccak256("roster");
    uint64 internal constant EPOCH = 42;

    /// @notice A proof that the HonkVerifier (tautology) will accept.
    ///         HonkVerifier.verify(proof, publicInputs) returns (keccak256(proof) == publicInputs[0]).
    bytes internal validProof;

    /// @notice A proof that the HonkVerifier will reject (flipped bytes).
    bytes internal invalidProof;

    function setUp() public {
        reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg), address(this));

        // Grant roles
        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(verifier));

        // Register a session
        reg.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);

        // Build a valid proof: keccak256(proof) == publicInputs[0] (HonkVerifier tautology).
        validProof = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            validProof[i] = bytes1(uint8(i));
        }

        // Build an invalid proof: flip one byte so hash doesn't match.
        invalidProof = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            invalidProof[i] = validProof[i] ^ 0xFF;
        }
    }

    // -------------------------------------------------------------------------
    // Helper: keccak256 of proof bytes (matching HonkVerifier's calldata hash)
    // -------------------------------------------------------------------------
    function proofHash(bytes memory p) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(p));
    }

    // -------------------------------------------------------------------------
    // RED: Invalid proof must NOT consume epoch
    // -------------------------------------------------------------------------

    /// @notice RED: verifyAndConsume with an invalid proof should return false
    ///         WITHOUT consuming the epoch. Currently, the epoch IS consumed
    ///         before verification — this test FAILS (epoch consumed even on
    ///         invalid proof), enabling epoch-DOS (C21/F8).
    function test_invalid_proof_does_not_consume_epoch() public {
        // Pre-condition: epoch is fresh
        assertFalse(reg.isEpochConsumed(DKG_ROOT, EPOCH), "pre: epoch must be fresh");

        // Submit an invalid proof: ciphertextHash does NOT match keccak256(proof).
        // The HonkVerifier tautology accepts iff keccak256(proof) == publicInputs[0].
        // By passing a MISMATCHED hash, we force the proof to fail.
        vm.recordLogs();
        bool result = verifier.verifyAndConsume(
            bytes32(uint256(0xDEAD)), // MISMATCHED — NOT equal to keccak256(invalidProof)
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            DKG_ROOT,
            EPOCH,
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            invalidProof
        );

        // Proof was invalid — result should be false.
        assertFalse(result, "invalid proof must not verify");

        // CRITICAL: epoch must NOT be consumed by an invalid proof.
        assertFalse(
            reg.isEpochConsumed(DKG_ROOT, EPOCH),
            "RED: invalid proof must NOT consume epoch (currently consumes anyway)"
        );
    }

    // -------------------------------------------------------------------------
    // Happy path: valid proof consumes epoch and succeeds
    // -------------------------------------------------------------------------

    /// @notice verifyAndConsume with valid proof succeeds and marks epoch consumed.
    function test_valid_proof_consumes_epoch_and_succeeds() public {
        bool result = verifier.verifyAndConsume(
            proofHash(validProof),   // ciphertextHash = keccak256(proof) for tautology
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            DKG_ROOT,
            EPOCH,
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            validProof
        );

        assertTrue(result, "valid proof must verify");
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch must be consumed");
    }

    // -------------------------------------------------------------------------
    // Atomicity: invalid proof does not block subsequent valid proof
    // -------------------------------------------------------------------------

    /// @notice After an invalid proof attempt, a subsequent valid proof should
    ///         still be able to consume the same epoch.
    function test_invalid_then_valid_still_consumes_epoch() public {
        // First: submit invalid proof (mismatched hash).
        verifier.verifyAndConsume(
            bytes32(uint256(0xDEAD)), // MISMATCHED hash → proof fails
            bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH, bytes32(uint256(5)), bytes32(uint256(6)), invalidProof
        );

        // Epoch must still be fresh after invalid attempt.
        assertFalse(
            reg.isEpochConsumed(DKG_ROOT, EPOCH),
            "epoch must NOT be consumed after invalid proof"
        );

        // Second: submit valid proof for the same epoch — must succeed.
        bool result = verifier.verifyAndConsume(
            proofHash(validProof),
            bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH, bytes32(uint256(5)), bytes32(uint256(6)), validProof
        );

        assertTrue(result, "valid proof must verify after invalid attempt");
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch must be consumed by valid proof");
    }

    // -------------------------------------------------------------------------
    // Replay protection: same epoch cannot be consumed twice with valid proofs
    // -------------------------------------------------------------------------

    /// @notice verifyAndConsume on already-consumed epoch must revert (replay protection).
    function test_replay_protection_still_works() public {
        // First consumption succeeds.
        bool result = verifier.verifyAndConsume(
            proofHash(validProof),
            bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH, bytes32(uint256(5)), bytes32(uint256(6)), validProof
        );
        assertTrue(result, "first consumption must succeed");
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch must be consumed");

        // Second attempt with same epoch must revert.
        vm.expectRevert(bytes("PVTHFHE: epoch replay"));
        verifier.verifyAndConsume(
            proofHash(validProof),
            bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH, bytes32(uint256(5)), bytes32(uint256(6)), validProof
        );
    }
}
