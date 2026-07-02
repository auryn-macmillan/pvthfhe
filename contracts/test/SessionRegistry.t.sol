// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SessionRegistry.sol";

/// @title SessionRegistryTest
/// @notice Tests for SessionRegistry: t>n/2 enforcement, replay protection.
contract SessionRegistryTest is Test {
    SessionRegistry internal reg;

    bytes32 internal constant DKG_ROOT_A = keccak256("dkgRootA");
    bytes32 internal constant DKG_ROOT_B = keccak256("dkgRootB");
    bytes32 internal constant ROSTER_HASH = keccak256("roster");

    function setUp() public {
        reg = new SessionRegistry();
        // Grant both SESSION_CREATOR and VERIFIER roles to this test contract.
        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(this));
    }

    // -------------------------------------------------------------------------
    // registerSession — happy path
    // -------------------------------------------------------------------------

    /// @notice Valid registration (t > n/2) emits SessionRegistered event with runId=0.
    function test_registerSession_emitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit SessionRegistry.SessionRegistered(DKG_ROOT_A, 10, 6, ROSTER_HASH, 0);
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
    }

    /// @notice After registration, isRegistered returns true.
    function test_registerSession_setsRegistered() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        (,,, bool registered,,) = reg.sessions(DKG_ROOT_A);
        assertTrue(registered);
    }

    // -------------------------------------------------------------------------
    // RED: t > n/2 enforcement
    // -------------------------------------------------------------------------

    /// @notice t == n/2 must revert WeakThreshold.
    function test_rejectWeakThreshold_equal() public {
        // n=10, t=5 → 2*5 == 10, NOT > n; must revert
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.WeakThreshold.selector, uint32(5), uint32(10)));
        reg.registerSession(DKG_ROOT_A, 10, 5, ROSTER_HASH);
    }

    /// @notice t < n/2 must revert WeakThreshold.
    function test_rejectWeakThreshold() public {
        // n=10, t=4 → weak
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.WeakThreshold.selector, uint32(4), uint32(10)));
        reg.registerSession(DKG_ROOT_A, 10, 4, ROSTER_HASH);
    }

    // -------------------------------------------------------------------------
    // RED: Double-register
    // -------------------------------------------------------------------------

    /// @notice Double registerSession on same dkgRoot must revert AlreadyRegistered.
    function test_rejectDoubleRegister() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.AlreadyRegistered.selector, DKG_ROOT_A));
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
    }

    // -------------------------------------------------------------------------
    // markEpochConsumed — happy path
    // -------------------------------------------------------------------------

    /// @notice markEpochConsumed emits EpochConsumed with runId.
    function test_markEpochConsumed_emitsEvent() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        vm.expectEmit(true, false, false, true);
        emit SessionRegistry.EpochConsumed(DKG_ROOT_A, 1, 0);
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 1);
    }

    /// @notice After markEpochConsumed, isEpochConsumed returns true (R6.9: scoped to current runId).
    function test_markEpochConsumed_setsConsumed() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 1);
        assertTrue(reg.isEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 1));
    }

    // -------------------------------------------------------------------------
    // RED: Epoch replay
    // -------------------------------------------------------------------------

    /// @notice markEpochConsumed twice on the same epoch must revert EpochAlreadyConsumed.
    function test_rejectEpochReplay() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 42);
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.EpochAlreadyConsumed.selector, DKG_ROOT_A, uint64(42)));
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 42);
    }

    // -------------------------------------------------------------------------
    // verifySession — happy path
    // -------------------------------------------------------------------------

    /// @notice verifySession succeeds when session is registered and epoch not consumed.
    function test_verifySession_succeeds() public view {
        // Registered in setUp? No — need to set up in test.
        // We call it on a fresh contract via a prank trick — instead, let's do a stateful test.
    }

    function test_verifySession_succeedsAfterRegister() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        // Should not revert
        reg.verifySession(DKG_ROOT_A, 99, ROSTER_HASH);
    }

    // -------------------------------------------------------------------------
    // RED: Unregistered session
    // -------------------------------------------------------------------------

    /// @notice verifySession on unregistered dkgRoot must revert SessionNotFound.
    function test_rejectUnregisteredSession() public {
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.SessionNotFound.selector, DKG_ROOT_A));
        reg.verifySession(DKG_ROOT_A, 1, ROSTER_HASH);
    }

    /// @notice markEpochConsumed on unregistered session must revert SessionNotFound.
    function test_markEpochConsumed_rejectsUnregistered() public {
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.SessionNotFound.selector, DKG_ROOT_A));
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 1);
    }

    // -------------------------------------------------------------------------
    // RED: Roster mismatch
    // -------------------------------------------------------------------------

    /// @notice verifySession with wrong rosterHash must revert RosterMismatch.
    function test_rejectRosterMismatch() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        bytes32 wrongRoster = keccak256("wrong");
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.RosterMismatch.selector, ROSTER_HASH, wrongRoster));
        reg.verifySession(DKG_ROOT_A, 1, wrongRoster);
    }

    // -------------------------------------------------------------------------
    // RED: Consumed epoch in verifySession
    // -------------------------------------------------------------------------

    /// @notice verifySession on a consumed epoch must revert EpochAlreadyConsumed.
    function test_verifySession_rejectsConsumedEpoch() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 7);
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.EpochAlreadyConsumed.selector, DKG_ROOT_A, uint64(7)));
        reg.verifySession(DKG_ROOT_A, 7, ROSTER_HASH);
    }

    // -------------------------------------------------------------------------
    // Cross-session replay: same epoch, different dkgRoot → OK
    // -------------------------------------------------------------------------

    /// @notice Consuming epoch N in session A does not affect session B (same epoch).
    function test_crossSessionReplay_independent() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.registerSession(DKG_ROOT_B, 10, 6, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 1);
        // Session B, same epoch 1 → should NOT revert
        reg.verifySession(DKG_ROOT_B, 1, ROSTER_HASH);
    }

    // =========================================================================
    // T11.7 LIVENESS TESTS — abortSession path
    // =========================================================================
    // HIGH liveness gap: hermine.rs derives dkgRoot deterministically from
    // (participant set, threshold) only. If DKG stalls and the same committee
    // retries, the same dkgRoot is produced → AlreadyRegistered revert →
    // permanent on-chain deadlock. abortSession unblocks restarts.

    /// @notice RED → GREEN: abortSession emits SessionAborted with runId.
    function test_liveness_abortSession_emitsEvent() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        vm.expectEmit(true, false, false, false);
        emit SessionRegistry.SessionAborted(DKG_ROOT_A, 0);
        reg.abortSession(DKG_ROOT_A);
    }

    /// @notice RED → GREEN: after abortSession, verifySession reverts SessionAbortedError.
    function test_liveness_abortSession_blocksVerify() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.abortSession(DKG_ROOT_A);
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.SessionAbortedError.selector, DKG_ROOT_A));
        reg.verifySession(DKG_ROOT_A, 1, ROSTER_HASH);
    }

    /// @notice RED → GREEN: after abortSession, markEpochConsumed reverts SessionAbortedError.
    function test_liveness_abortSession_blocksMarkEpoch() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.abortSession(DKG_ROOT_A);
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.SessionAbortedError.selector, DKG_ROOT_A));
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 1);
    }

    /// @notice RED → GREEN: abortSession on unregistered dkgRoot reverts SessionNotFound.
    function test_liveness_abortSession_rejectsUnregistered() public {
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.SessionNotFound.selector, DKG_ROOT_A));
        reg.abortSession(DKG_ROOT_A);
    }

    /// @notice RED → GREEN: double abortSession reverts SessionAbortedError.
    function test_liveness_abortSession_rejectsDoubleAbort() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.abortSession(DKG_ROOT_A);
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.SessionAbortedError.selector, DKG_ROOT_A));
        reg.abortSession(DKG_ROOT_A);
    }

    /// @notice RED → GREEN: the critical liveness fix — same committee can re-register after abort.
    /// Simulates hermine.rs deterministic dkgRoot: same participants+threshold → same dkgRoot.
    /// Without abortSession this would permanently deadlock via AlreadyRegistered.
    function test_liveness_reregisterAfterAbort_unblocksDKGRestart() public {
        // First DKG attempt
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        // DKG stalls off-chain — abort on-chain
        reg.abortSession(DKG_ROOT_A);
        // Same committee (same dkgRoot) registers again — must succeed
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        // New attempt is active
        (,,, bool registered, bool aborted,) = reg.sessions(DKG_ROOT_A);
        assertTrue(registered, "session must be registered");
        assertFalse(aborted, "re-registered session must not be aborted");
    }

    /// @notice RED → GREEN (R6.9): epochs consumed in aborted session ARE reusable after re-register
    ///         because consumption is scoped to runId. Old run's consumed flag is preserved
    ///         in _consumed[dkgRoot][epoch][oldRunId] but does NOT block the new run.
    function test_liveness_consumedEpochsReusableAfterReregister() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        // Consume epoch 99 under run 0
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 99);
        // Verify it was consumed under runId=0
        assertTrue(reg.consumed(DKG_ROOT_A, 99, 0), "epoch 99 consumed under runId=0");

        reg.abortSession(DKG_ROOT_A);
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);

        // R6.9: epoch 99 is NOT consumed under new runId=1
        assertFalse(reg.isEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 99), "epoch 99 must be reusable under runId=1");
        // But still consumed under old runId=0 (off-chain audit trail)
        assertTrue(reg.consumed(DKG_ROOT_A, 99, 0), "epoch 99 still consumed under runId=0");

        // New run can consume epoch 99 fresh
        reg.markEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 99);
        assertTrue(reg.isEpochConsumed(DKG_ROOT_A, bytes32(uint256(1)), 99), "epoch 99 consumed under runId=1");
    }

    // -------------------------------------------------------------------------
    // F.2 smudge-slot freshness
    // -------------------------------------------------------------------------

    function test_smudgeSlot_rejectsReuseForDifferentCiphertext() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        bytes32 firstCiphertext = keccak256("ciphertext-a");
        bytes32 secondCiphertext = keccak256("ciphertext-b");

        reg.recordSmudgeSlotUse(DKG_ROOT_A, bytes32(uint256(1)), 3, 7, firstCiphertext, 11);

        vm.expectRevert(
            abi.encodeWithSelector(SessionRegistry.SmudgeSlotAlreadyBound.selector, DKG_ROOT_A, uint32(3), uint32(7))
        );
        reg.recordSmudgeSlotUse(DKG_ROOT_A, bytes32(uint256(1)), 3, 7, secondCiphertext, 11);
    }

    function test_smudgeSlot_rejectsReuseForDifferentDecryptRound() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        bytes32 ciphertextHash = keccak256("ciphertext-a");

        reg.recordSmudgeSlotUse(DKG_ROOT_A, bytes32(uint256(1)), 3, 7, ciphertextHash, 11);

        vm.expectRevert(
            abi.encodeWithSelector(SessionRegistry.SmudgeSlotAlreadyBound.selector, DKG_ROOT_A, uint32(3), uint32(7))
        );
        reg.recordSmudgeSlotUse(DKG_ROOT_A, bytes32(uint256(1)), 3, 7, ciphertextHash, 12);
    }

    function test_smudgeSlot_allowsIdempotentSameTuple() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        bytes32 ciphertextHash = keccak256("ciphertext-a");

        reg.recordSmudgeSlotUse(DKG_ROOT_A, bytes32(uint256(1)), 3, 7, ciphertextHash, 11);
        reg.recordSmudgeSlotUse(DKG_ROOT_A, bytes32(uint256(1)), 3, 7, ciphertextHash, 11);

        (bool consumed, bytes32 storedCiphertextHash, uint64 storedDecryptRound) = reg.smudgeSlotUse(DKG_ROOT_A, 3, 7);
        assertTrue(consumed, "slot must be recorded");
        assertEq(storedCiphertextHash, ciphertextHash, "ciphertext hash must be stable");
        assertEq(storedDecryptRound, 11, "decrypt round must be stable");
    }

    function test_smudgeSlot_recordRequiresVerifierRole() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        address outsider = address(0xBEEF);

        vm.prank(outsider);
        vm.expectRevert();
        reg.recordSmudgeSlotUse(DKG_ROOT_A, bytes32(uint256(1)), 3, 7, keccak256("ciphertext-a"), 11);
    }
}
