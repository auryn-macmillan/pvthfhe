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
    }

    // -------------------------------------------------------------------------
    // registerSession — happy path
    // -------------------------------------------------------------------------

    /// @notice Valid registration (t > n/2) emits SessionRegistered event.
    function test_registerSession_emitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit SessionRegistry.SessionRegistered(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
    }

    /// @notice After registration, isRegistered returns true.
    function test_registerSession_setsRegistered() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        (, , , bool registered) = reg.sessions(DKG_ROOT_A);
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

    /// @notice markEpochConsumed emits EpochConsumed.
    function test_markEpochConsumed_emitsEvent() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        vm.expectEmit(true, false, false, true);
        emit SessionRegistry.EpochConsumed(DKG_ROOT_A, 1);
        reg.markEpochConsumed(DKG_ROOT_A, 1);
    }

    /// @notice After markEpochConsumed, consumed mapping is true.
    function test_markEpochConsumed_setsConsumed() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT_A, 1);
        assertTrue(reg.consumed(DKG_ROOT_A, 1));
    }

    // -------------------------------------------------------------------------
    // RED: Epoch replay
    // -------------------------------------------------------------------------

    /// @notice markEpochConsumed twice on the same epoch must revert EpochAlreadyConsumed.
    function test_rejectEpochReplay() public {
        reg.registerSession(DKG_ROOT_A, 10, 6, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT_A, 42);
        vm.expectRevert(abi.encodeWithSelector(SessionRegistry.EpochAlreadyConsumed.selector, DKG_ROOT_A, uint64(42)));
        reg.markEpochConsumed(DKG_ROOT_A, 42);
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
        reg.markEpochConsumed(DKG_ROOT_A, 1);
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
        reg.markEpochConsumed(DKG_ROOT_A, 7);
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
        reg.markEpochConsumed(DKG_ROOT_A, 1);
        // Session B, same epoch 1 → should NOT revert
        reg.verifySession(DKG_ROOT_B, 1, ROSTER_HASH);
    }
}
