// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SessionRegistry.sol";

/// @title SessionRegistryAccessTest
/// @notice R6.3 tests: AccessControl on SessionRegistry with roles
///         SESSION_CREATOR and VERIFIER contract gating.
///
/// Three role-gate categories:
///   1. registerSession + abortSession → SESSION_CREATOR_ROLE
///   2. markEpochConsumed → only the registered VERIFIER contract
///   3. verifySession → view-only, no access control needed
contract SessionRegistryAccessTest is Test {
    SessionRegistry internal registry;

    bytes32 internal constant DKG_ROOT = keccak256("access-test-dkg");
    bytes32 internal constant ROSTER_HASH = keccak256("access-test-roster");

    address internal constant SESSION_CREATOR = address(0xCAFE0001);
    address internal constant RANDOM_CALLER = address(0xBEEF0002);
    address internal constant VERIFIER_ADDR = address(0xDA000003);

    // Role identifiers - must match what SessionRegistry defines.
    bytes32 internal constant SESSION_CREATOR_ROLE = keccak256("SESSION_CREATOR_ROLE");
    bytes32 internal constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    function setUp() public {
        registry = new SessionRegistry();
        // Grant roles from the deployer (DEFAULT_ADMIN_ROLE) to the test actors.
        registry.grantRole(SESSION_CREATOR_ROLE, SESSION_CREATOR);
        registry.grantRole(VERIFIER_ROLE, VERIFIER_ADDR);
    }

    // -------------------------------------------------------------------------
    // 1. registerSession: unauthorized reverts, authorized succeeds
    // -------------------------------------------------------------------------

    /// @notice RED: registerSession reverts for caller without SESSION_CREATOR_ROLE.
    function test_registerSession_reverts_unless_creator() public {
        vm.prank(RANDOM_CALLER);
        vm.expectRevert();
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);
    }

    /// @notice RED: registerSession succeeds for caller with SESSION_CREATOR_ROLE.
    function test_registerSession_succeeds_for_creator() public {
        vm.startPrank(SESSION_CREATOR);
        // Expect success - no revert.
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);
        vm.stopPrank();

        (, , , bool registered, , ) = registry.sessions(DKG_ROOT);
        assertTrue(registered, "session must be registered");
    }

    // -------------------------------------------------------------------------
    // 2. abortSession: unauthorized reverts, authorized succeeds
    // -------------------------------------------------------------------------

    /// @notice RED: abortSession reverts for caller without SESSION_CREATOR_ROLE.
    function test_abortSession_reverts_unless_creator() public {
        // First, a session must exist - SESSION_CREATOR creates one.
        vm.prank(SESSION_CREATOR);
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);

        // Now a random caller tries to abort → must revert.
        vm.prank(RANDOM_CALLER);
        vm.expectRevert();
        registry.abortSession(DKG_ROOT);
    }

    /// @notice RED: abortSession succeeds for SESSION_CREATOR.
    function test_abortSession_succeeds_for_creator() public {
        vm.startPrank(SESSION_CREATOR);
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);
        registry.abortSession(DKG_ROOT);
        vm.stopPrank();

        (, , , , bool aborted, ) = registry.sessions(DKG_ROOT);
        assertTrue(aborted, "session must be aborted");
    }

    // -------------------------------------------------------------------------
    // 3. markEpochConsumed: only VERIFIER contract (or address with VERIFIER_ROLE)
    // -------------------------------------------------------------------------

    /// @notice RED: markEpochConsumed reverts for caller without VERIFIER_ROLE.
    function test_markEpochConsumed_reverts_unless_verifier() public {
        // SESSION_CREATOR registers a session.
        vm.prank(SESSION_CREATOR);
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);

        // A random caller tries to mark epoch consumed → must revert.
        vm.prank(RANDOM_CALLER);
        vm.expectRevert();
        registry.markEpochConsumed(DKG_ROOT, bytes32(uint256(1)), 1);
    }

    /// @notice RED: markEpochConsumed succeeds for VERIFIER address.
    function test_markEpochConsumed_succeeds_for_verifier() public {
        vm.prank(SESSION_CREATOR);
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);

        vm.prank(VERIFIER_ADDR);
        registry.markEpochConsumed(DKG_ROOT, bytes32(uint256(1)), 1);

        assertTrue(registry.isEpochConsumed(DKG_ROOT, bytes32(uint256(1)), 1), "epoch must be consumed");
    }

    // -------------------------------------------------------------------------
    // 4. verifySession: view-only, no access control - should still work for anyone
    // -------------------------------------------------------------------------

    /// @notice verifySession is a view function - even random callers can call it.
    function test_verifySession_accessible_to_anyone() public {
        vm.prank(SESSION_CREATOR);
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);

        vm.prank(RANDOM_CALLER);
        // Should not revert - view-only operation.
        registry.verifySession(DKG_ROOT, 1, ROSTER_HASH);
    }

    // -------------------------------------------------------------------------
    // 5. Role admin can grant/revoke roles
    // -------------------------------------------------------------------------

    /// @notice Only DEFAULT_ADMIN_ROLE can grant roles; random caller cannot.
    function test_only_admin_can_grant_role() public {
        // Random caller tries to grant SESSION_CREATOR_ROLE to someone else.
        vm.prank(RANDOM_CALLER);
        vm.expectRevert();
        registry.grantRole(SESSION_CREATOR_ROLE, address(0xB0B));
    }

    /// @notice Admin can revoke a role.
    function test_admin_can_revoke_role() public {
        // We are the deployer (= DEFAULT_ADMIN_ROLE).
        bytes32 roleToRevoke = SESSION_CREATOR_ROLE;
        // Verify the role is currently granted to SESSION_CREATOR.
        assertTrue(registry.hasRole(roleToRevoke, SESSION_CREATOR), "role must be granted");

        registry.revokeRole(roleToRevoke, SESSION_CREATOR);
        assertFalse(registry.hasRole(roleToRevoke, SESSION_CREATOR), "role must be revoked");
    }
}
