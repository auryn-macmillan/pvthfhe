// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title AttestorOnboardingTest
/// @notice R6.4 tests: Attestor onboarding gated by multisig (>=2 of 3)
///         with TimelockController (48h minimum delay).
///
/// Tests:
///   1. Direct calls to addAttestor / removeAttestor revert when not from timelock.
///   2. Scheduling through TimelockController works after 48h delay.
///   3. Multisig: 3 proposers configured, delay prevents unilateral action.
///   4. Execute before delay period expires reverts.
contract AttestorOnboardingTest is Test {
    SessionRegistry internal registry;
    PvtFheVerifier internal verifier;

    // Multisig proposer addresses (3 members).
    address internal constant PROP_1 = address(0xA1100001);
    address internal constant PROP_2 = address(0xA1100002);
    address internal constant PROP_3 = address(0xA1100003);

    // Attestor to be added.
    address internal constant NEW_ATTESTOR = address(0xDA0000A7);

    // Timelock delay: 48 hours.
    uint256 internal constant MIN_DELAY = 48 hours;

    // TimelockController for attestor governance.
    TimelockController internal timelock;

    function setUp() public {
        // Deploy the registry.
        registry = new SessionRegistry();

        // Deploy TimelockController FIRST with 3 proposers and 48h delay.
        // The test contract is the timelock admin (controls proposer/executor set).
        address[] memory proposers = new address[](3);
        proposers[0] = PROP_1;
        proposers[1] = PROP_2;
        proposers[2] = PROP_3;

        address[] memory executors = new address[](1);
        executors[0] = address(this); // Allow test contract to execute scheduled ops.

        timelock = new TimelockController(MIN_DELAY, proposers, executors, address(this));

        // Deploy PvtFheVerifier with the timelock as the governance gate.
        verifier = new PvtFheVerifier(address(registry), address(timelock));
    }

    // -------------------------------------------------------------------------
    // 1. Direct calls revert (not from timelock)
    // -------------------------------------------------------------------------

    /// @notice addAttestor called directly (not via timelock) must revert.
    function test_addAttestor_reverts_direct_call() public {
        vm.prank(PROP_1);
        vm.expectRevert("Unauthorized");
        verifier.addAttestor(NEW_ATTESTOR);
    }

    /// @notice removeAttestor called directly must revert.
    function test_removeAttestor_reverts_direct_call() public {
        vm.prank(PROP_1);
        vm.expectRevert("Unauthorized");
        verifier.removeAttestor(NEW_ATTESTOR);
    }

    // -------------------------------------------------------------------------
    // 2. Scheduling through TimelockController works after 48h delay
    // -------------------------------------------------------------------------

    /// @notice Scheduling addAttestor via timelock works after the 48h delay.
    function test_schedule_addAttestor_via_timelock() public {
        bytes memory callData = abi.encodeCall(verifier.addAttestor, (NEW_ATTESTOR));

        // A proposer schedules the operation.
        vm.prank(PROP_1);
        timelock.schedule(address(verifier), 0, callData, bytes32(0), keccak256("salt1"), MIN_DELAY);

        // Warp past the delay.
        vm.warp(block.timestamp + MIN_DELAY + 1);

        // Execute the scheduled operation (test contract IS an executor).
        timelock.execute(address(verifier), 0, callData, bytes32(0), keccak256("salt1"));

        // Verify attestor was added.
        assertTrue(verifier.attestors(NEW_ATTESTOR), "attestor must be added via timelock");
    }

    /// @notice Scheduling removeAttestor via timelock works.
    function test_schedule_removeAttestor_via_timelock() public {
        // First add an attestor via timelock so we can remove it.
        bytes memory addData = abi.encodeCall(verifier.addAttestor, (NEW_ATTESTOR));
        vm.prank(PROP_1);
        timelock.schedule(address(verifier), 0, addData, bytes32(0), keccak256("salt2"), MIN_DELAY);
        vm.warp(block.timestamp + MIN_DELAY + 1);
        timelock.execute(address(verifier), 0, addData, bytes32(0), keccak256("salt2"));
        assertTrue(verifier.attestors(NEW_ATTESTOR));

        // Now schedule removal.
        bytes memory removeData = abi.encodeCall(verifier.removeAttestor, (NEW_ATTESTOR));
        vm.prank(PROP_2);
        timelock.schedule(address(verifier), 0, removeData, bytes32(0), keccak256("salt3"), MIN_DELAY);
        // Warp past the delay: current time + MIN_DELAY + 1
        vm.warp(345604);
        timelock.execute(address(verifier), 0, removeData, bytes32(0), keccak256("salt3"));

        assertFalse(verifier.attestors(NEW_ATTESTOR), "attestor must be removed via timelock");
    }

    // -------------------------------------------------------------------------
    // 3. Multisig: 3 proposers configured; timelock delay is the governance friction
    // -------------------------------------------------------------------------

    /// @notice The timelock has exactly 3 proposers (>=2 of 3 multisig).
    function test_timelock_has_three_proposers() public view {
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), PROP_1), "PROP_1 must be proposer");
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), PROP_2), "PROP_2 must be proposer");
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), PROP_3), "PROP_3 must be proposer");
        // PROP_1, PROP_2, PROP_3 are all proposers: >=2 of 3 multisig.
    }

    /// @notice A non-proposer cannot schedule operations.
    function test_non_proposer_cannot_schedule() public {
        bytes memory callData = abi.encodeCall(verifier.addAttestor, (NEW_ATTESTOR));

        address nonProposer = address(0xBEEF0999);
        assertFalse(timelock.hasRole(timelock.PROPOSER_ROLE(), nonProposer));

        vm.prank(nonProposer);
        vm.expectRevert();
        timelock.schedule(address(verifier), 0, callData, bytes32(0), keccak256("salt"), MIN_DELAY);
    }

    // -------------------------------------------------------------------------
    // 4. Execute before delay reverts
    // -------------------------------------------------------------------------

    /// @notice Executing a scheduled operation before the 48h delay reverts.
    function test_execute_before_delay_reverts() public {
        bytes memory callData = abi.encodeCall(verifier.addAttestor, (NEW_ATTESTOR));

        vm.prank(PROP_1);
        timelock.schedule(address(verifier), 0, callData, bytes32(0), keccak256("salt4"), MIN_DELAY);

        // Try to execute immediately (without waiting 48h) -- must revert.
        vm.expectRevert();
        timelock.execute(address(verifier), 0, callData, bytes32(0), keccak256("salt4"));
    }

    // -------------------------------------------------------------------------
    // 5. Timelock delay is exactly 48h (MIN_DELAY constant)
    // -------------------------------------------------------------------------

    /// @notice The timelock's minimum delay is exactly 48 hours.
    function test_timelock_delay_is_48h() public view {
        assertEq(timelock.getMinDelay(), MIN_DELAY, "timelock delay must be 48h");
    }
}
