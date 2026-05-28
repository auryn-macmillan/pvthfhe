// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SessionRegistry.sol";
import "../src/PvtFheVerifier.sol";

/// @title SessionRegistryAbortRestartTest
/// @notice R6.9 tests: registry abort/restart liveness with runId.
contract SessionRegistryAbortRestartTest is Test {
    SessionRegistry internal reg;
    PvtFheVerifier internal verifier;

    bytes32 internal constant DKG_ROOT = keccak256("abort-restart-dkg");
    bytes32 internal constant ROSTER_HASH = keccak256("test-roster");
    uint32 internal constant N = 10;
    uint32 internal constant T = 6;
    uint64 internal constant EPOCH_1 = 1;
    uint64 internal constant EPOCH_2 = 2;
    bytes32 internal constant ZERO_HASH = bytes32(0);

    /// @dev HonkVerifier (LOG_N=16) expects exactly 7776-byte proofs.
    function _makeProof() internal pure returns (bytes memory) {
        bytes memory proof = new bytes(7776);
        for (uint256 i = 0; i < proof.length; i++) {
            proof[i] = bytes1(uint8(i & 0xff) | 0x01);
        }
        return proof;
    }

    function setUp() public {
        reg = new SessionRegistry();
        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(this));

        verifier = new PvtFheVerifier(address(reg), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(verifier));
    }

    // =========================================================================
    // 1: Liveness — after abort+re-register, fresh epoch under new runId accepted
    // =========================================================================

    function test_liveness_abortRestart_epochReusableUnderNewRunId() public {
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_1), "epoch 1 must be consumed in run 0");
        reg.abortSession(DKG_ROOT);

        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_1), "epoch 1 must be consumed in run 1");
    }

    // =========================================================================
    // 2: Replay protection — old-run consumed flag is independent
    // =========================================================================

    function test_replayProtection_oldRunConsumedDoesNotBlockNewRun() public {
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_2);
        reg.abortSession(DKG_ROOT);

        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_2);

        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_1), "epoch 1 consumed in run 1");
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_2), "epoch 2 consumed in run 1");

        vm.expectRevert(
            abi.encodeWithSelector(SessionRegistry.EpochAlreadyConsumed.selector, DKG_ROOT, EPOCH_1)
        );
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
    }

    // =========================================================================
    // 3: Abort emits event for off-chain tracking
    // =========================================================================

    function test_abort_emitsEvent_forOffChainTracking() public {
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        vm.expectEmit(true, false, false, false);
        emit SessionRegistry.SessionAborted(DKG_ROOT, 0);
        reg.abortSession(DKG_ROOT);

        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);
        (, , , bool registered, bool aborted, ) = reg.sessions(DKG_ROOT);
        assertTrue(registered, "re-registered session must be active");
        assertFalse(aborted, "re-registered session must not be aborted");
    }

    // =========================================================================
    // Additional: PvtFheVerifier integration — verifyAndConsume with runId
    // =========================================================================

    function test_verifyAndConsume_afterAbortRestart() public {
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        bytes memory proof0 = _makeProof();

        // Invalid proof → HonkVerifier reverts, propagated by verifyAndConsume.
        vm.expectRevert();
        verifier.verifyAndConsume(
            ZERO_HASH, ZERO_HASH, ZERO_HASH, DKG_ROOT, EPOCH_1, ZERO_HASH, ZERO_HASH, proof0
        );

        reg.abortSession(DKG_ROOT);
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        bytes memory proof1 = _makeProof();
        vm.expectRevert();
        verifier.verifyAndConsume(
            ZERO_HASH, ZERO_HASH, ZERO_HASH, DKG_ROOT, EPOCH_1, ZERO_HASH, ZERO_HASH, proof1
        );

        // Replay also reverts.
        vm.expectRevert();
        verifier.verifyAndConsume(
            ZERO_HASH, ZERO_HASH, ZERO_HASH, DKG_ROOT, EPOCH_1, ZERO_HASH, ZERO_HASH, proof1
        );
    }
}
