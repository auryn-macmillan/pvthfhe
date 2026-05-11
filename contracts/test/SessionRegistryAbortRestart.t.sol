// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SessionRegistry.sol";
import "../src/PvtFheVerifier.sol";

/// @title SessionRegistryAbortRestartTest
/// @notice R6.9 RED tests: registry abort/restart liveness with runId.
///
/// F69: `consumed[dkgRoot][epoch]` persists across abort/restart, making
/// DKG restart impossible when the same committee produces the same dkgRoot.
///
/// Fix: replace `consumed[dkgRoot][epoch]` with `consumed[dkgRoot][epoch][runId]`
/// where runId increments on each re-registration after abort.
///
/// Three tests (currently FAIL because consumed is 2-level, not 3-level):
///   1. Liveness: after abort+re-register, a fresh epoch under new runId is accepted.
///   2. Replay protection: old-run consumed epoch does NOT block new-run same epoch.
///   3. Abort emits SessionAborted event with runId for off-chain tracking.
contract SessionRegistryAbortRestartTest is Test {
    SessionRegistry internal reg;
    PvtFheVerifier internal verifier;

    bytes32 internal constant DKG_ROOT = keccak256("abort-restart-dkg");
    bytes32 internal constant ROSTER_HASH = keccak256("test-roster");
    uint32 internal constant N = 10;
    uint32 internal constant T = 6;
    uint64 internal constant EPOCH_1 = 1;
    uint64 internal constant EPOCH_2 = 2;

    // HonkVerifier tautology values
    bytes32 internal constant ZERO_HASH = bytes32(0);

    function setUp() public {
        reg = new SessionRegistry();
        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(this));

        verifier = new PvtFheVerifier(address(reg), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(verifier));
    }

    // =========================================================================
    // RED 1: Liveness — after abort+re-register, an honestly re-generated
    //         proof for the new run is accepted (same epoch is usable again).
    // =========================================================================

    /// @notice RED → GREEN: After abort+re-register, a fresh epoch under the
    ///         new runId is accepted. Demonstrates that the 3-level consumed
    ///         mapping (dkgRoot/epoch/runId) does NOT block the new run.
    function test_liveness_abortRestart_epochReusableUnderNewRunId() public {
        // --- Run 0 (runId = 0) ---
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // Consume epoch 1 under run 0
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_1), "epoch 1 must be consumed in run 0");

        // Abort the session
        reg.abortSession(DKG_ROOT);

        // --- Run 1 (runId = 1) ---
        // Re-register same dkgRoot (simulates deterministic dkgRoot from HermineAdapter)
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // epoch 1 was consumed in run 0, but must be USABLE in run 1
        // (this is the key liveness fix from F69)
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        // If this succeeds, the 3-level mapping works correctly.
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_1), "epoch 1 must be consumed in run 1");
    }

    // =========================================================================
    // RED 2: Replay protection — the old-run consumed flag is preserved.
    //         When the old epoch was consumed under old runId, the mapping
    //         preserved that information separately from the new run.
    // =========================================================================

    /// @notice RED → GREEN: The old-run consumed flag (runId=0) is independent
    ///         of the new-rerun consumed flag (runId=1). Both can be consumed.
    ///         Replay of the old proof is prevented because the proof binds to
    ///         a specific runId (R8.2 pre-reveal tuple).
    ///
    ///         For now (pre-R8.2), we verify that the old-run epoch consumption
    ///         does NOT prevent the new-run epoch from being consumed.
    function test_replayProtection_oldRunConsumedDoesNotBlockNewRun() public {
        // --- Run 0 ---
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // Consume epochs 1 and 2 under run 0
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_2);

        // Abort
        reg.abortSession(DKG_ROOT);

        // --- Run 1 ---
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // Both epochs 1 and 2 from run 0 should NOT block run 1
        // (they were consumed under runId=0, not runId=1)
        // If the old 2-level mapping behavior persists, this reverts.
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
        reg.markEpochConsumed(DKG_ROOT, EPOCH_2);

        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_1), "epoch 1 consumed in run 1");
        assertTrue(reg.isEpochConsumed(DKG_ROOT, EPOCH_2), "epoch 2 consumed in run 1");

        // Attempt to re-consume either epoch under this run should still revert
        // (same-run replay protection)
        vm.expectRevert(
            abi.encodeWithSelector(SessionRegistry.EpochAlreadyConsumed.selector, DKG_ROOT, EPOCH_1)
        );
        reg.markEpochConsumed(DKG_ROOT, EPOCH_1);
    }

    // =========================================================================
    // RED 3: Abort emits event that off-chain indexers can use to track
    //         the new epoch / runId.
    // =========================================================================

    /// @notice RED → GREEN: Aborting a session emits SessionAborted.
    ///         The event should include dkgRoot (already emitted).
    ///         Off-chain indexers track runId by watching for
    ///         SessionRegistered after SessionAborted on the same dkgRoot.
    function test_abort_emitsEvent_forOffChainTracking() public {
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        vm.expectEmit(true, false, false, false);
        emit SessionRegistry.SessionAborted(DKG_ROOT, 0);
        reg.abortSession(DKG_ROOT);

        // Off-chain indexers can now detect:
        //   1. SessionRegistered(DKG_ROOT) → runId starts at 0
        //   2. SessionAborted(DKG_ROOT)    → run 0 is done
        //   3. SessionRegistered(DKG_ROOT) → runId = 1 (re-registration)
        // The runId is implicitly tracked by counting register/abort cycles.
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // Verify the re-registered session is active
        (, , , bool registered, bool aborted, ) = reg.sessions(DKG_ROOT);
        assertTrue(registered, "re-registered session must be active");
        assertFalse(aborted, "re-registered session must not be aborted");
    }

    // =========================================================================
    // Additional: PvtFheVerifier integration — verifyAndConsume with runId
    // =========================================================================

    /// @notice RED → GREEN: verifyAndConsume through PvtFheVerifier works
    ///         correctly with the 3-level consumed mapping.
    function test_verifyAndConsume_afterAbortRestart() public {
        // --- Run 0 ---
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // Craft a proof that passes the HonkVerifier tautology
        bytes memory proof0 = hex"deadbeef";
        bytes32 ctHash0 = keccak256(proof0);

        bool ok0 = verifier.verifyAndConsume(
            ctHash0, ZERO_HASH, ZERO_HASH, DKG_ROOT, EPOCH_1, ZERO_HASH, ZERO_HASH, proof0
        );
        assertTrue(ok0, "verifyAndConsume run 0 epoch 1 must succeed");

        // Abort run 0
        reg.abortSession(DKG_ROOT);

        // --- Run 1 ---
        reg.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // Fresh proof for run 1, same epoch — must succeed
        bytes memory proof1 = hex"cafebabe";
        bytes32 ctHash1 = keccak256(proof1);

        bool ok1 = verifier.verifyAndConsume(
            ctHash1, ZERO_HASH, ZERO_HASH, DKG_ROOT, EPOCH_1, ZERO_HASH, ZERO_HASH, proof1
        );
        assertTrue(ok1, "verifyAndConsume run 1 epoch 1 must succeed after abort/restart");

        // Replay of run 1 proof must revert
        vm.expectRevert(bytes("PVTHFHE: epoch replay"));
        verifier.verifyAndConsume(
            ctHash1, ZERO_HASH, ZERO_HASH, DKG_ROOT, EPOCH_1, ZERO_HASH, ZERO_HASH, proof1
        );
    }
}
