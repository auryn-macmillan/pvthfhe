// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title SessionBindingTest
/// @notice R6.1 RED tests: atomic session binding for the on-chain verifier.
///
/// Three tests:
///   1. verify reverts if session does not exist.
///   2. verify reverts if epoch is already consumed.
///   3. verifyAndConsume atomically marks epoch consumed and succeeds;
///      replaying the same proof reverts.
contract SessionBindingTest is Test {
    SessionRegistry internal registry;
    PvtFheVerifier internal verifier;

    bytes32 internal constant DKG_ROOT = keccak256("test-dkg-root");
    bytes32 internal constant ROSTER_HASH = keccak256("test-roster");
    bytes32 internal constant ZERO_HASH = bytes32(0);
    uint32 internal constant N = 10;
    uint32 internal constant T = 6;
    uint64 internal constant EPOCH = 42;

    function setUp() public {
        registry = new SessionRegistry();
        verifier = new PvtFheVerifier(address(registry), address(this));
        // Grant roles for test contract (SESSION_CREATOR + VERIFIER) and verifier contract.
        registry.grantRole(registry.SESSION_CREATOR_ROLE(), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(verifier));
    }

    // -------------------------------------------------------------------------
    // RED 1: verify must revert if the session (dkgRoot) is unknown
    // -------------------------------------------------------------------------

    /// @notice Calling verify() with an unregistered dkgRoot must revert.
    function test_verify_reverts_on_unknown_session() public {
        bytes32 unknownDkgRoot = keccak256("unknown-dkg-root");
        bytes memory proof = hex"deadbeef";

        vm.expectRevert(bytes("PVTHFHE: unknown dkg root"));
        verifier.verify(
            ZERO_HASH,
            ZERO_HASH,
            ZERO_HASH,
            unknownDkgRoot,
            0,
            ZERO_HASH,
            ZERO_HASH,
            proof
        );
    }

    // -------------------------------------------------------------------------
    // RED 2: verify must revert if the epoch is already consumed
    // -------------------------------------------------------------------------

    /// @notice Calling verify() with a consumed epoch must revert.
    function test_verify_reverts_on_consumed_epoch() public {
        registry.registerSession(DKG_ROOT, N, T, ROSTER_HASH);
        registry.markEpochConsumed(DKG_ROOT, EPOCH);

        bytes memory proof = hex"deadbeef";

        vm.expectRevert(bytes("PVTHFHE: epoch replay"));
        verifier.verify(
            ZERO_HASH,
            ZERO_HASH,
            ZERO_HASH,
            DKG_ROOT,
            EPOCH,
            ZERO_HASH,
            ZERO_HASH,
            proof
        );
    }

    // -------------------------------------------------------------------------
    // RED 3: verifyAndConsume atomically marks epoch consumed; replay reverts
    // -------------------------------------------------------------------------

    /// @notice verifyAndConsume must atomically mark the epoch consumed
    ///         so that a subsequent call with the same (dkgRoot, epoch) reverts.
    function test_verifyAndConsume_atomic_and_replay_reverts() public {
        registry.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        // Craft a proof whose keccak256 matches ciphertextHash (HonkVerifier tautology).
        bytes memory proof = hex"deadbeef";
        bytes32 ctHash = keccak256(proof);

        // First call: should succeed (epoch not consumed yet).
        bool result = verifier.verifyAndConsume(
            ctHash,
            ZERO_HASH,
            ZERO_HASH,
            DKG_ROOT,
            EPOCH,
            ZERO_HASH,
            ZERO_HASH,
            proof
        );
        assertTrue(result, "verifyAndConsume must succeed for fresh epoch");

        // Epoch must now be marked consumed.
        assertTrue(
            registry.isEpochConsumed(DKG_ROOT, EPOCH),
            "epoch must be consumed after verifyAndConsume"
        );

        // Replay: same proof, same (dkgRoot, epoch) must revert.
        vm.expectRevert(bytes("PVTHFHE: epoch replay"));
        verifier.verifyAndConsume(
            ctHash,
            ZERO_HASH,
            ZERO_HASH,
            DKG_ROOT,
            EPOCH,
            ZERO_HASH,
            ZERO_HASH,
            proof
        );
    }
}
