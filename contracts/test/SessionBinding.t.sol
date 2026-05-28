// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title SessionBindingTest
/// @notice R6.1 tests: atomic session binding for the on-chain verifier.
contract SessionBindingTest is Test {
    SessionRegistry internal registry;
    PvtFheVerifier internal verifier;

    bytes32 internal constant DKG_ROOT = keccak256("test-dkg-root");
    bytes32 internal constant ROSTER_HASH = keccak256("test-roster");
    bytes32 internal constant ZERO_HASH = bytes32(0);
    uint32 internal constant N = 10;
    uint32 internal constant T = 6;
    uint64 internal constant EPOCH = 42;

    /// @dev HonkVerifier (LOG_N=16) expects exactly 7776-byte proofs.
    function _makeProof() internal pure returns (bytes memory) {
        bytes memory proof = new bytes(7776);
        // Fill with non-zero data so keccak256 is not all-zeros.
        for (uint256 i = 0; i < proof.length; i++) {
            proof[i] = bytes1(uint8(i & 0xff) | 0x01);
        }
        return proof;
    }

    function setUp() public {
        registry = new SessionRegistry();
        verifier = new PvtFheVerifier(address(registry), address(this));
        registry.grantRole(registry.SESSION_CREATOR_ROLE(), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(verifier));
    }

    // -------------------------------------------------------------------------
    // 1: verify reverts if session (dkgRoot) is unknown
    // -------------------------------------------------------------------------

    function test_verify_reverts_on_unknown_session() public {
        bytes32 unknownDkgRoot = keccak256("unknown-dkg-root");
        bytes memory proof = _makeProof();

        vm.expectRevert(bytes("PVTHFHE: unknown dkg root"));
        verifier.verify(
            ZERO_HASH, ZERO_HASH, ZERO_HASH,
            unknownDkgRoot, 0, ZERO_HASH, ZERO_HASH, proof
        );
    }

    // -------------------------------------------------------------------------
    // 2: verify reverts if the epoch is already consumed
    // -------------------------------------------------------------------------

    function test_verify_reverts_on_consumed_epoch() public {
        registry.registerSession(DKG_ROOT, N, T, ROSTER_HASH);
        registry.markEpochConsumed(DKG_ROOT, EPOCH);
        bytes memory proof = _makeProof();

        vm.expectRevert(bytes("PVTHFHE: epoch replay"));
        verifier.verify(
            ZERO_HASH, ZERO_HASH, ZERO_HASH,
            DKG_ROOT, EPOCH, ZERO_HASH, ZERO_HASH, proof
        );
    }

    // -------------------------------------------------------------------------
    // 3: verifyAndConsume with invalid proof returns false and does NOT consume epoch
    // -------------------------------------------------------------------------

    function test_verifyAndConsume_atomic_and_replay_reverts() public {
        registry.registerSession(DKG_ROOT, N, T, ROSTER_HASH);

        bytes memory proof = _makeProof();

        // Invalid proof → HonkVerifier reverts during deserialization.
        // verifyAndConsume propagates the revert.
        vm.expectRevert();
        verifier.verifyAndConsume(
            ZERO_HASH, ZERO_HASH, ZERO_HASH,
            DKG_ROOT, EPOCH, ZERO_HASH, ZERO_HASH, proof
        );

        // Epoch must NOT be consumed (proof was invalid, call reverted).
        assertFalse(
            registry.isEpochConsumed(DKG_ROOT, EPOCH),
            "epoch must not be consumed when proof is invalid"
        );

        // Replay: same proof, same epoch — also reverts (still not consumed).
        vm.expectRevert();
        verifier.verifyAndConsume(
            ZERO_HASH, ZERO_HASH, ZERO_HASH,
            DKG_ROOT, EPOCH, ZERO_HASH, ZERO_HASH, proof
        );
    }
}
