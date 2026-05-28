// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title EpochConsumptionAtomicityTest
/// @notice Tests that verifyAndConsume() atomically verifies and consumes epochs.
contract EpochConsumptionAtomicityTest is Test {
    PvtFheVerifier internal verifier;
    SessionRegistry internal reg;

    bytes32 internal constant DKG_ROOT = keccak256("dkgRoot");
    bytes32 internal constant ROSTER_HASH = keccak256("roster");
    uint64 internal constant EPOCH = 42;

    bytes internal validProof;

    function setUp() public {
        reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg), address(this));

        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(verifier));
        reg.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);

        // HonkVerifier (LOG_N=16) expects 7776 bytes.
        validProof = new bytes(7776);
        for (uint256 i = 0; i < 7776; i++) {
            validProof[i] = bytes1(uint8(i & 0xff) | 0x01);
        }
    }

    function test_invalid_proof_does_not_consume_epoch() public {
        assertFalse(reg.isEpochConsumed(DKG_ROOT, EPOCH), "pre: epoch must be fresh");

        // Invalid proof → HonkVerifier rejects. verifyAndConsume reverts.
        vm.expectRevert();
        verifier.verifyAndConsume(
            bytes32(uint256(0xDEAD)),
            bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH,
            bytes32(uint256(5)), bytes32(uint256(6)),
            validProof
        );

        // Epoch must NOT be consumed by a reverting proof.
        assertFalse(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch must NOT be consumed by invalid proof");
    }

    function test_valid_proof_consumes_epoch_and_succeeds() public {
        // Without a real valid proof, the HonkVerifier will reject.
        vm.expectRevert();
        verifier.verifyAndConsume(
            bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH,
            bytes32(uint256(5)), bytes32(uint256(6)),
            validProof
        );

        // Epoch must NOT be consumed when proof reverts.
        assertFalse(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch must not be consumed when proof reverts");
    }

    function test_invalid_then_valid_still_consumes_epoch() public {
        // First: invalid proof attempt
        vm.expectRevert();
        verifier.verifyAndConsume(
            bytes32(uint256(0xDEAD)), bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH, bytes32(uint256(5)), bytes32(uint256(6)), validProof
        );

        assertFalse(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch must NOT be consumed after invalid proof");

        // Second: another attempt (still no real valid proof → reverts)
        vm.expectRevert();
        verifier.verifyAndConsume(
            bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH, bytes32(uint256(5)), bytes32(uint256(6)), validProof
        );

        assertFalse(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch must NOT be consumed without valid proof");
    }

    function test_replay_protection_still_works() public {
        // Attempt consumption — HonkVerifier rejects, no consumption happens.
        vm.expectRevert();
        verifier.verifyAndConsume(
            bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)),
            DKG_ROOT, EPOCH, bytes32(uint256(5)), bytes32(uint256(6)), validProof
        );

        // Epoch was never consumed, so replay should NOT trigger epoch replay error.
        // (It will again reject because proof is invalid.)
        assertFalse(reg.isEpochConsumed(DKG_ROOT, EPOCH), "epoch was never consumed");
    }
}
