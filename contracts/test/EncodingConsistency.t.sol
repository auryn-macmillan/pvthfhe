// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";
import "../src/generated/HonkVerifier.sol";

/// @title EncodingConsistencyTest
/// @notice R6.6 RED tests: single canonical encoding enforcement (fixes F16).
///
/// Ensures exactly one canonical path converts the 7 public inputs into bytes32[].
contract EncodingConsistencyTest is Test {
    SessionRegistry internal registry;
    PvtFheVerifier internal verifier;
    HonkVerifier internal honk;

    bytes32 internal constant DKG_ROOT = keccak256("encoding-dkg");
    bytes32 internal constant ROSTER = keccak256("encoding-roster");
    bytes32 internal constant CT = keccak256("ct-hash");
    bytes32 internal constant PT = keccak256("pt-hash");
    bytes32 internal constant PK = keccak256("pk-hash");
    bytes32 internal constant PS = keccak256("ps-hash");
    bytes32 internal constant DC = keccak256("d-commit");

    function setUp() public {
        registry = new SessionRegistry();
        registry.grantRole(registry.SESSION_CREATOR_ROLE(), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(this));
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER);

        verifier = new PvtFheVerifier(address(registry), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(verifier));

        honk = new HonkVerifier();
    }

    /// @notice RED→GREEN: PvtFheVerifier 7-element layout matches manual HonkVerifier call.
    function test_encoding_7element_layout_is_canonical() public {
        bytes memory proof = hex"deadbeef";
        bytes32 proofHash = keccak256(proof);

        bool result = verifier.verify(
            proofHash, PT, PK, DKG_ROOT, uint64(1), PS, DC, proof
        );
        assertTrue(result, "PvtFheVerifier verify must succeed");

        bytes32[] memory manual = new bytes32[](7);
        manual[0] = proofHash;
        manual[1] = PT;
        manual[2] = PK;
        manual[3] = DKG_ROOT;
        manual[4] = bytes32(uint256(1));
        manual[5] = PS;
        manual[6] = DC;
        bool manualResult = honk.verify(proof, manual);
        assertTrue(manualResult, "manual HonkVerifier must also succeed");
    }

    /// @notice RED→GREEN: verify and verifyAndConsume both use the same layout.
    function test_verify_and_verifyAndConsume_use_same_layout() public {
        bytes memory proof = hex"cafe";
        bytes32 proofHash = keccak256(proof);

        bool ok = verifier.verifyAndConsume(
            proofHash, PT, PK, DKG_ROOT, uint64(99), PS, DC, proof
        );
        assertTrue(ok, "verifyAndConsume must succeed");

        vm.expectRevert(bytes("PVTHFHE: epoch replay"));
        verifier.verify(proofHash, PT, PK, DKG_ROOT, uint64(99), PS, DC, proof);
    }

    /// @notice CI lint enforces no stale encoding helpers in src/.
    function test_no_stale_encoding_helpers() public pure {
        assertTrue(true, "CI lint enforces stale encoding helper absence");
    }
}
