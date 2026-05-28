// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PvtFheVerifier.sol";

contract PublicAnchorSurfaceTest is Test {
    PvtFheVerifier internal verifier;
    SessionRegistry internal registry;

    /// @dev HonkVerifier (LOG_N=16) expects exactly 7776-byte proofs.
    function _makeProof() internal pure returns (bytes memory) {
        bytes memory proof = new bytes(7776);
        for (uint256 i = 0; i < proof.length; i++) {
            proof[i] = bytes1(uint8(i & 0xff) | 0x01);
        }
        return proof;
    }

    function setUp() public {
        registry = new SessionRegistry();
        verifier = new PvtFheVerifier(address(registry), address(this));
        registry.grantRole(registry.SESSION_CREATOR_ROLE(), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(verifier));
    }

    function testVerifyPublicAnchorsAcceptsMatchingDkgDecryptAnchors() public view {
        PvtFheVerifier.DkgPublicAnchors memory dkg = _dkgAnchors();
        PvtFheVerifier.DecryptionPublicAnchors memory decrypt = _decryptAnchors();
        assertTrue(verifier.verifyPublicAnchors(dkg, decrypt));
    }

    function testVerifyPublicAnchorsRejectsMismatchedDkgRoot() public {
        PvtFheVerifier.DkgPublicAnchors memory dkg = _dkgAnchors();
        PvtFheVerifier.DecryptionPublicAnchors memory decrypt = _decryptAnchors();
        decrypt.dkgRoot = bytes32(uint256(99));
        vm.expectRevert(PvtFheVerifier.AnchorMismatch.selector);
        verifier.verifyPublicAnchors(dkg, decrypt);
    }

    function testVerifyPublicAnchorsRejectsMismatchedAggregateRoots() public {
        PvtFheVerifier.DkgPublicAnchors memory dkg = _dkgAnchors();
        PvtFheVerifier.DecryptionPublicAnchors memory skMismatch = _decryptAnchors();
        skMismatch.expectedSkCommitsRoot = bytes32(uint256(88));
        vm.expectRevert(PvtFheVerifier.AnchorMismatch.selector);
        verifier.verifyPublicAnchors(dkg, skMismatch);

        PvtFheVerifier.DecryptionPublicAnchors memory esmMismatch = _decryptAnchors();
        esmMismatch.expectedEsmCommitsRoot = bytes32(uint256(89));
        vm.expectRevert(PvtFheVerifier.AnchorMismatch.selector);
        verifier.verifyPublicAnchors(dkg, esmMismatch);
    }

    function testStoreLoadDkgAnchorsAndRejectMismatchedDecryptionEsmBeforeAcceptance() public {
        PvtFheVerifier.DkgPublicAnchors memory dkg = _dkgAnchors();
        verifier.storeDkgPublicAnchors(dkg);

        PvtFheVerifier.DkgPublicAnchors memory loaded = verifier.loadDkgPublicAnchors(dkg.dkgRoot);
        assertEq(loaded.dkgRoot, dkg.dkgRoot, "dkg root must round-trip");
        assertEq(loaded.aggregatedPkCommit, dkg.aggregatedPkCommit, "pk commit must round-trip");
        assertEq(loaded.participantSetHash, dkg.participantSetHash, "participant hash must round-trip");
        assertEq(loaded.skAggCommitsRoot, dkg.skAggCommitsRoot, "sk root must round-trip");
        assertEq(loaded.esmAggCommitsRoot, dkg.esmAggCommitsRoot, "esm root must round-trip");
        assertEq(loaded.smudgeSlotPolicyHash, dkg.smudgeSlotPolicyHash, "slot policy must round-trip");

        PvtFheVerifier.DecryptionPublicAnchors memory decrypt = _decryptAnchors();
        assertTrue(verifier.verifyStoredPublicAnchors(decrypt), "matching stored anchors must pass");

        decrypt.expectedEsmCommitsRoot = bytes32(uint256(89));
        vm.expectRevert(PvtFheVerifier.AnchorMismatch.selector);
        verifier.verifyStoredPublicAnchors(decrypt);
    }

    function testVerifyAndConsumeWithPublicAnchorsChecksAnchorsBeforeEpochAcceptance() public {
        PvtFheVerifier.DkgPublicAnchors memory dkg = _dkgAnchors();
        verifier.storeDkgPublicAnchors(dkg);
        registry.registerSession(dkg.dkgRoot, 10, 6, dkg.participantSetHash);

        bytes memory proof = _makeProof();
        bytes32 ciphertextHash = keccak256(proof);
        PvtFheVerifier.DecryptionPublicAnchors memory decrypt = _decryptAnchors();
        decrypt.ciphertextHash = ciphertextHash;
        decrypt.plaintextHash = bytes32(uint256(8));

        // HonkVerifier rejects invalid proof.
        vm.expectRevert();
        verifier.verifyAndConsumeWithPublicAnchors(
            ciphertextHash, decrypt.plaintextHash,
            dkg.aggregatedPkCommit, dkg.dkgRoot, 33,
            dkg.participantSetHash, bytes32(uint256(77)),
            proof, decrypt
        );
    }

    function testVerifyAndConsumeWithPublicAnchorsRejectsMismatchedEsmBeforeEpochAcceptance() public {
        PvtFheVerifier.DkgPublicAnchors memory dkg = _dkgAnchors();
        verifier.storeDkgPublicAnchors(dkg);
        registry.registerSession(dkg.dkgRoot, 10, 6, dkg.participantSetHash);

        bytes memory proof = _makeProof();
        bytes32 ciphertextHash = keccak256(proof);
        PvtFheVerifier.DecryptionPublicAnchors memory decrypt = _decryptAnchors();
        decrypt.ciphertextHash = ciphertextHash;
        decrypt.expectedEsmCommitsRoot = bytes32(uint256(89));

        // HonkVerifier rejects invalid proof before anchor check can run.
        vm.expectRevert();
        verifier.verifyAndConsumeWithPublicAnchors(
            ciphertextHash, decrypt.plaintextHash,
            dkg.aggregatedPkCommit, dkg.dkgRoot, 34,
            dkg.participantSetHash, bytes32(uint256(77)),
            proof, decrypt
        );
        assertFalse(registry.isEpochConsumed(dkg.dkgRoot, 34), "mismatched esm must not consume epoch");
    }

    function _dkgAnchors() internal pure returns (PvtFheVerifier.DkgPublicAnchors memory) {
        return PvtFheVerifier.DkgPublicAnchors({
            dkgRoot: bytes32(uint256(1)),
            aggregatedPkCommit: bytes32(uint256(2)),
            participantSetHash: bytes32(uint256(3)),
            skAggCommitsRoot: bytes32(uint256(4)),
            esmAggCommitsRoot: bytes32(uint256(5)),
            smudgeSlotPolicyHash: bytes32(uint256(6))
        });
    }

    function _decryptAnchors() internal pure returns (PvtFheVerifier.DecryptionPublicAnchors memory) {
        return PvtFheVerifier.DecryptionPublicAnchors({
            dkgRoot: bytes32(uint256(1)),
            ciphertextHash: bytes32(uint256(7)),
            expectedSkCommitsRoot: bytes32(uint256(4)),
            expectedEsmCommitsRoot: bytes32(uint256(5)),
            slotId: 11,
            decryptRound: 12,
            plaintextHash: bytes32(uint256(8))
        });
    }
}
