// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "./P3StubVerifier.sol";

/// @title RealVerifierTest
/// @notice RED tests for the real on-chain P3 verifier (D.I.1).
///
/// These tests are intentionally written to FAIL because the implementation
/// under test (`P3StubVerifier`) reverts with "unimplemented".  Every test
/// that calls `verifier.verify(...)` directly receives an unexpected revert
/// and is therefore marked FAIL by Foundry's test runner.
///
/// When the real UltraHonk verifier is wired in (D.I.2 green phase), these
/// tests should be updated with a real proof fixture so they turn GREEN.
///
/// Public-inputs layout (200 bytes, per interface-spec.md §Calldata):
///   [  0.. 31] ciphertext_hash      (32 B, SHA-256)
///   [ 32.. 63] plaintext_hash       (32 B, SHA-256)
///   [ 64.. 95] aggregate_pk_hash    (32 B, SHA-256)
///   [ 96..127] dkg_root             (32 B, SHA-256)
///   [128..135] epoch                ( 8 B, big-endian u64)
///   [136..167] participant_set_hash (32 B, SHA-256)
///   [168..199] d_commitment         (32 B, SHA-256)
contract RealVerifierTest is Test {
    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    P3StubVerifier internal verifier;
    P3ProofRouter  internal router;

    /// @dev Minimal valid-looking 200-byte public-inputs blob.
    bytes internal validPublicInputs;
    /// @dev Proof envelope: version=0x01, backend=0x01, then 64 bytes of data.
    bytes internal validProof;

    function setUp() public {
        verifier = new P3StubVerifier();
        router   = new P3ProofRouter(address(verifier));

        // Build 200-byte public-inputs fixture
        validPublicInputs = _buildPublicInputs(
            keccak256("ciphertext"),
            keccak256("plaintext"),
            keccak256("agg_pk"),
            keccak256("dkg_root"),
            uint64(1),
            keccak256("participant_set"),
            keccak256("d_commitment")
        );

        // Build proof envelope: version=0x01, backend=0x01, 64 bytes payload
        validProof = new bytes(66);
        validProof[0] = 0x01; // proof_version
        validProof[1] = 0x01; // backend_id (SP1+Groth16)
        for (uint256 i = 2; i < 66; i++) {
            validProof[i] = bytes1(uint8(i));
        }
    }

    /// @dev Build the canonical 200-byte public-inputs blob.
    function _buildPublicInputs(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64  epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment
    ) internal pure returns (bytes memory pi) {
        pi = new bytes(200);
        assembly {
            let ptr := add(pi, 32)
            mstore(ptr,        ciphertextHash)
            mstore(add(ptr, 32),  plaintextHash)
            mstore(add(ptr, 64),  aggregatePkHash)
            mstore(add(ptr, 96),  dkgRoot)
            // epoch at offset 128, 8 bytes — store as right-aligned uint64
            mstore(add(ptr, 128), shl(192, epoch))
            mstore(add(ptr, 136), participantSetHash)
            mstore(add(ptr, 168), dCommitment)
        }
    }

    // -------------------------------------------------------------------------
    // 1. Honest proof verifies
    // -------------------------------------------------------------------------

    /// @notice An honest P2 final proof with correct public inputs MUST return true.
    ///         RED: stub reverts "unimplemented" → test fails with unexpected revert.
    function test_honest_proof_verifies() public view {
        bool ok = verifier.verify(validProof, validPublicInputs);
        assertTrue(ok, "honest proof must verify");
    }

    // -------------------------------------------------------------------------
    // 2. Tampered proof rejected
    // -------------------------------------------------------------------------

    /// @notice A single-byte tamper to the proof payload MUST return false (not true).
    ///         RED: stub reverts "unimplemented" → test fails with unexpected revert.
    function test_tampered_proof_rejects() public view {
        bytes memory tampered = _copyAndFlipByte(validProof, 10);
        bool ok = verifier.verify(tampered, validPublicInputs);
        assertFalse(ok, "tampered proof must not verify");
    }

    // -------------------------------------------------------------------------
    // 3. Wrong public inputs rejected
    // -------------------------------------------------------------------------

    /// @notice Submitting proof against wrong publicInputs MUST return false.
    ///         RED: stub reverts "unimplemented" → test fails with unexpected revert.
    function test_wrong_public_inputs_rejects() public view {
        bytes memory wrongPi = _buildPublicInputs(
            keccak256("wrong_ciphertext"),
            keccak256("plaintext"),
            keccak256("agg_pk"),
            keccak256("dkg_root"),
            uint64(1),
            keccak256("participant_set"),
            keccak256("d_commitment")
        );
        bool ok = verifier.verify(validProof, wrongPi);
        assertFalse(ok, "proof against wrong publicInputs must not verify");
    }

    // -------------------------------------------------------------------------
    // 4. Gas within budget
    // -------------------------------------------------------------------------

    /// @notice Gas consumed by verify() MUST be ≤5,000,000.
    ///         RED: stub reverts "unimplemented" → test fails with unexpected revert.
    function test_gas_within_budget() public view {
        uint256 gasBefore = gasleft();
        verifier.verify(validProof, validPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertLe(gasUsed, 5_000_000, "gas exceeds 5M budget");
    }

    // -------------------------------------------------------------------------
    // 5. ProofRejected event on rejection
    // -------------------------------------------------------------------------

    /// @notice Router MUST emit ProofRejected when the verifier rejects a proof.
    ///         RED: stub reverts "unimplemented" inside router → router reverts
    ///              → test fails (router call reverts unexpectedly).
    function test_blame_event_on_rejection() public {
        bytes memory badProof = _copyAndFlipByte(validProof, 5);

        vm.expectEmit(true, true, false, true, address(router));
        emit P3ProofRouter.ProofRejected(
            keccak256(validPublicInputs),
            keccak256(badProof),
            3
        );

        router.submitProof(badProof, validPublicInputs);
    }

    // -------------------------------------------------------------------------
    // 6. Determinism across resubmissions
    // -------------------------------------------------------------------------

    /// @notice Calling verify() twice with identical inputs MUST return the same result.
    ///         RED: both calls revert "unimplemented" → first revert terminates the test.
    function test_determinism_across_resubmissions() public view {
        bool r1 = verifier.verify(validProof, validPublicInputs);
        bool r2 = verifier.verify(validProof, validPublicInputs);
        assertEq(r1, r2, "verify must be deterministic");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _copyAndFlipByte(bytes memory src, uint256 idx)
        internal
        pure
        returns (bytes memory dst)
    {
        dst = new bytes(src.length);
        for (uint256 i = 0; i < src.length; i++) {
            dst[i] = src[i];
        }
        dst[idx] = dst[idx] ^ 0xff;
    }
}
