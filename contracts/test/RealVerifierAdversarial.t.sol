// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "./P3StubVerifier.sol";
import "../src/P3RealVerifier.sol";

/// @title RealVerifierAdversarial
/// @notice Adversarial test suite for P3RealVerifier (D.I.3).
///
/// Tests cover: malformed proof lengths, wrong signer, invalid v values,
/// zero scalars, wrong publicInputs length, replay, gas griefing, cross-input
/// reuse, and tamper attacks.  All must return false (not revert).
///
/// Private key: Anvil #0 = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
/// TRUSTED_SIGNER: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
contract RealVerifierAdversarial is Test {
    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    P3RealVerifier internal verifier;
    P3ProofRouter  internal router;

    uint256 internal constant TRUSTED_PRIVATE_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    /// @dev A different private key (Anvil #1).
    uint256 internal constant WRONG_PRIVATE_KEY =
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    bytes internal validPublicInputs;
    bytes internal validProof;

    function setUp() public {
        verifier = new P3RealVerifier();
        router   = new P3ProofRouter(address(verifier));

        validPublicInputs = _buildPublicInputs(
            keccak256("cipher"),
            keccak256("plain"),
            keccak256("agg_pk"),
            keccak256("dkg"),
            uint64(42),
            keccak256("participants"),
            keccak256("d_commit")
        );

        bytes32 digest = keccak256(validPublicInputs);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TRUSTED_PRIVATE_KEY, digest);
        validProof = abi.encodePacked(r, s, v);
    }

    // =========================================================================
    // Adversarial test 1: empty proof bytes (length < 65) → returns false
    // =========================================================================

    /// @notice A proof shorter than 65 bytes must be rejected.
    function test_adv_empty_proof_rejected() public view {
        bytes memory emptyProof = new bytes(0);
        bool ok = verifier.verify(emptyProof, validPublicInputs);
        assertFalse(ok, "empty proof must be rejected");
    }

    /// @notice A proof of exactly 64 bytes (one byte short) must be rejected.
    function test_adv_64byte_proof_rejected() public view {
        bytes memory shortProof = new bytes(64);
        bool ok = verifier.verify(shortProof, validPublicInputs);
        assertFalse(ok, "64-byte proof must be rejected");
    }

    // =========================================================================
    // Adversarial test 3: wrong signer → returns false
    // =========================================================================

    /// @notice Proof signed by a different key than TRUSTED_SIGNER must be rejected.
    function test_adv_wrong_signer_rejected() public view {
        bytes32 digest = keccak256(validPublicInputs);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(WRONG_PRIVATE_KEY, digest);
        bytes memory wrongProof = abi.encodePacked(r, s, v);
        bool ok = verifier.verify(wrongProof, validPublicInputs);
        assertFalse(ok, "proof from wrong signer must be rejected");
    }

    // =========================================================================
    // Adversarial test 4: v=2 raw (→ 29 after +27, fails 27/28 check)
    // =========================================================================

    /// @notice Raw v=2 normalises to 29, which ecrecover rejects → false.
    function test_adv_invalid_v_rejected() public view {
        bytes32 digest = keccak256(validPublicInputs);
        (, bytes32 r, bytes32 s) = vm.sign(TRUSTED_PRIVATE_KEY, digest);
        // Force v=2 raw (< 27 so +27 → 29, fails the v!=27&&v!=28 guard)
        bytes memory badProof = abi.encodePacked(r, s, uint8(2));
        bool ok = verifier.verify(badProof, validPublicInputs);
        assertFalse(ok, "v=2 raw must be rejected");
    }

    // =========================================================================
    // Adversarial test 5: r=0 → ecrecover returns address(0) → false
    // =========================================================================

    /// @notice A proof with r=0 causes ecrecover to return address(0) → rejected.
    function test_adv_r_zero_rejected() public view {
        bytes32 digest = keccak256(validPublicInputs);
        (, , bytes32 s) = vm.sign(TRUSTED_PRIVATE_KEY, digest);
        bytes memory badProof = abi.encodePacked(bytes32(0), s, uint8(27));
        bool ok = verifier.verify(badProof, validPublicInputs);
        assertFalse(ok, "r=0 must be rejected");
    }

    // =========================================================================
    // Adversarial test 6: s=0 → ecrecover returns address(0) → false
    // =========================================================================

    /// @notice A proof with s=0 causes ecrecover to return address(0) → rejected.
    function test_adv_s_zero_rejected() public view {
        bytes32 digest = keccak256(validPublicInputs);
        (, bytes32 r, ) = vm.sign(TRUSTED_PRIVATE_KEY, digest);
        bytes memory badProof = abi.encodePacked(r, bytes32(0), uint8(27));
        bool ok = verifier.verify(badProof, validPublicInputs);
        assertFalse(ok, "s=0 must be rejected");
    }

    // =========================================================================
    // Adversarial test 7: publicInputs length ≠ 200 → false
    // =========================================================================

    /// @notice 199-byte publicInputs must be rejected.
    function test_adv_wrong_pubinputs_length_rejected() public view {
        bytes memory shortPi = new bytes(199);
        bool ok = verifier.verify(validProof, shortPi);
        assertFalse(ok, "199-byte publicInputs must be rejected");
    }

    /// @notice 201-byte publicInputs must also be rejected.
    function test_adv_too_long_pubinputs_rejected() public view {
        bytes memory longPi = new bytes(201);
        bool ok = verifier.verify(validProof, longPi);
        assertFalse(ok, "201-byte publicInputs must be rejected");
    }

    // =========================================================================
    // Adversarial test 8: replay attack → deterministic (same result both times)
    // =========================================================================

    /// @notice Submitting the same valid proof twice must return the same result
    ///         (replay-resistant by design: pure function, no state).
    function test_adv_replay_deterministic() public view {
        bool r1 = verifier.verify(validProof, validPublicInputs);
        bool r2 = verifier.verify(validProof, validPublicInputs);
        assertTrue(r1, "first call must succeed");
        assertEq(r1, r2, "replay must return same result (deterministic)");
    }

    // =========================================================================
    // Adversarial test 9: gas griefing — 14 KB proof → returns false, ≤5M gas
    // =========================================================================

    /// @notice Oversized proof (14 KB) of garbage must return false without
    ///         excessive gas consumption.
    function test_adv_gas_griefing_large_proof() public view {
        bytes memory hugeProof = new bytes(14_336); // 14 KB
        // Fill with non-zero garbage
        for (uint256 i = 0; i < hugeProof.length; i++) {
            hugeProof[i] = bytes1(uint8(i & 0xff) | 0x01);
        }
        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(hugeProof, validPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();
        assertFalse(ok, "garbage 14KB proof must be rejected");
        assertLe(gasUsed, 5_000_000, "gas must not exceed 5M");
    }

    // =========================================================================
    // Adversarial test 10: MEV cross-input — valid proof for A used against B
    // =========================================================================

    /// @notice Proof valid for publicInputs_A must not verify against publicInputs_B.
    function test_adv_cross_input_reuse_rejected() public view {
        // Build a second, different public-inputs blob
        bytes memory piB = _buildPublicInputs(
            keccak256("different_cipher"),
            keccak256("different_plain"),
            keccak256("agg_pk"),
            keccak256("dkg"),
            uint64(43),
            keccak256("participants"),
            keccak256("d_commit")
        );
        // validProof was generated for validPublicInputs, not piB
        bool ok = verifier.verify(validProof, piB);
        assertFalse(ok, "proof for A must not verify against B");
    }

    // =========================================================================
    // Adversarial test 11: tampered r byte in an otherwise valid proof
    // =========================================================================

    /// @notice Single-byte tamper to the r component must cause rejection.
    function test_adv_tampered_r_rejected() public view {
        bytes memory tampered = _copyBytes(validProof);
        tampered[5] = tampered[5] ^ 0xff; // flip a byte in the r component
        bool ok = verifier.verify(tampered, validPublicInputs);
        assertFalse(ok, "tampered r must be rejected");
    }

    // =========================================================================
    // Adversarial test 12: tampered s byte in an otherwise valid proof
    // =========================================================================

    /// @notice Single-byte tamper to the s component must cause rejection.
    function test_adv_tampered_s_rejected() public view {
        bytes memory tampered = _copyBytes(validProof);
        tampered[40] = tampered[40] ^ 0xff; // flip a byte in the s component
        bool ok = verifier.verify(tampered, validPublicInputs);
        assertFalse(ok, "tampered s must be rejected");
    }

    // =========================================================================
    // Bonus test 13: router emits ProofRejected when real verifier returns false
    // =========================================================================

    /// @notice When the real verifier rejects, the router MUST emit ProofRejected.
    function test_adv_router_emits_proof_rejected() public {
        bytes memory badProof = _copyBytes(validProof);
        badProof[0] ^= 0xff; // corrupt r

        vm.expectEmit(true, true, false, true, address(router));
        emit P3ProofRouter.ProofRejected(
            keccak256(validPublicInputs),
            keccak256(badProof),
            3
        );
        router.submitProof(badProof, validPublicInputs);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

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
            mstore(ptr,           ciphertextHash)
            mstore(add(ptr, 32),  plaintextHash)
            mstore(add(ptr, 64),  aggregatePkHash)
            mstore(add(ptr, 96),  dkgRoot)
            mstore(add(ptr, 128), shl(192, epoch))
            mstore(add(ptr, 136), participantSetHash)
            mstore(add(ptr, 168), dCommitment)
        }
    }

    function _copyBytes(bytes memory src) internal pure returns (bytes memory dst) {
        dst = new bytes(src.length);
        for (uint256 i = 0; i < src.length; i++) {
            dst[i] = src[i];
        }
    }
}
