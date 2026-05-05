// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../test/BaseVerifierTest.t.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title PvtFheVerifierTest
/// @notice Foundry tests for PvtFheVerifier hard-revert killswitch.
///
/// All verify() calls MUST revert with the surrogate notice string.
/// No code path in verify() may return true (C1 killswitch, Stage-0 red-team).
contract PvtFheVerifierTest is BaseVerifierTest {
    PvtFheVerifier internal verifier;

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    bytes32 internal constant ZERO_HASH = bytes32(0);
    bytes internal constant SURROGATE_REVERT =
        unicode"PVTHFHE: on-chain verifier is a research surrogate \u2014 do not deploy";

    function setUp() public override {
        super.setUp();
        SessionRegistry reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg));
        // Override sampleProof with a non-empty byte array to exercise proof parsing.
        sampleProof = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            sampleProof[i] = bytes1(uint8(i));
        }
    }

    // -------------------------------------------------------------------------
    // 1. ABI signature — must revert (not return)
    // -------------------------------------------------------------------------

    /// @notice Calls verify() with all-zero inputs; asserts it reverts with surrogate notice.
    function test_abi_signature() public {
        vm.expectRevert(
            unicode"PVTHFHE: on-chain verifier is a research surrogate \u2014 do not deploy"
        );
        verifier.verify(
            ZERO_HASH,
            ZERO_HASH,
            ZERO_HASH,
            ZERO_HASH,
            0,
            ZERO_HASH,
            ZERO_HASH,
            new bytes(0)
        );
    }

    // -------------------------------------------------------------------------
    // 2. Gas budget — revert is cheap; assert gas < 5M still holds
    // -------------------------------------------------------------------------

    /// @notice Measures gas consumed by verify() (which reverts) and asserts < 5M.
    function test_gas_budget() public {
        uint256 gasBefore = gasleft();
        (bool ok,) = address(verifier).call(
            abi.encodeCall(
                verifier.verify,
                (SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
                 SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, sampleProof)
            )
        );
        uint256 gasUsed = gasBefore - gasleft();
        assertFalse(ok, "call must revert");
        assertLt(gasUsed, 5_000_000, "gas used exceeds 5M soft target");
        assertLt(gasUsed, 10_000_000, "gas used exceeds 10M hard ceiling");
    }

    // -------------------------------------------------------------------------
    // 3. Tampered proof reverts
    // -------------------------------------------------------------------------

    /// @notice Tampered proof bytes must also revert — no bypass path exists.
    function test_tampered_proof_reverts_or_returns_false() public {
        bytes memory tampered = new bytes(sampleProof.length);
        for (uint256 i = 0; i < sampleProof.length; i++) {
            tampered[i] = sampleProof[i] ^ 0xff;
        }

        vm.expectRevert(
            unicode"PVTHFHE: on-chain verifier is a research surrogate \u2014 do not deploy"
        );
        verifier.verify(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, tampered
        );
    }

    // -------------------------------------------------------------------------
    // 4. "Valid" proof also reverts (killswitch)
    // -------------------------------------------------------------------------

    /// @notice Documents that surrogate verifier ALWAYS reverts — even with a "valid" proof.
    ///
    /// TODO(T39): When BB-generated verifier is wired in, replace this test with
    ///            a real UltraHonk proof acceptance check.
    function test_valid_proof_accepted() public {
        vm.expectRevert(
            unicode"PVTHFHE: on-chain verifier is a research surrogate \u2014 do not deploy"
        );
        verifier.verify(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, sampleProof
        );
    }

    // -------------------------------------------------------------------------
    // 5. Threshold value
    // -------------------------------------------------------------------------

    /// @notice threshold() returns 0 — dynamic threshold is now in SessionRegistry.
    function test_threshold_value() public view {
        assertEq(verifier.threshold(), 0, "threshold must be 0 (dynamic, use registeredThreshold)");
    }

    // -------------------------------------------------------------------------
    // 6. RLWE degree value
    // -------------------------------------------------------------------------

    /// @notice rlweDegree() returns 8192.
    function test_rlwe_degree_value() public view {
        assertEq(verifier.rlweDegree(), 8192, "rlweDegree must be 8192");
    }

    // -------------------------------------------------------------------------
    // 7. Interface compliance — cast works, but call reverts
    // -------------------------------------------------------------------------

    /// @notice Verifies that PvtFheVerifier implements IPvthfheVerifier via cast,
    ///         and that verify() reverts as expected.
    function test_interface_compliance() public {
        IPvthfheVerifier iface = IPvthfheVerifier(address(verifier));
        vm.expectRevert(
            unicode"PVTHFHE: on-chain verifier is a research surrogate \u2014 do not deploy"
        );
        iface.verify(
            ZERO_HASH, ZERO_HASH, ZERO_HASH, ZERO_HASH,
            0, ZERO_HASH, ZERO_HASH, new bytes(0)
        );
    }

    // -------------------------------------------------------------------------
    // 8. Adversarial fuzz: verify() ALWAYS reverts for any inputs
    // -------------------------------------------------------------------------

    function testVerifyAlwaysReverts(bytes calldata proof, bytes32 seed, uint64 epoch) public {
        bytes32 h0 = keccak256(abi.encode(seed, uint256(0)));
        bytes32 h1 = keccak256(abi.encode(seed, uint256(1)));
        bytes32 h2 = keccak256(abi.encode(seed, uint256(2)));
        bytes32 h3 = keccak256(abi.encode(seed, uint256(3)));
        bytes32 h5 = keccak256(abi.encode(seed, uint256(5)));
        bytes32 h6 = keccak256(abi.encode(seed, uint256(6)));
        vm.expectRevert(
            unicode"PVTHFHE: on-chain verifier is a research surrogate \u2014 do not deploy"
        );
        verifier.verify(h0, h1, h2, h3, epoch, h5, h6, proof);
    }
}
