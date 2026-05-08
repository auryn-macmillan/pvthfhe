// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../test/BaseVerifierTest.t.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title PvtFheVerifierTest
/// @notice Foundry tests for the NoGo branch verifier wiring.
contract PvtFheVerifierTest is BaseVerifierTest {
    PvtFheVerifier internal verifier;

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    bytes32 internal constant ZERO_HASH = bytes32(0);
    address internal constant TEST_ATTESTOR = address(0xA7713570);

    function setUp() public override {
        super.setUp();
        SessionRegistry reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg));
        verifier.addAttestor(TEST_ATTESTOR);
        // Override sampleProof with a non-empty byte array to exercise proof parsing.
        sampleProof = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            sampleProof[i] = bytes1(uint8(i));
        }
    }

    // -------------------------------------------------------------------------
    // 1. ABI signature
    // -------------------------------------------------------------------------

    /// @notice Calls verify() with all-zero inputs; asserts it returns false.
    function test_abi_signature() public view {
        bool valid = verifier.verify(
            ZERO_HASH,
            ZERO_HASH,
            ZERO_HASH,
            ZERO_HASH,
            0,
            ZERO_HASH,
            ZERO_HASH,
            new bytes(0)
        );
        assertFalse(valid, "zeroed surrogate inputs must not verify");
    }

    // -------------------------------------------------------------------------
    // 2. Gas budget
    // -------------------------------------------------------------------------

    /// @notice Measures gas consumed by verify() and asserts < 5M.
    function test_gas_budget() public {
        uint256 gasBefore = gasleft();
        (bool ok, bytes memory data) = address(verifier).call(
            abi.encodeCall(
                verifier.verify,
                (SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
                 SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, sampleProof)
            )
        );
        uint256 gasUsed = gasBefore - gasleft();
        assertTrue(ok, "call must not revert");
        assertFalse(abi.decode(data, (bool)), "placeholder proof should not verify");
        assertLt(gasUsed, 5_000_000, "gas used exceeds 5M soft target");
        assertLt(gasUsed, 10_000_000, "gas used exceeds 10M hard ceiling");
    }

    // -------------------------------------------------------------------------
    // 3. Tampered proof returns false
    // -------------------------------------------------------------------------

    /// @notice Tampered proof bytes must return false.
    function test_tampered_proof_reverts_or_returns_false() public view {
        bytes memory tampered = new bytes(sampleProof.length);
        for (uint256 i = 0; i < sampleProof.length; i++) {
            tampered[i] = sampleProof[i] ^ 0xff;
        }

        bool valid = verifier.verify(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, tampered
        );
        assertFalse(valid, "tampered proof must not verify");
    }

    // -------------------------------------------------------------------------
    // 4. "Valid" proof succeeds
    // -------------------------------------------------------------------------

    /// @notice The placeholder verifier accepts proofs whose keccak matches ciphertextHash.
    function test_valid_proof_accepted() public view {
        bool valid = verifier.verify(
            keccak256(sampleProof), SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, sampleProof
        );
        assertTrue(valid, "proof hash wired through verify() must verify");
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
    // 7. Interface compliance
    // -------------------------------------------------------------------------

    /// @notice Verifies that PvtFheVerifier implements IPvthfheVerifier via cast,
    ///         and that verify() remains callable through the interface.
    function test_interface_compliance() public view {
        IPvthfheVerifier iface = IPvthfheVerifier(address(verifier));
        bool valid = iface.verify(
            ZERO_HASH, ZERO_HASH, ZERO_HASH, ZERO_HASH,
            0, ZERO_HASH, ZERO_HASH, new bytes(0)
        );
        assertFalse(valid, "interface call must preserve verify ABI");
    }

    // -------------------------------------------------------------------------
    // 8. Fuzz: verify() mirrors HonkVerifier placeholder semantics
    // -------------------------------------------------------------------------

    function testVerifyMatchesProofHash(bytes calldata proof, bytes32 seed, uint64 epoch) public view {
        bytes32 h0 = keccak256(abi.encode(seed, uint256(0)));
        bytes32 h1 = keccak256(abi.encode(seed, uint256(1)));
        bytes32 h2 = keccak256(abi.encode(seed, uint256(2)));
        bytes32 h3 = keccak256(abi.encode(seed, uint256(3)));
        bytes32 h5 = keccak256(abi.encode(seed, uint256(5)));
        bytes32 h6 = keccak256(abi.encode(seed, uint256(6)));

        bool valid = verifier.verify(h0, h1, h2, h3, epoch, h5, h6, proof);
        assertEq(valid, h0 == keccak256(proof), "verify() must delegate to HonkVerifier");
    }

    function test_verifyWithAttestation_valid_attestor_passes() public view {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[1] = bytes32(uint256(1));
        publicInputs[2] = bytes32(uint256(2));
        publicInputs[3] = bytes32(uint256(3));
        publicInputs[4] = bytes32(uint256(4));
        publicInputs[5] = bytes32(uint256(5));

        AttestationBundle memory attestation = AttestationBundle({
            sonobeStateCommitment: publicInputs[4],
            cycloAggregateCommitment: publicInputs[5],
            sessionId: bytes32(uint256(6)),
            signer: TEST_ATTESTOR,
            signature: hex"1234"
        });

        bool valid = verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
        assertTrue(valid, "matching attestation and proof must verify");
    }

    function test_verifyWithAttestation_invalid_attestor_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[4] = bytes32(uint256(4));
        publicInputs[5] = bytes32(uint256(5));

        AttestationBundle memory attestation = AttestationBundle({
            sonobeStateCommitment: publicInputs[4],
            cycloAggregateCommitment: publicInputs[5],
            sessionId: bytes32(uint256(6)),
            signer: address(0xBEEF),
            signature: hex"1234"
        });

        vm.expectRevert(bytes("InvalidAttestor"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyWithAttestation_commitment_mismatch_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[4] = bytes32(uint256(4));
        publicInputs[5] = bytes32(uint256(5));

        AttestationBundle memory attestation = AttestationBundle({
            sonobeStateCommitment: bytes32(uint256(44)),
            cycloAggregateCommitment: publicInputs[5],
            sessionId: bytes32(uint256(6)),
            signer: TEST_ATTESTOR,
            signature: hex"1234"
        });

        vm.expectRevert(bytes("CommitmentMismatch"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyWithAttestation_invalid_proof_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = bytes32(uint256(1));
        publicInputs[4] = bytes32(uint256(4));
        publicInputs[5] = bytes32(uint256(5));

        AttestationBundle memory attestation = AttestationBundle({
            sonobeStateCommitment: publicInputs[4],
            cycloAggregateCommitment: publicInputs[5],
            sessionId: bytes32(uint256(6)),
            signer: TEST_ATTESTOR,
            signature: hex"1234"
        });

        vm.expectRevert(bytes("InvalidProof"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }
}
