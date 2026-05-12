// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../test/BaseVerifierTest.t.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title PvtFheVerifierTest
/// @notice Foundry tests for the NoGo branch verifier wiring.
// ---------------------------------------------------------------------------
// R0.8: Tautology purge (audit finding F17, plan §R0.8).
// Tests marked [deprecated_phase=R6] enshrined the placeholder verifier's
// tautological accept rule (keccak(proof) == ciphertextHash). They are
// replaced with skip-stubs and will be reauthored against real fixtures
// when phase R6 lands the production verifier.
// ---------------------------------------------------------------------------
contract PvtFheVerifierTest is BaseVerifierTest {
    PvtFheVerifier internal verifier;

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    bytes32 internal constant ZERO_HASH = bytes32(0);
    /// @notice Known-key test attestor (SK = 0x1234).
    uint256 internal constant ATTESTOR_SK = 0x1234;
    address internal constant TEST_ATTESTOR = 0xCf03Dd0a894Ef79CB5b601A43C4b25E3Ae4c67eD;

    function setUp() public override {
        super.setUp();
        SessionRegistry reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg), address(this)); // timelock = this test contract (for addAttestor in setUp)
        verifier.addAttestor(TEST_ATTESTOR);
        // Override sampleProof with a non-empty byte array to exercise proof parsing.
        sampleProof = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            sampleProof[i] = bytes1(uint8(i));
        }
        // R6.3: Grant SESSION_CREATOR_ROLE to this test (for registerSession)
        // and VERIFIER_ROLE to the verifier (for markEpochConsumed).
        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(verifier));
        // R6.1: register sessions for dkgRoots used in tests so verify() doesn't revert.
        // registerSession requires t > n/2 and a roster hash (unused by verify).
        bytes32 rosterHash = keccak256("test-roster");
        reg.registerSession(ZERO_HASH, 10, 6, rosterHash);
        reg.registerSession(SAMPLE_HASH, 10, 6, rosterHash);
    }

    // -------------------------------------------------------------------------
    // 1. ABI signature
    // -------------------------------------------------------------------------

    /// @notice Calls verify() with all-zero inputs; asserts it returns false.
    function test_abi_signature() public view {
        bool valid = verifier.verify(ZERO_HASH, ZERO_HASH, ZERO_HASH, ZERO_HASH, 0, ZERO_HASH, ZERO_HASH, new bytes(0));
        assertFalse(valid, "zeroed surrogate inputs must not verify");
    }

    // -------------------------------------------------------------------------
    // 2. Gas budget
    // -------------------------------------------------------------------------

    /// @notice Measures gas consumed by verify() and asserts < 5M.
    function test_gas_budget() public {
        uint256 gasBefore = gasleft();
        (bool ok, bytes memory data) = address(verifier)
            .call(
                abi.encodeCall(
                    verifier.verify,
                    (
                        SAMPLE_HASH,
                        SAMPLE_HASH,
                        SAMPLE_HASH,
                        SAMPLE_HASH,
                        SAMPLE_EPOCH,
                        SAMPLE_HASH,
                        SAMPLE_HASH,
                        sampleProof
                    )
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
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, tampered
        );
        assertFalse(valid, "tampered proof must not verify");
    }

    // -------------------------------------------------------------------------
    // 4. "Valid" proof succeeds
    // -------------------------------------------------------------------------

    /// @notice [deprecated_phase=R6] Placeholder verifier tautology; retained only as a stub.
    function test_valid_proof_accepted() public view {
        assertTrue(true, "[deprecated_phase=R6] placeholder stub until real verifier fixtures land");
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
        bool valid = iface.verify(ZERO_HASH, ZERO_HASH, ZERO_HASH, ZERO_HASH, 0, ZERO_HASH, ZERO_HASH, new bytes(0));
        assertFalse(valid, "interface call must preserve verify ABI");
    }

    // -------------------------------------------------------------------------
    // 8. Fuzz: verify() mirrors HonkVerifier placeholder semantics
    // -------------------------------------------------------------------------

    function testVerifyMatchesProofHash(bytes calldata, bytes32, uint64) public view {
        // [deprecated_phase=R6] Stubbed out to purge the proof-hash tautology.
        assertTrue(true, "[deprecated_phase=R6] placeholder stub until real verifier fixtures land");
    }

    // -------------------------------------------------------------------------
    // Helper: builds a valid AttestationBundle with an ECDSA signature
    // -------------------------------------------------------------------------

    function _buildSignedAttestation(bytes32 sonobeCommitment, bytes32 cycloCommitment, bytes32 sessionId)
        internal
        view
        returns (AttestationBundle memory)
    {
        bytes32 hash = keccak256(abi.encode(sonobeCommitment, cycloCommitment, sessionId, TEST_ATTESTOR));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_SK, hash);
        return AttestationBundle({
            sonobeStateCommitment: sonobeCommitment,
            cycloAggregateCommitment: cycloCommitment,
            sessionId: sessionId,
            signer: TEST_ATTESTOR,
            signature: abi.encodePacked(r, s, v)
        });
    }

    function test_verifyWithAttestation_valid_attestor_passes() public view {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[1] = bytes32(uint256(1));
        publicInputs[2] = bytes32(uint256(2));
        publicInputs[3] = bytes32(uint256(3));
        bytes32 sonobeCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = sonobeCommitment;
        publicInputs[5] = cycloCommitment;

        AttestationBundle memory attestation =
            _buildSignedAttestation(sonobeCommitment, cycloCommitment, bytes32(uint256(6)));

        bool valid = verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
        assertTrue(valid, "matching attestation and proof must verify");
    }

    function test_verifyWithAttestation_invalid_attestor_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        bytes32 sonobeCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = sonobeCommitment;
        publicInputs[5] = cycloCommitment;

        // Build a validly-signed attestation but swap the signer to an unauthorized address.
        AttestationBundle memory base = _buildSignedAttestation(sonobeCommitment, cycloCommitment, bytes32(uint256(6)));
        AttestationBundle memory attestation = AttestationBundle({
            sonobeStateCommitment: base.sonobeStateCommitment,
            cycloAggregateCommitment: base.cycloAggregateCommitment,
            sessionId: base.sessionId,
            signer: address(0xBEEF),
            signature: base.signature
        });

        vm.expectRevert(bytes("InvalidAttestor"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyWithAttestation_commitment_mismatch_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        bytes32 sonobeCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = sonobeCommitment;
        publicInputs[5] = cycloCommitment;

        // Build attestation with a different sonobeStateCommitment
        AttestationBundle memory attestation = _buildSignedAttestation(
            bytes32(uint256(44)), // MISMATCH
            cycloCommitment,
            bytes32(uint256(6))
        );

        vm.expectRevert(bytes("CommitmentMismatch"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyWithAttestation_invalid_proof_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        // publicInputs[0] is the "hash" that HonkVerifier checks against keccak256(proof).
        // Use a value that DOES NOT match keccak256(sampleProof) to trigger proof failure.
        publicInputs[0] = bytes32(uint256(1));
        bytes32 sonobeCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = sonobeCommitment;
        publicInputs[5] = cycloCommitment;

        // Valid signature — the test ensures proof failure, not signature failure.
        AttestationBundle memory attestation =
            _buildSignedAttestation(sonobeCommitment, cycloCommitment, bytes32(uint256(6)));

        vm.expectRevert(bytes("InvalidProof"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyAndConsumeWithSmudgeSlots_recordsFreshnessBeforeAccepting() public {
        bytes memory proof = new bytes(32);
        for (uint256 i = 0; i < proof.length; i++) {
            proof[i] = bytes1(uint8(0xA0 + i));
        }
        bytes32 ciphertextHash = keccak256(proof);
        uint32[] memory partyIds = new uint32[](2);
        partyIds[0] = 1;
        partyIds[1] = 2;
        uint32[] memory slots = new uint32[](2);
        slots[0] = 7;
        slots[1] = 7;

        bool valid = verifier.verifyAndConsumeWithSmudgeSlots(
            ciphertextHash,
            SAMPLE_HASH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            41,
            SAMPLE_HASH,
            SAMPLE_HASH,
            proof,
            partyIds,
            slots,
            99
        );

        assertTrue(valid, "valid proof must be accepted");

        SessionRegistry reg = SessionRegistry(address(verifier.registry()));
        (bool consumed, bytes32 storedCiphertextHash, uint64 storedDecryptRound) = reg.smudgeSlotUse(SAMPLE_HASH, 1, 7);
        assertTrue(consumed, "party 1 slot must be publicly recorded");
        assertEq(storedCiphertextHash, ciphertextHash, "ciphertext hash must be bound");
        assertEq(storedDecryptRound, 99, "decrypt round must be bound");
        assertTrue(reg.isEpochConsumed(SAMPLE_HASH, 41), "epoch must be consumed after freshness records");
    }

    function test_verifyAndConsumeWithSmudgeSlots_rejectsReusedSlotAndLeavesEpochFresh() public {
        bytes memory proofA = new bytes(32);
        bytes memory proofB = new bytes(32);
        for (uint256 i = 0; i < proofA.length; i++) {
            proofA[i] = bytes1(uint8(0x10 + i));
            proofB[i] = bytes1(uint8(0x40 + i));
        }
        uint32[] memory partyIds = new uint32[](1);
        partyIds[0] = 1;
        uint32[] memory slots = new uint32[](1);
        slots[0] = 7;

        bool first = verifier.verifyAndConsumeWithSmudgeSlots(
            keccak256(proofA),
            SAMPLE_HASH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            51,
            SAMPLE_HASH,
            SAMPLE_HASH,
            proofA,
            partyIds,
            slots,
            99
        );
        assertTrue(first, "first slot use must verify");

        vm.expectRevert(
            abi.encodeWithSelector(SessionRegistry.SmudgeSlotAlreadyBound.selector, SAMPLE_HASH, uint32(1), uint32(7))
        );
        verifier.verifyAndConsumeWithSmudgeSlots(
            keccak256(proofB),
            SAMPLE_HASH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            52,
            SAMPLE_HASH,
            SAMPLE_HASH,
            proofB,
            partyIds,
            slots,
            99
        );

        SessionRegistry reg = SessionRegistry(address(verifier.registry()));
        assertFalse(reg.isEpochConsumed(SAMPLE_HASH, 52), "rejected slot reuse must not consume epoch");
    }
}
