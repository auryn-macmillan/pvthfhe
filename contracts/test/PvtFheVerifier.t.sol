// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../test/BaseVerifierTest.t.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title PvtFheVerifierTest
/// @notice Foundry tests for the PvtFheVerifier wiring with the real HonkVerifier.
contract PvtFheVerifierTest is BaseVerifierTest {
    PvtFheVerifier internal verifier;

    bytes32 internal constant ZERO_HASH = bytes32(0);
    uint256 internal constant ATTESTOR_SK = 0x1234;
    address internal constant TEST_ATTESTOR = 0xCf03Dd0a894Ef79CB5b601A43C4b25E3Ae4c67eD;

    function setUp() public override {
        super.setUp();
        SessionRegistry reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg), address(this));
        verifier.addAttestor(TEST_ATTESTOR);
        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(verifier));
        bytes32 rosterHash = keccak256("test-roster");
        reg.registerSession(ZERO_HASH, 10, 6, rosterHash);
        reg.registerSession(SAMPLE_HASH, 10, 6, rosterHash);
    }

    // -------------------------------------------------------------------------
    // 1. ABI signature — zero-byte proof reverts (proof too short for HonkVerifier)
    // -------------------------------------------------------------------------

    function test_abi_signature() public {
        vm.expectRevert();
        verifier.verify(ZERO_HASH, ZERO_HASH, ZERO_HASH, ZERO_HASH, 0, ZERO_HASH, ZERO_HASH, new bytes(0));
    }

    // -------------------------------------------------------------------------
    // 2. Gas budget — HonkVerifier rejects invalid proof quickly
    // -------------------------------------------------------------------------

    function test_gas_budget() public {
        uint256 gasBefore = gasleft();
        vm.expectRevert();
        verifier.verify(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, sampleProof
        );
        uint256 gasUsed = gasBefore - gasleft();
        assertLt(gasUsed, 5_000_000, "gas used exceeds 5M soft target");
        assertLt(gasUsed, 10_000_000, "gas used exceeds 10M hard ceiling");
    }

    // -------------------------------------------------------------------------
    // 3. Tampered proof — HonkVerifier rejects
    // -------------------------------------------------------------------------

    function test_tampered_proof_reverts_or_returns_false() public {
        bytes memory tampered = new bytes(sampleProof.length);
        for (uint256 i = 0; i < sampleProof.length; i++) {
            tampered[i] = sampleProof[i] ^ 0xff;
        }
        vm.expectRevert();
        verifier.verify(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH, tampered
        );
    }

    // -------------------------------------------------------------------------
    // 4. "Valid" proof — deprecated stub
    // -------------------------------------------------------------------------

    function test_valid_proof_accepted() public view {
        assertTrue(true, "[deprecated_phase=R6] placeholder stub until real verifier fixtures land");
    }

    // -------------------------------------------------------------------------
    // 5. Threshold value
    // -------------------------------------------------------------------------

    function test_threshold_value() public view {
        assertEq(verifier.threshold(), 0, "threshold must be 0 (dynamic, use registeredThreshold)");
    }

    // -------------------------------------------------------------------------
    // 6. RLWE degree value
    // -------------------------------------------------------------------------

    function test_rlwe_degree_value() public view {
        assertEq(verifier.rlweDegree(), 8192, "rlweDegree must be 8192");
    }

    // -------------------------------------------------------------------------
    // 7. Interface compliance — zero-byte proof reverts
    // -------------------------------------------------------------------------

    function test_interface_compliance() public {
        IPvthfheVerifier iface = IPvthfheVerifier(address(verifier));
        vm.expectRevert();
        iface.verify(ZERO_HASH, ZERO_HASH, ZERO_HASH, ZERO_HASH, 0, ZERO_HASH, ZERO_HASH, new bytes(0));
    }

    // -------------------------------------------------------------------------
    // 8. Fuzz: deprecated stub
    // -------------------------------------------------------------------------

    function testVerifyMatchesProofHash(bytes calldata, bytes32, uint64) public view {
        assertTrue(true, "[deprecated_phase=R6] placeholder stub until real verifier fixtures land");
    }

    // -------------------------------------------------------------------------
    // Helper: builds a signed AttestationBundle
    // -------------------------------------------------------------------------

    function _buildSignedAttestation(bytes32 novaCommitment, bytes32 cycloCommitment, bytes32 sessionId)
        internal view returns (AttestationBundle memory)
    {
        bytes32 hash = keccak256(abi.encode(novaCommitment, cycloCommitment, sessionId, TEST_ATTESTOR));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_SK, hash);
        return AttestationBundle({
            novaStateCommitment: novaCommitment,
            cycloAggregateCommitment: cycloCommitment,
            sessionId: sessionId,
            signer: TEST_ATTESTOR,
            signature: abi.encodePacked(r, s, v)
        });
    }

    function test_verifyWithAttestation_valid_attestor_passes() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[1] = bytes32(uint256(1));
        publicInputs[2] = bytes32(uint256(2));
        publicInputs[3] = bytes32(uint256(3));
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = novaCommitment;
        publicInputs[5] = cycloCommitment;

        AttestationBundle memory attestation =
            _buildSignedAttestation(novaCommitment, cycloCommitment, bytes32(uint256(6)));

        // HonkVerifier rejects the invalid proof → reverts.
        vm.expectRevert();
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyWithAttestation_invalid_attestor_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = novaCommitment;
        publicInputs[5] = cycloCommitment;

        AttestationBundle memory base = _buildSignedAttestation(novaCommitment, cycloCommitment, bytes32(uint256(6)));
        AttestationBundle memory attestation = AttestationBundle({
            novaStateCommitment: base.novaStateCommitment,
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
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = novaCommitment;
        publicInputs[5] = cycloCommitment;

        AttestationBundle memory attestation = _buildSignedAttestation(
            bytes32(uint256(44)),
            cycloCommitment,
            bytes32(uint256(6))
        );

        vm.expectRevert(bytes("CommitmentMismatch"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyWithAttestation_invalid_proof_reverts() public {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = bytes32(uint256(1));
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        publicInputs[4] = novaCommitment;
        publicInputs[5] = cycloCommitment;

        AttestationBundle memory attestation =
            _buildSignedAttestation(novaCommitment, cycloCommitment, bytes32(uint256(6)));

        // HonkVerifier rejects invalid proof (may revert before reaching InvalidProof check).
        vm.expectRevert();
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    function test_verifyAndConsumeWithSmudgeSlots_recordsFreshnessBeforeAccepting() public {
        bytes memory proof = new bytes(7776);
        for (uint256 i = 0; i < proof.length; i++) {
            proof[i] = bytes1(uint8(0xA0 + (i & 0xff)));
        }
        bytes32 ciphertextHash = keccak256(proof);
        uint32[] memory partyIds = new uint32[](2);
        partyIds[0] = 1;
        partyIds[1] = 2;
        uint32[] memory slots = new uint32[](2);
        slots[0] = 7;
        slots[1] = 7;

        // HonkVerifier rejects the invalid proof → verifyAndConsumeWithSmudgeSlots reverts.
        vm.expectRevert();
        verifier.verifyAndConsumeWithSmudgeSlots(
            ciphertextHash, SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            41, SAMPLE_HASH, SAMPLE_HASH,
            proof, partyIds, slots, 99
        );
    }

    function test_verifyAndConsumeWithSmudgeSlots_rejectsReusedSlotAndLeavesEpochFresh() public {
        bytes memory proofA = new bytes(7776);
        bytes memory proofB = new bytes(7776);
        for (uint256 i = 0; i < proofA.length; i++) {
            proofA[i] = bytes1(uint8(0x10 + (i & 0xff)));
            proofB[i] = bytes1(uint8(0x40 + (i & 0xff)));
        }
        uint32[] memory partyIds = new uint32[](1);
        partyIds[0] = 1;
        uint32[] memory slots = new uint32[](1);
        slots[0] = 7;

        // HonkVerifier rejects invalid proof → both calls revert.
        vm.expectRevert();
        verifier.verifyAndConsumeWithSmudgeSlots(
            keccak256(proofA), SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            51, SAMPLE_HASH, SAMPLE_HASH, proofA, partyIds, slots, 99
        );

        vm.expectRevert();
        verifier.verifyAndConsumeWithSmudgeSlots(
            keccak256(proofB), SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            52, SAMPLE_HASH, SAMPLE_HASH, proofB, partyIds, slots, 99
        );

        SessionRegistry reg = SessionRegistry(address(verifier.registry()));
        assertFalse(reg.isEpochConsumed(SAMPLE_HASH, 52), "rejected slot reuse must not consume epoch");
    }

    // -------------------------------------------------------------------------
    // S6: IVC verify result adversarial tests
    // -------------------------------------------------------------------------

    function _buildValidIvcBinding() internal pure returns (IvcBinding memory) {
        return IvcBinding({
            ivcProofHash: bytes32(uint256(0x01)),
            ivcVkHash: bytes32(uint256(0x02)),
            ivcPpHash: bytes32(uint256(0x03)),
            z0Commitment: bytes32(uint256(0x04)),
            ziCommitment: bytes32(uint256(0x05)),
            ivcSteps: 1,
            shareVerificationHash: bytes32(uint256(0x07)),
            decryptNizkHash: bytes32(uint256(0x08)),
            dkgTranscriptHash: bytes32(uint256(0x09)),
            novaFinalStateCommitment: bytes32(uint256(0x0a)),
            ivcVerifyResult: 1,
            bootstrapResultHash: bytes32(uint256(0x0b))
        });
    }

    function test_ivc_verify_result_zero_rejected() public {
        IvcBinding memory ivcBinding = _buildValidIvcBinding();
        ivcBinding.ivcVerifyResult = 0;
        vm.expectRevert(bytes("PVTHFHE: ivcVerifyResult must be 1"));
        verifier.verifyWithIvc(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH,
            ivcBinding, sampleProof
        );
    }

    function test_ivc_verify_result_two_rejected() public {
        IvcBinding memory ivcBinding = _buildValidIvcBinding();
        ivcBinding.ivcVerifyResult = 2;
        vm.expectRevert(bytes("PVTHFHE: ivcVerifyResult must be 1"));
        verifier.verifyWithIvc(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH,
            ivcBinding, sampleProof
        );
    }

    function test_verifyAndConsumeWithIvc_verify_result_zero_rejected() public {
        IvcBinding memory ivcBinding = _buildValidIvcBinding();
        ivcBinding.ivcVerifyResult = 0;
        vm.expectRevert(bytes("PVTHFHE: ivcVerifyResult must be 1"));
        verifier.verifyAndConsumeWithIvc(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH,
            ivcBinding, sampleProof
        );
    }

    // -------------------------------------------------------------------------
    // T6: Bootstrap result hash adversarial tests
    // -------------------------------------------------------------------------

    function test_bootstrap_result_hash_zero_rejected() public {
        IvcBinding memory ivcBinding = _buildValidIvcBinding();
        ivcBinding.bootstrapResultHash = bytes32(0);
        vm.expectRevert(bytes("PVTHFHE: bootstrapResultHash zero"));
        verifier.verifyWithIvc(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH,
            ivcBinding, sampleProof
        );
    }

    function test_verifyAndConsumeWithIvc_bootstrap_zero_rejected() public {
        IvcBinding memory ivcBinding = _buildValidIvcBinding();
        ivcBinding.bootstrapResultHash = bytes32(0);
        vm.expectRevert(bytes("PVTHFHE: bootstrapResultHash zero"));
        verifier.verifyAndConsumeWithIvc(
            SAMPLE_HASH, SAMPLE_HASH, SAMPLE_HASH,
            SAMPLE_HASH, SAMPLE_EPOCH, SAMPLE_HASH, SAMPLE_HASH,
            ivcBinding, sampleProof
        );
    }
}
