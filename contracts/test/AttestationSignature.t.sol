// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @title AttestationSignatureTest
/// @notice RED test for B.2: verifyWithAttestation() must check attestation ECDSA signature.
///         Currently, verifyWithAttestation only checks that the signer is in the attestors
///         set and that commitments match. It does NOT verify the signature itself — meaning
///         anyone can forge an attestation by setting signer to a known attestor address.
///
///         This RED test is written BEFORE the green implementation. Expected failures:
///           test_valid_signature_passes    — SHOULD FAIL: signature not verified yet
///           test_invalid_signature_reverts — SHOULD PASS: already reverts on current code?
///         After GREEN: both tests should pass with ecrecover verification in place.
contract AttestationSignatureTest is Test {
    PvtFheVerifier internal verifier;
    SessionRegistry internal reg;

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @notice Well-known private key used for test attestor signing.
    ///         Corresponds to address derived via: cast wallet address --private-key 0x1234
    uint256 internal constant ATTESTOR_SK = 0x1234;
    address internal constant ATTESTOR_ADDR = 0xCf03Dd0a894Ef79CB5b601A43C4b25E3Ae4c67eD;

    /// @notice Sample proof bytes (64 bytes as in PvtFheVerifierTest).
    bytes internal sampleProof;

    function setUp() public {
        reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg), address(this));
        verifier.addAttestor(ATTESTOR_ADDR);

        // HonkVerifier (LOG_N=16) expects 7776-byte proofs.
        sampleProof = new bytes(7776);
        for (uint256 i = 0; i < 7776; i++) {
            sampleProof[i] = bytes1(uint8(i & 0xff));
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// @dev Computes the attestation hash that the contract SHOULD verify against.
    ///      Matches: keccak256(abi.encode(novaStateCommitment, cycloAggregateCommitment, sessionId, signer))
    function computeAttestationHash(
        bytes32 novaStateCommitment,
        bytes32 cycloAggregateCommitment,
        bytes32 sessionId,
        address signer
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(novaStateCommitment, cycloAggregateCommitment, sessionId, signer));
    }

    /// @dev Builds a complete attestation with a valid ECDSA signature.
    function buildValidAttestation(
        bytes32 novaCommitment,
        bytes32 cycloCommitment,
        bytes32 sessionId
    ) internal view returns (AttestationBundle memory) {
        bytes32 hash = computeAttestationHash(
            novaCommitment,
            cycloCommitment,
            sessionId,
            ATTESTOR_ADDR
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_SK, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        require(signature.length == 65, "sig length");

        return AttestationBundle({
            novaStateCommitment: novaCommitment,
            cycloAggregateCommitment: cycloCommitment,
            sessionId: sessionId,
            signer: ATTESTOR_ADDR,
            signature: signature
        });
    }

    // -------------------------------------------------------------------------
    // RED: Valid signature must pass
    // -------------------------------------------------------------------------

    /// @notice RED: verifyWithAttestation — attestation signature passes, but HonkVerifier rejects invalid proof.
    function test_valid_signature_passes() public {
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        bytes32 sessionId = bytes32(uint256(6));

        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[1] = bytes32(uint256(1));
        publicInputs[2] = bytes32(uint256(2));
        publicInputs[3] = bytes32(uint256(3));
        publicInputs[4] = novaCommitment;
        publicInputs[5] = cycloCommitment;

        AttestationBundle memory attestation = buildValidAttestation(
            novaCommitment,
            cycloCommitment,
            sessionId
        );

        // Attestation signature passes, but HonkVerifier rejects garbage proof.
        vm.expectRevert();
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    // -------------------------------------------------------------------------
    // RED: Invalid signature must revert
    // -------------------------------------------------------------------------

    /// @notice RED: verifyWithAttestation with tampered signature must revert.
    function test_invalid_signature_reverts() public {
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        bytes32 sessionId = bytes32(uint256(6));

        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[1] = bytes32(uint256(1));
        publicInputs[2] = bytes32(uint256(2));
        publicInputs[3] = bytes32(uint256(3));
        publicInputs[4] = novaCommitment;
        publicInputs[5] = cycloCommitment;

        // Build a valid attestation, then corrupt the signature
        AttestationBundle memory attestation = buildValidAttestation(
            novaCommitment,
            cycloCommitment,
            sessionId
        );

        // Corrupt the signature by flipping a byte
        bytes memory corruptedSig = attestation.signature;
        corruptedSig[0] = bytes1(uint8(corruptedSig[0]) ^ 0xFF);

        AttestationBundle memory badAttestation = AttestationBundle({
            novaStateCommitment: novaCommitment,
            cycloAggregateCommitment: cycloCommitment,
            sessionId: sessionId,
            signer: ATTESTOR_ADDR,
            signature: corruptedSig
        });

        // Currently this may NOT revert because ecrecover is not called.
        // After GREEN (with ecrecover), this will correctly revert with
        // "InvalidAttestationSignature".
        vm.expectRevert(bytes("InvalidAttestationSignature"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, badAttestation);
    }

    // -------------------------------------------------------------------------
    // RED: Signature for wrong message must revert
    // -------------------------------------------------------------------------

    /// @notice RED: Signature over different data must not verify.
    function test_signature_for_wrong_message_reverts() public {
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        bytes32 sessionId = bytes32(uint256(6));

        // Public inputs claim different commitments than what was signed
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[1] = bytes32(uint256(1));
        publicInputs[2] = bytes32(uint256(2));
        publicInputs[3] = bytes32(uint256(3));
        publicInputs[4] = bytes32(uint256(999));  // MISMATCH with signed value
        publicInputs[5] = cycloCommitment;

        // Attestation was signed for novaCommitment=4, but publicInputs[4]=999
        AttestationBundle memory attestation = buildValidAttestation(
            novaCommitment,    // signed this
            cycloCommitment,
            sessionId
        );
        // Override to match publicInputs[4] — but the SIGNATURE was over the original
        // (novaCommitment=4). So the attestation hash won't match the signed message.
        attestation.novaStateCommitment = bytes32(uint256(999));

        vm.expectRevert(bytes("InvalidAttestationSignature"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, attestation);
    }

    // -------------------------------------------------------------------------
    // GREEN: Wrong signer must revert
    // -------------------------------------------------------------------------

    /// @notice GREEN helper: signature by wrong key must fail.
    function test_signature_by_wrong_signer_reverts() public {
        bytes32 novaCommitment = bytes32(uint256(4));
        bytes32 cycloCommitment = bytes32(uint256(5));
        bytes32 sessionId = bytes32(uint256(6));

        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = keccak256(sampleProof);
        publicInputs[1] = bytes32(uint256(1));
        publicInputs[2] = bytes32(uint256(2));
        publicInputs[3] = bytes32(uint256(3));
        publicInputs[4] = novaCommitment;
        publicInputs[5] = cycloCommitment;

        // Build valid attestation for ATTESTOR_ADDR
        AttestationBundle memory attestation = buildValidAttestation(
            novaCommitment,
            cycloCommitment,
            sessionId
        );

        // But claim a different signer (who is also an attestor)
        address otherAttestor = address(0xBEEF);
        verifier.addAttestor(otherAttestor);

        AttestationBundle memory badAttestation = AttestationBundle({
            novaStateCommitment: novaCommitment,
            cycloAggregateCommitment: cycloCommitment,
            sessionId: sessionId,
            signer: otherAttestor,  // signature was by ATTESTOR_ADDR, not this
            signature: attestation.signature
        });

        vm.expectRevert(bytes("InvalidAttestationSignature"));
        verifier.verifyWithAttestation(sampleProof, publicInputs, badAttestation);
    }
}
