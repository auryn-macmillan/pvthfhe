// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "./P3StubVerifier.sol";
import "../src/P3RealVerifier.sol";

/// @title P3VacuityProof
/// @notice AUDIT EVIDENCE — demonstrates that P3RealVerifier is a vacuous
///         trusted-signer authenticator: it accepts ANY false FHE claim so
///         long as the trusted signer signs the publicInputs hash.
///
/// Vacuity proof: the verifier checks NOTHING about:
///   - FHE ciphertext correctness
///   - Threshold reconstruction validity
///   - NIZK / LatticeFold+ proof validity
///   - Consistency between ciphertext_hash and plaintext_hash
///   - Participant set honesty
///
/// All it checks: ECDSA signature by TRUSTED_SIGNER over keccak256(publicInputs).
/// Any attacker who controls (or colludes with) TRUSTED_SIGNER can prove ANY result.
contract P3VacuityProof is Test {
    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    P3RealVerifier internal verifier;

    /// @dev Anvil key #0 — the hardcoded TRUSTED_SIGNER private key.
    uint256 internal constant TRUSTED_SIGNER_PK =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function setUp() public {
        verifier = new P3RealVerifier();
    }

    // -------------------------------------------------------------------------
    // Vacuity falsification test
    // -------------------------------------------------------------------------

    /// @notice The trusted signer can attest to a completely fabricated FHE result.
    ///
    /// Attack scenario:
    ///   1. Adversary (holding TRUSTED_SIGNER key) fabricates public inputs
    ///      claiming that ciphertext Enc(0) decrypts to plaintext "999999" —
    ///      a plaintext that has never been computed by the threshold parties.
    ///   2. Adversary signs keccak256(falsePi) with the trusted key.
    ///   3. P3RealVerifier.verify() returns TRUE.
    ///
    /// This PASSES — and that is the vulnerability.
    function testVacuousVerifierAcceptsFalseClaim() public view {
        // Step 1: craft completely fabricated (attacker-chosen) public inputs.
        // None of these hashes correspond to any real FHE computation.
        bytes memory falsePi = _buildPublicInputs(
            keccak256("FAKE_CIPHERTEXT_THAT_NEVER_EXISTED"),
            keccak256("FAKE_PLAINTEXT_999999"),
            keccak256("FAKE_AGGREGATE_PK"),
            keccak256("FAKE_DKG_ROOT"),
            uint64(999_999),
            keccak256("FAKE_PARTICIPANT_SET"),
            keccak256("FAKE_D_COMMITMENT")
        );

        // Step 2: sign the fabricated publicInputs — exactly what the verifier checks.
        bytes32 digest = keccak256(falsePi);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TRUSTED_SIGNER_PK, digest);
        bytes memory falseProof = abi.encodePacked(r, s, v);

        // Step 3: the verifier accepts the fabricated claim.
        bool accepted = verifier.verify(falseProof, falsePi);

        // This assertion PASSES — that IS the bug.
        // The verifier cannot distinguish a false claim from a true one.
        assertTrue(
            accepted,
            "VACUITY: verifier accepted fabricated FHE result; no FHE correctness verified"
        );
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    /// @dev Build a canonical 200-byte public-inputs blob (matches interface-spec).
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
            mstore(add(ptr,  32), plaintextHash)
            mstore(add(ptr,  64), aggregatePkHash)
            mstore(add(ptr,  96), dkgRoot)
            // epoch at offset 128, 8 bytes — right-aligned uint64
            mstore(add(ptr, 128), shl(192, epoch))
            mstore(add(ptr, 136), participantSetHash)
            mstore(add(ptr, 168), dCommitment)
        }
    }
}
