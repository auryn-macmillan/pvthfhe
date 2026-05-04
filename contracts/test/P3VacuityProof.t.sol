// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

/// @title P3VacuityProof
/// @notice Regression guard: fabricated claims no longer pass after removing
///         the trusted-signer surrogate and delegating to UltraHonkVerifier.
contract P3VacuityProof is P3RealVerifierBase {

    // -------------------------------------------------------------------------
    // Vacuity falsification test
    // -------------------------------------------------------------------------

    /// @notice Fabricated claims without a matching proof hash must be rejected.
    function testFabricatedClaimIsRejected() public view {
        bytes memory falsePi = _buildPublicInputs(
            keccak256("FAKE_CIPHERTEXT_THAT_NEVER_EXISTED"),
            keccak256("FAKE_PLAINTEXT_999999"),
            keccak256("FAKE_AGGREGATE_PK"),
            keccak256("FAKE_DKG_ROOT"),
            uint64(999_999),
            keccak256("FAKE_PARTICIPANT_SET"),
            keccak256("FAKE_D_COMMITMENT")
        );

        bytes memory falseProof = abi.encodePacked("fabricated-proof");
        bool accepted = verifier.verify(falseProof, falsePi);

        assertFalse(
            accepted,
            "fabricated FHE claim must be rejected once trusted-signer surrogate is removed"
        );
    }
}
