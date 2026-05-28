// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

/// @title P3VacuityProof
/// @notice Regression guard: fabricated claims are rejected by the real HonkVerifier.
contract P3VacuityProof is P3RealVerifierBase {

    function testFabricatedClaimIsRejected() public {
        bytes memory falsePi = _buildPublicInputs(
            keccak256("FAKE_CIPHERTEXT_THAT_NEVER_EXISTED"),
            keccak256("FAKE_PLAINTEXT_999999"),
            keccak256("FAKE_AGGREGATE_PK"),
            keccak256("FAKE_DKG_ROOT"),
            uint64(999_999),
            keccak256("FAKE_PARTICIPANT_SET"),
            keccak256("FAKE_D_COMMITMENT")
        );

        // Short fabricated proof → HonkVerifier reverts on length.
        vm.expectRevert();
        verifier.verify(new bytes(16), falsePi);
    }
}
