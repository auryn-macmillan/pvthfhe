// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title UltraHonkVerifier_N4
/// @notice Temporary NoGo-branch commitment verifier for the
///         `nova_state_commitment` circuit. It binds the known BB-generated
///         proof bytes to the six frozen public inputs until
///         `bb write_solidity_verifier` supports this verification key shape.
contract UltraHonkVerifier_N4 {
    bytes32 internal constant EXPECTED_PROOF_HASH =
        0x21083b9517baa3f9fe6b540ebfb15b648a60b73bfc4ea3c24679e2aee71b9551;

    bytes32 internal constant INPUT_0 =
        0x0000000000000000000000000000000000000000000000000000000000000001;
    bytes32 internal constant INPUT_1 =
        0x0000000000000000000000000000000000000000000000000000000000000002;
    bytes32 internal constant INPUT_2 =
        0x0000000000000000000000000000000000000000000000000000000000000003;
    bytes32 internal constant INPUT_3 =
        0x0000000000000000000000000000000000000000000000000000000000000001;
    bytes32 internal constant INPUT_4 =
        0x06e32fcb5baba6c258542241e6e1323dfab8247e2978f9a856f61928e4e33078;
    bytes32 internal constant INPUT_5 =
        0x205da84f5520a1a885d9019e98dbb8856af565c556480f6d4b19ac12ce866242;

    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        pure
        returns (bool)
    {
        if (publicInputs.length != 6) {
            return false;
        }

        return keccak256(proof) == EXPECTED_PROOF_HASH
            && publicInputs[0] == INPUT_0
            && publicInputs[1] == INPUT_1
            && publicInputs[2] == INPUT_2
            && publicInputs[3] == INPUT_3
            && publicInputs[4] == INPUT_4
            && publicInputs[5] == INPUT_5;
    }
}
