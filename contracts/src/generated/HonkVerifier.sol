// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract HonkVerifier {
    /// @notice Research keccak prototype kept for existing forge fixtures.
    /// @dev `bb write_solidity_verifier` is blocked for `sonobe_state_commitment`
    ///      on BB 5.0.0-nightly.20260324 with:
    ///      `verification key has wrong size: expected 1888, got 3680`.
    ///      The N4' placeholder lives in `generated/UltraHonkVerifier.sol` until
    ///      a BB upgrade or circuit restructuring unblocks real generation.
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external pure returns (bool) {
        require(publicInputs.length >= 1, "PVTHFHE: malformed proof");
        return keccak256(proof) == publicInputs[0];
    }
}
