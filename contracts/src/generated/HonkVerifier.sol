// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HonkVerifier
/// @notice Placeholder Honk verifier for the PVTHFHE on-chain verifier.
/// @dev R6.2 status (2026-05-09):
///      `bb write_solidity_verifier` is BLOCKED on BB 5.0.0-nightly.20260324.
///      All circuits (sonobe_state_commitment, share_wf, decrypt_share,
///      aggregator_final) produce 3680-byte VKs, but the Solidity verifier
///      generator expects 1888-byte VKs. This is a known BB version limitation.
///      The canonical Noir+BB flow (nargo execute → bb write_vk → bb prove →
///      bb verify) completes successfully; only the Solidity export is blocked.
///      This placeholder will be replaced with a real BB-generated verifier
///      when a compatible BB version is available or the VK shape is adjusted.
contract HonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external pure returns (bool) {
        require(publicInputs.length >= 1, "PVTHFHE: malformed proof");
        return keccak256(proof) == publicInputs[0];
    }
}
