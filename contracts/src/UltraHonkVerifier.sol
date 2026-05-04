// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./generated/HonkVerifier.sol";
import "../test/P3StubVerifier.sol";

/// @title UltraHonkVerifier
/// @notice Adapts the frozen IP3Verifier interface to the HonkVerifier prototype.
/// @dev Barretenberg `write_solidity_verifier` currently fails for this VK shape:
///      `verification key has wrong size: expected 1888, got 3680`.
///      This wrapper preserves the contract surface while delegating to the
///      research prototype HonkVerifier until the BB CLI supports this VK format.
contract UltraHonkVerifier is IP3Verifier {
    HonkVerifier internal immutable _honk;

    constructor(address honkVerifier) {
        _honk = HonkVerifier(honkVerifier);
    }

    /// @notice Parse the canonical 200-byte public input blob into 7 field slots.
    /// Layout:
    ///   [  0.. 31] ciphertext_hash
    ///   [ 32.. 63] plaintext_hash
    ///   [ 64.. 95] aggregate_pk_hash
    ///   [ 96..127] dkg_root
    ///   [128..135] epoch (8-byte big-endian uint64)
    ///   [136..167] participant_set_hash
    ///   [168..199] d_commitment
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 200) {
            return false;
        }

        bytes32[] memory inputs = new bytes32[](7);
        assembly {
            let pi := publicInputs.offset
            mstore(add(inputs, 0x20), calldataload(pi))
            mstore(add(inputs, 0x40), calldataload(add(pi, 32)))
            mstore(add(inputs, 0x60), calldataload(add(pi, 64)))
            mstore(add(inputs, 0x80), calldataload(add(pi, 96)))
            mstore(add(inputs, 0xa0), shr(192, calldataload(add(pi, 128))))
            mstore(add(inputs, 0xc0), calldataload(add(pi, 136)))
            mstore(add(inputs, 0xe0), calldataload(add(pi, 168)))
        }

        return _honk.verify(proof, inputs);
    }
}
