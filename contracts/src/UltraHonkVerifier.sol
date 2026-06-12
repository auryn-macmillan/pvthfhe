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

    /// @notice Parse the canonical 232-byte public input blob into 8 field slots.
    /// Layout:
    ///   [  0.. 31] ciphertext_hash
    ///   [ 32.. 63] plaintext_hash
    ///   [ 64.. 95] aggregate_pk_hash
    ///   [ 96..127] dkg_root
    ///   [128..159] session_id          ← GAP-1: 8th field
    ///   [160..167] epoch (8-byte big-endian uint64)
    ///   [168..199] participant_set_hash
    ///   [200..231] d_commitment
    ///
    /// GAP-1 FIXED (MPC-AUDIT-2026-06-12): session_id is now the 8th public
    /// input, bound into the UltraHonk transcript and the in-circuit Fiat-Shamir
    /// challenge derivation.  Requires VK recompilation.
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 232) {
            return false;
        }

        bytes32[] memory inputs = new bytes32[](8);
        assembly {
            let pi := publicInputs.offset
            mstore(add(inputs, 0x20), calldataload(pi))           // ciphertext_hash   [0..31]
            mstore(add(inputs, 0x40), calldataload(add(pi, 32)))   // plaintext_hash     [32..63]
            mstore(add(inputs, 0x60), calldataload(add(pi, 64)))   // aggregate_pk_hash  [64..95]
            mstore(add(inputs, 0x80), calldataload(add(pi, 96)))   // dkg_root           [96..127]
            mstore(add(inputs, 0xa0), calldataload(add(pi, 128)))  // session_id         [128..159] GAP-1
            mstore(add(inputs, 0xc0), shr(192, calldataload(add(pi, 160)))) // epoch     [160..167]
            mstore(add(inputs, 0xe0), calldataload(add(pi, 168)))  // participant_set_hash [168..199]
            mstore(add(inputs, 0x100), calldataload(add(pi, 200))) // d_commitment       [200..231]
        }

        return _honk.verify(proof, inputs);
    }
}
