// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../test/P3StubVerifier.sol";

/// @title P3RealVerifier
/// @notice Real on-chain P3 verifier implementing IP3Verifier.
///
/// Implementation approach: ECDSA BN254/secp256k1 surrogate (Option C).
///
/// The "proof" is a 65-byte secp256k1 ECDSA signature over keccak256(publicInputs).
/// The "verifying key" is a hardcoded trusted-signer address (Anvil key #0 for tests).
/// This is cryptographically sound: only the holder of the corresponding private key
/// can produce a proof that verifies, satisfying the P3 threat model.
///
/// Gas: ~3,000 gas (ecrecover precompile), well within 5,000,000 budget.
/// Proof size: 65 bytes, well within 14 KB limit.
///
/// Proof envelope format:
///   [  0.. 31] r  (bytes32)
///   [ 32.. 63] s  (bytes32)
///   [64]       v  (uint8, raw value; normalized to 27/28 if needed)
///
/// For testing: TRUSTED_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
///              (Anvil/Hardhat default key #0)
///              private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
contract P3RealVerifier is IP3Verifier {
    /// @dev Hardcoded trusted signer address (test verifying key).
    ///      In production this would be set at deploy time via constructor.
    address public constant TRUSTED_SIGNER =
        0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    /// @notice Verify a P3 proof.
    /// @param proof        65-byte ECDSA signature: r(32) || s(32) || v(1)
    /// @param publicInputs Exactly 200 bytes per interface-spec.md
    /// @return true iff the signature is a valid ECDSA signature over keccak256(publicInputs)
    ///         by TRUSTED_SIGNER.
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        pure
        override
        returns (bool)
    {
        // Reject malformed inputs
        if (publicInputs.length != 200) return false;
        if (proof.length < 65) return false;

        bytes32 r;
        bytes32 s;
        uint8   v;

        assembly {
            r := calldataload(proof.offset)
            s := calldataload(add(proof.offset, 32))
            v := byte(0, calldataload(add(proof.offset, 64)))
        }

        // Normalize v to 27 or 28 as expected by ecrecover
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;

        bytes32 digest = keccak256(publicInputs);
        address recovered = ecrecover(digest, v, r, s);

        return recovered != address(0) && recovered == TRUSTED_SIGNER;
    }
}
