// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IP3Verifier
/// @notice Frozen P3 on-chain verifier interface (D.D.1).
///         `proof`        — opaque backend envelope (≤14 KB)
///         `publicInputs` — exactly 200 bytes: 6×32-byte hashes + 8-byte epoch
interface IP3Verifier {
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        returns (bool);
}
