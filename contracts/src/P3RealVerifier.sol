// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../test/P3StubVerifier.sol";
import "./UltraHonkVerifier.sol";

/// @title P3RealVerifier
/// @notice Real on-chain P3 verifier delegating to UltraHonkVerifier.
contract P3RealVerifier is IP3Verifier {
    UltraHonkVerifier internal immutable _verifier;

    constructor(address ultraHonkVerifier) {
        _verifier = UltraHonkVerifier(ultraHonkVerifier);
    }

    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        override
        returns (bool)
    {
        return _verifier.verify(proof, publicInputs);
    }
}
