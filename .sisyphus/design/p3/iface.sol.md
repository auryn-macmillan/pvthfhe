# P3 Solidity ABI Sketch

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPvthfheP3Verifier {
    function verify(bytes calldata proof, bytes calldata publicInputs)
        external
        view
        returns (bool);
}

interface IPvthfheP3BlameRouterEvents {
    event VerificationMalformedCalldata(
        bytes32 indexed publicInputsHash,
        bytes32 indexed proofHash,
        bytes32 indexed routeId,
        uint8 reasonCode
    );

    event VerificationFailed(
        bytes32 indexed dkgRoot,
        uint64 indexed epoch,
        bytes32 indexed participantSetHash,
        bytes32 routeId,
        uint8 reasonCode,
        bytes32 publicInputsHash,
        bytes32 proofHash
    );

    event PublicBlameRouted(
        bytes32 indexed dkgRoot,
        uint64 indexed epoch,
        bytes32 indexed participantSetHash,
        address router,
        bytes32 blameRef,
        uint8 reasonCode
    );
}
```
