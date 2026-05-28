// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import "./P3StubVerifier.sol";
import "../src/P3RealVerifier.sol";
import "../src/UltraHonkVerifier.sol";
import "../src/generated/HonkVerifier.sol";

abstract contract P3RealVerifierBase is Test {
    P3RealVerifier internal verifier;
    P3ProofRouter internal router;
    UltraHonkVerifier internal ultraHonkVerifier;
    HonkVerifier internal honkVerifier;

    bytes internal validProof;
    bytes internal validPublicInputs;

    function setUp() public virtual {
        honkVerifier = new HonkVerifier();
        ultraHonkVerifier = new UltraHonkVerifier(address(honkVerifier));
        verifier = new P3RealVerifier(address(ultraHonkVerifier));
        router = new P3ProofRouter(address(verifier));

        // HonkVerifier expects exactly calculateProofSize(16) * 32 = 7776 bytes.
        // Provide a correctly-sized proof for tests that need a valid-length proof.
        validProof = _buildSizedProof();
        validPublicInputs = _buildPublicInputs(
            keccak256(validProof),
            keccak256("plaintext"),
            keccak256("aggregate_pk"),
            keccak256("dkg_root"),
            uint64(1),
            keccak256("participant_set"),
            keccak256("d_commitment")
        );
    }

    function _buildPublicInputs(
        bytes32 ciphertextHash,
        bytes32 plaintextHash,
        bytes32 aggregatePkHash,
        bytes32 dkgRoot,
        uint64 epoch,
        bytes32 participantSetHash,
        bytes32 dCommitment
    ) internal pure returns (bytes memory pi) {
        pi = new bytes(200);
        assembly {
            let ptr := add(pi, 32)
            mstore(ptr, ciphertextHash)
            mstore(add(ptr, 32), plaintextHash)
            mstore(add(ptr, 64), aggregatePkHash)
            mstore(add(ptr, 96), dkgRoot)
            mstore(add(ptr, 128), shl(192, epoch))
            mstore(add(ptr, 136), participantSetHash)
            mstore(add(ptr, 168), dCommitment)
        }
    }

    /// @dev Build a proof of exactly `calculateProofSize(LOG_N) * 32 = 7776` bytes.
    function _buildSizedProof() internal pure returns (bytes memory p) {
        // 243 field elements × 32 bytes = 7776 bytes (matches LOG_N=16)
        p = new bytes(7776);
    }

    function _copyBytes(bytes memory src) internal pure returns (bytes memory dst) {
        dst = new bytes(src.length);
        for (uint256 i = 0; i < src.length; i++) {
            dst[i] = src[i];
        }
    }
}
