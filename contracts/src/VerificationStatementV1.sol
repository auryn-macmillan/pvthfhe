// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PoseidonBn254.sol";

/// @title VerificationStatementV1
/// @notice Canonical Phase-1 verification statement encoding for Solidity parity with Rust and Noir.
library VerificationStatementV1 {
    uint256 internal constant DOMAIN_FIELD =
        0x707674686668652d766572696669636174696f6e2d73746d742d7631;
    uint256 internal constant SCHEMA_VERSION = 1;
    uint256 internal constant FIELD_COUNT = 19;
    uint256 internal constant PREIMAGE_LEN = 76;

    struct Statement {
        uint32 protocolVersion;
        bytes32 contextId;
        bytes32 dkgRoot;
        uint64 epoch;
        bytes32 participantSetHash;
        bytes32 aggregatePkHash;
        bytes32 ciphertextHash;
        bytes32 plaintextHash;
        bytes32 dCommitment;
        bytes32 c5ProofRoot;
        bytes32 c6ProofSetRoot;
        bytes32 cycloAccumulatorRoot;
        bytes32 ivcVkHash;
        bytes32 ivcPpHash;
        bytes32 ivcProofHash;
        bytes32 z0Commitment;
        bytes32 ziCommitment;
        uint64 ivcSteps;
        bytes32 bootstrapResultHash;
    }

    function computeStatementHash(Statement memory statement) internal pure returns (uint256) {
        return PoseidonBn254.sponge(poseidonPreimage(statement));
    }

    function computeStatementHashBytes32(Statement memory statement) internal pure returns (bytes32) {
        return bytes32(computeStatementHash(statement));
    }

    function poseidonPreimage(Statement memory statement) internal pure returns (uint256[76] memory out) {
        uint256 offset;
        out[offset++] = DOMAIN_FIELD;
        out[offset++] = SCHEMA_VERSION;
        out[offset++] = FIELD_COUNT;

        offset = _pushNumeric(out, offset, 1, 4, statement.protocolVersion);
        offset = _pushBytes32(out, offset, 2, statement.contextId);
        offset = _pushBytes32(out, offset, 3, statement.dkgRoot);
        offset = _pushNumeric(out, offset, 4, 8, statement.epoch);
        offset = _pushBytes32(out, offset, 5, statement.participantSetHash);
        offset = _pushBytes32(out, offset, 6, statement.aggregatePkHash);
        offset = _pushBytes32(out, offset, 7, statement.ciphertextHash);
        offset = _pushBytes32(out, offset, 8, statement.plaintextHash);
        offset = _pushBytes32(out, offset, 9, statement.dCommitment);
        offset = _pushBytes32(out, offset, 10, statement.c5ProofRoot);
        offset = _pushBytes32(out, offset, 11, statement.c6ProofSetRoot);
        offset = _pushBytes32(out, offset, 12, statement.cycloAccumulatorRoot);
        offset = _pushBytes32(out, offset, 13, statement.ivcVkHash);
        offset = _pushBytes32(out, offset, 14, statement.ivcPpHash);
        offset = _pushBytes32(out, offset, 15, statement.ivcProofHash);
        offset = _pushBytes32(out, offset, 16, statement.z0Commitment);
        offset = _pushBytes32(out, offset, 17, statement.ziCommitment);
        offset = _pushNumeric(out, offset, 18, 8, statement.ivcSteps);
        offset = _pushBytes32(out, offset, 19, statement.bootstrapResultHash);

        assert(offset == PREIMAGE_LEN);
    }

    function _pushNumeric(
        uint256[76] memory out,
        uint256 offset,
        uint256 fieldId,
        uint256 byteLen,
        uint256 value
    ) private pure returns (uint256) {
        out[offset++] = fieldId;
        out[offset++] = byteLen;
        out[offset++] = value;
        return offset;
    }

    function _pushBytes32(uint256[76] memory out, uint256 offset, uint256 fieldId, bytes32 value)
        private
        pure
        returns (uint256)
    {
        out[offset++] = fieldId;
        out[offset++] = 32;
        (uint256 hi, uint256 lo) = splitBytes32(value);
        out[offset++] = hi;
        out[offset++] = lo;
        return offset;
    }

    function splitBytes32(bytes32 value) internal pure returns (uint256 hi, uint256 lo) {
        uint256 word = uint256(value);
        hi = uint256(uint128(word >> 128));
        lo = uint256(uint128(word));
    }
}
