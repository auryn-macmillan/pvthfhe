// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/VerificationStatementV1.sol";

contract VerificationStatementVectorTest is Test {
    uint256 internal constant GOLDEN_HASH =
        2717525839999002672616025848791696639911259589570414897881626410761076250408;

    function testVerificationStatementPreimageMatchesGoldenJson() public pure {
        VerificationStatementV1.Statement memory statement = _goldenStatement();
        uint256[76] memory preimage = VerificationStatementV1.poseidonPreimage(statement);
        uint256[76] memory expected = _goldenPreimage();

        for (uint256 i = 0; i < expected.length; i++) {
            assertEq(preimage[i], expected[i], "preimage element mismatch");
        }
    }

    function testVerificationStatementVector() public {
        uint256 computed = VerificationStatementV1.computeStatementHash(_goldenStatement());
        emit log_named_uint("statement_hash_decimal", computed);
        assertEq(computed, GOLDEN_HASH, "statement hash must match Rust+Noir golden vector");
    }

    function testVerificationStatementFieldSwapChangesHash() public pure {
        VerificationStatementV1.Statement memory statement = _goldenStatement();
        (statement.contextId, statement.dkgRoot) = (statement.dkgRoot, statement.contextId);

        assertTrue(
            VerificationStatementV1.computeStatementHash(statement) != GOLDEN_HASH,
            "swapping context_id and dkg_root must change the statement hash"
        );
    }

    function testVerificationStatementHiLoSwapChangesHash() public pure {
        VerificationStatementV1.Statement memory statement = _goldenStatement();
        bytes32 original = statement.contextId;
        statement.contextId = bytes32((uint256(uint128(uint256(original))) << 128) | (uint256(original) >> 128));

        assertTrue(
            VerificationStatementV1.computeStatementHash(statement) != GOLDEN_HASH,
            "swapping hi/lo limbs must change the statement hash"
        );
    }

    function testVerificationStatementEachFieldMutationChangesHash() public pure {
        VerificationStatementV1.Statement memory statement;

        statement = _goldenStatement();
        statement.protocolVersion += 1;
        _assertStatementHashChanged(statement, "protocolVersion");

        statement = _goldenStatement();
        statement.contextId = _mutateBytes32(statement.contextId);
        _assertStatementHashChanged(statement, "contextId");

        statement = _goldenStatement();
        statement.dkgRoot = _mutateBytes32(statement.dkgRoot);
        _assertStatementHashChanged(statement, "dkgRoot");

        statement = _goldenStatement();
        statement.epoch += 1;
        _assertStatementHashChanged(statement, "epoch");

        statement = _goldenStatement();
        statement.participantSetHash = _mutateBytes32(statement.participantSetHash);
        _assertStatementHashChanged(statement, "participantSetHash");

        statement = _goldenStatement();
        statement.aggregatePkHash = _mutateBytes32(statement.aggregatePkHash);
        _assertStatementHashChanged(statement, "aggregatePkHash");

        statement = _goldenStatement();
        statement.ciphertextHash = _mutateBytes32(statement.ciphertextHash);
        _assertStatementHashChanged(statement, "ciphertextHash");

        statement = _goldenStatement();
        statement.plaintextHash = _mutateBytes32(statement.plaintextHash);
        _assertStatementHashChanged(statement, "plaintextHash");

        statement = _goldenStatement();
        statement.dCommitment = _mutateBytes32(statement.dCommitment);
        _assertStatementHashChanged(statement, "dCommitment");

        statement = _goldenStatement();
        statement.c5ProofRoot = _mutateBytes32(statement.c5ProofRoot);
        _assertStatementHashChanged(statement, "c5ProofRoot");

        statement = _goldenStatement();
        statement.c6ProofSetRoot = _mutateBytes32(statement.c6ProofSetRoot);
        _assertStatementHashChanged(statement, "c6ProofSetRoot");

        statement = _goldenStatement();
        statement.cycloAccumulatorRoot = _mutateBytes32(statement.cycloAccumulatorRoot);
        _assertStatementHashChanged(statement, "cycloAccumulatorRoot");

        statement = _goldenStatement();
        statement.ivcVkHash = _mutateBytes32(statement.ivcVkHash);
        _assertStatementHashChanged(statement, "ivcVkHash");

        statement = _goldenStatement();
        statement.ivcPpHash = _mutateBytes32(statement.ivcPpHash);
        _assertStatementHashChanged(statement, "ivcPpHash");

        statement = _goldenStatement();
        statement.ivcProofHash = _mutateBytes32(statement.ivcProofHash);
        _assertStatementHashChanged(statement, "ivcProofHash");

        statement = _goldenStatement();
        statement.z0Commitment = _mutateBytes32(statement.z0Commitment);
        _assertStatementHashChanged(statement, "z0Commitment");

        statement = _goldenStatement();
        statement.ziCommitment = _mutateBytes32(statement.ziCommitment);
        _assertStatementHashChanged(statement, "ziCommitment");

        statement = _goldenStatement();
        statement.ivcSteps += 1;
        _assertStatementHashChanged(statement, "ivcSteps");

        statement = _goldenStatement();
        statement.bootstrapResultHash = _mutateBytes32(statement.bootstrapResultHash);
        _assertStatementHashChanged(statement, "bootstrapResultHash");
    }

    function _goldenStatement() internal pure returns (VerificationStatementV1.Statement memory statement) {
        statement.protocolVersion = 1;
        statement.contextId = _bytesFromSeed(0x10);
        statement.dkgRoot = _bytesFromSeed(0x20);
        statement.epoch = 42;
        statement.participantSetHash = _bytesFromSeed(0x30);
        statement.aggregatePkHash = _bytesFromSeed(0x40);
        statement.ciphertextHash = _bytesFromSeed(0x50);
        statement.plaintextHash = _bytesFromSeed(0x60);
        statement.dCommitment = _bytesFromSeed(0x70);
        statement.c5ProofRoot = _bytesFromSeed(0x80);
        statement.c6ProofSetRoot = _bytesFromSeed(0x90);
        statement.cycloAccumulatorRoot = _bytesFromSeed(0xa0);
        statement.ivcVkHash = _bytesFromSeed(0xb0);
        statement.ivcPpHash = _bytesFromSeed(0xc0);
        statement.ivcProofHash = _bytesFromSeed(0xd0);
        statement.z0Commitment = _bytesFromSeed(0xe0);
        statement.ziCommitment = _bytesFromSeed(0xf0);
        statement.ivcSteps = 7;
        statement.bootstrapResultHash = _bytesFromSeed(0x08);
    }

    function _bytesFromSeed(uint8 seed) internal pure returns (bytes32 out) {
        uint256 value;
        for (uint256 i = 0; i < 32; i++) {
            value = (value << 8) | uint8(uint256(seed) + i);
        }
        out = bytes32(value);
    }

    function _mutateBytes32(bytes32 value) internal pure returns (bytes32) {
        return value ^ bytes32(uint256(1));
    }

    function _assertStatementHashChanged(VerificationStatementV1.Statement memory statement, string memory fieldName)
        internal
        pure
    {
        assertTrue(VerificationStatementV1.computeStatementHash(statement) != GOLDEN_HASH, fieldName);
    }

    function _goldenPreimage() internal pure returns (uint256[76] memory expected) {
        expected = [
            uint256(11843706111462126810235743653006615712282455314701937352287001081393),
            uint256(1),
            uint256(19),
            uint256(1),
            uint256(4),
            uint256(1),
            uint256(2),
            uint256(32),
            uint256(21356283574076891493948969979685445151),
            uint256(42707334047547540181846984563639529007),
            uint256(3),
            uint256(32),
            uint256(42707334047547540181846984563639529007),
            uint256(64058384521018188869744999147593612863),
            uint256(4),
            uint256(8),
            uint256(42),
            uint256(5),
            uint256(32),
            uint256(64058384521018188869744999147593612863),
            uint256(85409434994488837557643013731547696719),
            uint256(6),
            uint256(32),
            uint256(85409434994488837557643013731547696719),
            uint256(106760485467959486245541028315501780575),
            uint256(7),
            uint256(32),
            uint256(106760485467959486245541028315501780575),
            uint256(128111535941430134933439042899455864431),
            uint256(8),
            uint256(32),
            uint256(128111535941430134933439042899455864431),
            uint256(149462586414900783621337057483409948287),
            uint256(9),
            uint256(32),
            uint256(149462586414900783621337057483409948287),
            uint256(170813636888371432309235072067364032143),
            uint256(10),
            uint256(32),
            uint256(170813636888371432309235072067364032143),
            uint256(192164687361842080997133086651318115999),
            uint256(11),
            uint256(32),
            uint256(192164687361842080997133086651318115999),
            uint256(213515737835312729685031101235272199855),
            uint256(12),
            uint256(32),
            uint256(213515737835312729685031101235272199855),
            uint256(234866788308783378372929115819226283711),
            uint256(13),
            uint256(32),
            uint256(234866788308783378372929115819226283711),
            uint256(256217838782254027060827130403180367567),
            uint256(14),
            uint256(32),
            uint256(256217838782254027060827130403180367567),
            uint256(277568889255724675748725144987134451423),
            uint256(15),
            uint256(32),
            uint256(277568889255724675748725144987134451423),
            uint256(298919939729195324436623159571088535279),
            uint256(16),
            uint256(32),
            uint256(298919939729195324436623159571088535279),
            uint256(320270990202665973124521174155042619135),
            uint256(17),
            uint256(32),
            uint256(320270990202665973124521174155042619135),
            uint256(5233100606242806050955395731361295),
            uint256(18),
            uint256(8),
            uint256(7),
            uint256(19),
            uint256(32),
            uint256(10680758337341567149999962687708403223),
            uint256(32031808810812215837897977271662487079)
        ];
    }
}
