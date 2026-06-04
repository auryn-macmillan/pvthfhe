// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../test/BaseVerifierTest.t.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";
import "../src/VerificationStatementV1.sol";

contract MockIvcDeciderVerifierForPlumbing {
    bool public result;
    bool public checkExpected;

    bytes32 public expectedStatementHash;
    bytes32 public expectedVkHash;
    bytes32 public expectedPpHash;
    bytes32 public expectedZ0;
    bytes32 public expectedZi;
    uint64 public expectedSteps;

    bytes public lastProof;
    bytes32 public lastStatementHash;
    bytes32 public lastVkHash;
    bytes32 public lastPpHash;
    bytes32 public lastZ0;
    bytes32 public lastZi;
    uint64 public lastSteps;

    constructor(bool result_) {
        result = result_;
    }

    function setResult(bool result_) external {
        result = result_;
    }

    function setExpected(
        bytes32 statementHash,
        bytes32 vkHash,
        bytes32 ppHash,
        bytes32 z0,
        bytes32 zi,
        uint64 steps
    ) external {
        checkExpected = true;
        expectedStatementHash = statementHash;
        expectedVkHash = vkHash;
        expectedPpHash = ppHash;
        expectedZ0 = z0;
        expectedZi = zi;
        expectedSteps = steps;
    }

    function verify(
        bytes calldata proof,
        bytes32 statementHash,
        bytes32 vkHash,
        bytes32 ppHash,
        bytes32 z0,
        bytes32 zi,
        uint64 steps
    ) external view returns (bool) {
        proof.length;
        if (!checkExpected) {
            return result;
        }

        return result && statementHash == expectedStatementHash && vkHash == expectedVkHash && ppHash == expectedPpHash
            && z0 == expectedZ0 && zi == expectedZi && steps == expectedSteps;
    }

    function verifyAndRecord(
        bytes calldata proof,
        bytes32 statementHash,
        bytes32 vkHash,
        bytes32 ppHash,
        bytes32 z0,
        bytes32 zi,
        uint64 steps
    ) external returns (bool) {
        lastProof = proof;
        lastStatementHash = statementHash;
        lastVkHash = vkHash;
        lastPpHash = ppHash;
        lastZ0 = z0;
        lastZi = zi;
        lastSteps = steps;
        return this.verify(proof, statementHash, vkHash, ppHash, z0, zi, steps);
    }
}

/// @notice Phase 2 IVC decider seam tests. The true-returning mock is plumbing only;
/// it is not evidence of IVC soundness or Phase-2 cryptographic completion.
contract IvcDeciderWiringTest is BaseVerifierTest {
    PvtFheVerifier internal verifier;
    SessionRegistry internal registry;

    bytes32 internal constant DKG_ROOT = keccak256("ivc-decider-wiring-dkg-root");
    bytes32 internal constant ROSTER_HASH = keccak256("ivc-decider-wiring-roster");
    bytes32 internal constant CIPHERTEXT_HASH = keccak256("ivc-decider-wiring-ciphertext");
    bytes32 internal constant PLAINTEXT_HASH = keccak256("ivc-decider-wiring-plaintext");
    bytes32 internal constant AGGREGATE_PK_HASH = keccak256("ivc-decider-wiring-aggregate-pk");
    bytes32 internal constant PARTICIPANT_SET_HASH = keccak256("ivc-decider-wiring-participants");
    bytes32 internal constant D_COMMITMENT = keccak256("ivc-decider-wiring-d-commitment");
    address internal constant TIMELOCK = address(0xBEEF);

    function setUp() public override {
        super.setUp();

        registry = new SessionRegistry();
        verifier = new PvtFheVerifier(address(registry), TIMELOCK);
        registry.grantRole(registry.SESSION_CREATOR_ROLE(), address(this));
        registry.grantRole(registry.VERIFIER_ROLE(), address(verifier));
        registry.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);
    }

    function testUnconfiguredRevertsBeforeReadingResult() public {
        vm.expectRevert(bytes("PVTHFHE: IVC decider not configured"));
        verifier.verifyWithIvc(
            CIPHERTEXT_HASH,
            PLAINTEXT_HASH,
            AGGREGATE_PK_HASH,
            DKG_ROOT,
            SAMPLE_EPOCH,
            PARTICIPANT_SET_HASH,
            D_COMMITMENT,
            _wellFormedIvcBinding(0),
            sampleProof
        );
    }

    function testIvcVerifyResultOneStillRevertsWhenUnconfigured() public {
        vm.expectRevert(bytes("PVTHFHE: IVC decider not configured"));
        verifier.verifyWithIvc(
            CIPHERTEXT_HASH,
            PLAINTEXT_HASH,
            AGGREGATE_PK_HASH,
            DKG_ROOT,
            SAMPLE_EPOCH,
            PARTICIPANT_SET_HASH,
            D_COMMITMENT,
            _wellFormedIvcBinding(1),
            sampleProof
        );
    }

    function testConfiguredDeciderReturningFalseRejects() public {
        MockIvcDeciderVerifierForPlumbing decider = new MockIvcDeciderVerifierForPlumbing(false);
        _setDecider(address(decider));

        assertFalse(
            verifier.verifyWithIvc(
                CIPHERTEXT_HASH,
                PLAINTEXT_HASH,
                AGGREGATE_PK_HASH,
                DKG_ROOT,
                SAMPLE_EPOCH,
                PARTICIPANT_SET_HASH,
                D_COMMITMENT,
                _wellFormedIvcBinding(1),
                sampleProof
            )
        );

        assertFalse(
            verifier.verifyAndConsumeWithIvc(
                CIPHERTEXT_HASH,
                PLAINTEXT_HASH,
                AGGREGATE_PK_HASH,
                DKG_ROOT,
                SAMPLE_EPOCH,
                PARTICIPANT_SET_HASH,
                D_COMMITMENT,
                _wellFormedIvcBinding(1),
                sampleProof
            )
        );
        assertFalse(registry.isEpochConsumed(DKG_ROOT, SAMPLE_EPOCH), "false decider must not consume epoch");
    }

    function testEmptyProofRejected() public {
        MockIvcDeciderVerifierForPlumbing decider = new MockIvcDeciderVerifierForPlumbing(true);
        _setDecider(address(decider));
        assertGt(sampleProof.length, 0, "BaseVerifierTest sampleProof must remain non-empty");

        vm.expectRevert(bytes("PVTHFHE: empty IVC proof"));
        verifier.verifyWithIvc(
            CIPHERTEXT_HASH,
            PLAINTEXT_HASH,
            AGGREGATE_PK_HASH,
            DKG_ROOT,
            SAMPLE_EPOCH,
            PARTICIPANT_SET_HASH,
            D_COMMITMENT,
            _wellFormedIvcBinding(1),
            bytes("")
        );
    }

    function testWrongIvcParamsRejected() public {
        IvcBinding memory binding = _wellFormedIvcBinding(1);
        MockIvcDeciderVerifierForPlumbing decider = new MockIvcDeciderVerifierForPlumbing(true);
        decider.setExpected(
            _expectedStatementHash(binding),
            bytes32(uint256(0x1234)),
            binding.ivcPpHash,
            binding.z0Commitment,
            binding.ziCommitment,
            binding.ivcSteps
        );
        _setDecider(address(decider));

        assertFalse(
            verifier.verifyWithIvc(
                CIPHERTEXT_HASH,
                PLAINTEXT_HASH,
                AGGREGATE_PK_HASH,
                DKG_ROOT,
                SAMPLE_EPOCH,
                PARTICIPANT_SET_HASH,
                D_COMMITMENT,
                binding,
                sampleProof
            )
        );
    }

    function testStatementHashMismatchAloneRejected() public {
        IvcBinding memory binding = _wellFormedIvcBinding(1);
        bytes32 wrongStatementHash = _expectedStatementHash(binding) ^ bytes32(uint256(1));
        MockIvcDeciderVerifierForPlumbing decider = new MockIvcDeciderVerifierForPlumbing(true);
        decider.setExpected(
            wrongStatementHash,
            binding.ivcVkHash,
            binding.ivcPpHash,
            binding.z0Commitment,
            binding.ziCommitment,
            binding.ivcSteps
        );
        _setDecider(address(decider));

        assertFalse(
            verifier.verifyWithIvc(
                CIPHERTEXT_HASH,
                PLAINTEXT_HASH,
                AGGREGATE_PK_HASH,
                DKG_ROOT,
                SAMPLE_EPOCH,
                PARTICIPANT_SET_HASH,
                D_COMMITMENT,
                binding,
                sampleProof
            )
        );
    }

    function testDeciderReceivesExactStatementHashAndFields() public {
        IvcBinding memory binding = _wellFormedIvcBinding(1);
        MockIvcDeciderVerifierForPlumbing decider = new MockIvcDeciderVerifierForPlumbing(true);
        _setDecider(address(new RecordingIvcDeciderAdapter(decider)));

        assertTrue(
            verifier.verifyAndConsumeWithIvc(
                CIPHERTEXT_HASH,
                PLAINTEXT_HASH,
                AGGREGATE_PK_HASH,
                DKG_ROOT,
                SAMPLE_EPOCH,
                PARTICIPANT_SET_HASH,
                D_COMMITMENT,
                binding,
                sampleProof
            )
        );

        assertEq(decider.lastStatementHash(), _expectedStatementHash(binding), "statement hash mismatch");
        assertEq(decider.lastVkHash(), binding.ivcVkHash, "vk hash mismatch");
        assertEq(decider.lastPpHash(), binding.ivcPpHash, "pp hash mismatch");
        assertEq(decider.lastZ0(), binding.z0Commitment, "z0 mismatch");
        assertEq(decider.lastZi(), binding.ziCommitment, "zi mismatch");
        assertEq(decider.lastSteps(), binding.ivcSteps, "steps mismatch");
    }

    function testCallerResultIgnored_PlumbingSuccess() public {
        // PLUMBING/control-flow only: this true-returning mock is not a soundness proof
        // and does not complete real Nova/LatticeFold on-chain decider research.
        IvcBinding memory binding = _wellFormedIvcBinding(0);
        MockIvcDeciderVerifierForPlumbing decider = new MockIvcDeciderVerifierForPlumbing(true);
        _setDecider(address(decider));

        assertTrue(
            verifier.verifyWithIvc(
                CIPHERTEXT_HASH,
                PLAINTEXT_HASH,
                AGGREGATE_PK_HASH,
                DKG_ROOT,
                SAMPLE_EPOCH,
                PARTICIPANT_SET_HASH,
                D_COMMITMENT,
                binding,
                sampleProof
            )
        );
        assertTrue(
            verifier.verifyAndConsumeWithIvc(
                CIPHERTEXT_HASH,
                PLAINTEXT_HASH,
                AGGREGATE_PK_HASH,
                DKG_ROOT,
                SAMPLE_EPOCH,
                PARTICIPANT_SET_HASH,
                D_COMMITMENT,
                binding,
                sampleProof
            )
        );
        assertTrue(registry.isEpochConsumed(DKG_ROOT, SAMPLE_EPOCH), "true decider should consume epoch in plumbing test");
    }

    function _setDecider(address decider) internal {
        vm.prank(TIMELOCK);
        verifier.setIvcDeciderVerifier(decider);
    }

    function _wellFormedIvcBinding(uint64 ivcVerifyResult) internal pure returns (IvcBinding memory) {
        return IvcBinding({
            ivcProofHash: bytes32(uint256(0x01)),
            ivcVkHash: bytes32(uint256(0x02)),
            ivcPpHash: bytes32(uint256(0x03)),
            z0Commitment: bytes32(uint256(0x04)),
            ziCommitment: bytes32(uint256(0x05)),
            ivcSteps: 1,
            shareVerificationHash: bytes32(uint256(0x07)),
            decryptNizkHash: bytes32(uint256(0x08)),
            dkgTranscriptHash: bytes32(uint256(0x09)),
            c5ProofRoot: bytes32(uint256(0x0c)),
            novaFinalStateCommitment: bytes32(uint256(0x0a)),
            ivcVerifyResult: ivcVerifyResult,
            bootstrapResultHash: bytes32(uint256(0x0b))
        });
    }

    function _expectedStatementHash(IvcBinding memory binding) internal pure returns (bytes32) {
        return VerificationStatementV1.computeStatementHashBytes32(
            VerificationStatementV1.Statement({
                protocolVersion: 1,
                contextId: bytes32(0),
                dkgRoot: DKG_ROOT,
                epoch: SAMPLE_EPOCH,
                participantSetHash: PARTICIPANT_SET_HASH,
                aggregatePkHash: AGGREGATE_PK_HASH,
                ciphertextHash: CIPHERTEXT_HASH,
                plaintextHash: PLAINTEXT_HASH,
                dCommitment: D_COMMITMENT,
                c5ProofRoot: binding.c5ProofRoot,
                c6ProofSetRoot: bytes32(0),
                cycloAccumulatorRoot: bytes32(0),
                ivcVkHash: binding.ivcVkHash,
                ivcPpHash: binding.ivcPpHash,
                ivcProofHash: binding.ivcProofHash,
                z0Commitment: binding.z0Commitment,
                ziCommitment: binding.ziCommitment,
                ivcSteps: binding.ivcSteps,
                bootstrapResultHash: binding.bootstrapResultHash,
                shareVerificationHash: binding.shareVerificationHash,
                decryptNizkHash: binding.decryptNizkHash,
                dkgTranscriptHash: binding.dkgTranscriptHash,
                novaFinalStateCommitment: binding.novaFinalStateCommitment
            })
        );
    }
}

contract RecordingIvcDeciderAdapter {
    MockIvcDeciderVerifierForPlumbing internal immutable mock;

    constructor(MockIvcDeciderVerifierForPlumbing mock_) {
        mock = mock_;
    }

    function verify(
        bytes calldata proof,
        bytes32 statementHash,
        bytes32 vkHash,
        bytes32 ppHash,
        bytes32 z0,
        bytes32 zi,
        uint64 steps
    ) external returns (bool) {
        return mock.verifyAndRecord(proof, statementHash, vkHash, ppHash, z0, zi, steps);
    }
}
