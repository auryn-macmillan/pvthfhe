// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../test/BaseVerifierTest.t.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// @notice F1 regression tests: IVC paths must fail closed until a real decider exists.
contract IvcFailClosedTest is BaseVerifierTest {
    PvtFheVerifier internal verifier;

    bytes32 internal constant DKG_ROOT = keccak256("ivc-fail-closed-dkg-root");
    bytes32 internal constant ROSTER_HASH = keccak256("ivc-fail-closed-roster");
    address internal constant TIMELOCK = address(0xBEEF);
    address internal constant NON_TIMELOCK = address(0xCAFE);
    address internal constant DECIDER = address(0xD311D3);

    function setUp() public override {
        super.setUp();

        SessionRegistry reg = new SessionRegistry();
        verifier = new PvtFheVerifier(address(reg), TIMELOCK);
        reg.grantRole(reg.SESSION_CREATOR_ROLE(), address(this));
        reg.grantRole(reg.VERIFIER_ROLE(), address(verifier));
        reg.registerSession(DKG_ROOT, 10, 6, ROSTER_HASH);
    }

    function testIvcRequiresDecider() public {
        vm.expectRevert(bytes("PVTHFHE: IVC decider not configured"));
        verifier.verifyWithIvc(
            SAMPLE_HASH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            DKG_ROOT,
            SAMPLE_EPOCH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            _wellFormedIvcBinding(1),
            sampleProof
        );
    }

    function testIvcConsumeRequiresDecider() public {
        vm.expectRevert(bytes("PVTHFHE: IVC decider not configured"));
        verifier.verifyAndConsumeWithIvc(
            SAMPLE_HASH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            DKG_ROOT,
            SAMPLE_EPOCH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            _wellFormedIvcBinding(1),
            sampleProof
        );
    }

    function testRejectsForgedIvcVerifyResult() public {
        IvcBinding memory forgedBinding = _wellFormedIvcBinding(1);

        vm.expectRevert(bytes("PVTHFHE: IVC decider not configured"));
        verifier.verifyWithIvc(
            SAMPLE_HASH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            DKG_ROOT,
            SAMPLE_EPOCH,
            SAMPLE_HASH,
            SAMPLE_HASH,
            forgedBinding,
            sampleProof
        );
    }

    function testSetIvcDeciderVerifierOnlyTimelock() public {
        vm.prank(NON_TIMELOCK);
        (bool unauthorized, bytes memory unauthorizedReturndata) = address(verifier).call(
            abi.encodeWithSignature("setIvcDeciderVerifier(address)", DECIDER)
        );
        assertFalse(unauthorized, "non-timelock must not set IVC decider verifier");
        assertEq(_revertReason(unauthorizedReturndata), "Unauthorized");

        vm.prank(TIMELOCK);
        (bool authorized,) = address(verifier).call(abi.encodeWithSignature("setIvcDeciderVerifier(address)", DECIDER));
        assertTrue(authorized, "timelock must set IVC decider verifier");

        (bool readOk, bytes memory readReturndata) = address(verifier).staticcall(
            abi.encodeWithSignature("ivcDeciderVerifier()")
        );
        assertTrue(readOk, "IVC decider getter must be readable");
        assertEq(abi.decode(readReturndata, (address)), DECIDER);
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

    function _revertReason(bytes memory returndata) internal pure returns (string memory) {
        if (returndata.length < 68) {
            return "";
        }

        bytes memory reason = new bytes(returndata.length - 4);
        for (uint256 i = 4; i < returndata.length; i++) {
            reason[i - 4] = returndata[i];
        }
        return abi.decode(reason, (string));
    }
}
