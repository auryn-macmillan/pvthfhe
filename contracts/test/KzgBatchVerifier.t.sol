// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../bench/KzgBatchVerifier.sol";

contract KzgBatchVerifierTest {
    KzgBatchVerifier internal verifier;

    function setUp() public {
        verifier = new KzgBatchVerifier();
    }

    function testHonestVerifies() public view {
        _assertVerify(1, true);
        _assertVerify(8, true);
        _assertVerify(32, true);
        _assertVerify(128, true);
    }

    function testTamperedRejects() public view {
        _assertVerify(1, false);
        _assertVerify(8, false);
        _assertVerify(32, false);
        _assertVerify(128, false);
    }

    function testGas_verifyBatch_1() public view {
        _callVerify(1, false);
    }

    function testGas_verifyBatch_8() public view {
        _callVerify(8, false);
    }

    function testGas_verifyBatch_32() public view {
        _callVerify(32, false);
    }

    function testGas_verifyBatch_128() public view {
        _callVerify(128, false);
    }

    function _assertVerify(uint256 batchSize, bool honest) internal view {
        bool ok = _callVerify(batchSize, !honest);
        if (honest) {
            require(ok, "honest batch should verify");
        } else {
            require(!ok, "tampered batch should reject");
        }
    }

    function _callVerify(uint256 batchSize, bool tamper) internal view returns (bool) {
        bytes memory proof = verifier.sampleProof(batchSize);
        bytes memory pubInputs = verifier.samplePubInputs(batchSize);

        if (tamper) {
            (KzgBatchVerifier.G1Point[] memory commitments, uint256[] memory values) = abi.decode(
                pubInputs,
                (KzgBatchVerifier.G1Point[], uint256[])
            );
            values[0] += 1;
            pubInputs = abi.encode(commitments, values);
        }

        if (batchSize == 1) {
            return verifier.verifyBatch_1(proof, pubInputs);
        }
        if (batchSize == 8) {
            return verifier.verifyBatch_8(proof, pubInputs);
        }
        if (batchSize == 32) {
            return verifier.verifyBatch_32(proof, pubInputs);
        }
        if (batchSize == 128) {
            return verifier.verifyBatch_128(proof, pubInputs);
        }

        revert("unsupported batch");
    }
}
