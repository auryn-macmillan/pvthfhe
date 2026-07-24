// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract KzgBatchVerifier {
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant GROUP_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant RANDOMIZER = 7;

    error InvalidBatchLength(uint256 expected, uint256 actual);
    error UnsupportedBatch(uint256 batchSize);

    function verifyBatch_1(bytes calldata proof, bytes calldata pubInputs) external view returns (bool) {
        return _verifyBatch(1, proof, pubInputs);
    }

    function verifyBatch_8(bytes calldata proof, bytes calldata pubInputs) external view returns (bool) {
        return _verifyBatch(8, proof, pubInputs);
    }

    function verifyBatch_32(bytes calldata proof, bytes calldata pubInputs) external view returns (bool) {
        return _verifyBatch(32, proof, pubInputs);
    }

    function verifyBatch_128(bytes calldata proof, bytes calldata pubInputs) external view returns (bool) {
        return _verifyBatch(128, proof, pubInputs);
    }

    function sampleProof(uint256 batchSize) external view returns (bytes memory proof) {
        (proof, ) = _sampleBatch(batchSize);
    }

    function samplePubInputs(uint256 batchSize) external view returns (bytes memory pubInputs) {
        (, pubInputs) = _sampleBatch(batchSize);
    }

    function sampleCallData(uint256 batchSize) external view returns (bytes memory) {
        (bytes memory proof, bytes memory pubInputs) = _sampleBatch(batchSize);
        return _encodeCallData(batchSize, proof, pubInputs);
    }

    function sampleCalldataGas(uint256 batchSize) external view returns (uint256) {
        return _calldataGas(_buildSampleCallData(batchSize));
    }

    function _verifyBatch(uint256 batchSize, bytes calldata proof, bytes calldata pubInputs) internal view returns (bool) {
        G1Point[] memory proofs = abi.decode(proof, (G1Point[]));
        (G1Point[] memory commitments, uint256[] memory values) = abi.decode(pubInputs, (G1Point[], uint256[]));

        if (proofs.length != batchSize) {
            revert InvalidBatchLength(batchSize, proofs.length);
        }
        if (commitments.length != batchSize) {
            revert InvalidBatchLength(batchSize, commitments.length);
        }
        if (values.length != batchSize) {
            revert InvalidBatchLength(batchSize, values.length);
        }

        G1Point memory lhs;
        G1Point memory rhs;
        uint256 weight = 1;

        for (uint256 i = 0; i < batchSize; ++i) {
            G1Point memory commitmentMinusValue = _g1Add(commitments[i], _g1Neg(_g1Mul(_g1Generator(), values[i])));
            lhs = _g1Add(lhs, _g1Mul(commitmentMinusValue, weight));
            rhs = _g1Add(rhs, _g1Mul(proofs[i], weight));
            weight = mulmod(weight, RANDOMIZER, GROUP_ORDER);
        }

        return _pairingEq(lhs, rhs);
    }

    function _sampleBatch(uint256 batchSize) internal view returns (bytes memory proof, bytes memory pubInputs) {
        if (batchSize != 1 && batchSize != 8 && batchSize != 32 && batchSize != 128) {
            revert UnsupportedBatch(batchSize);
        }

        G1Point[] memory proofs = new G1Point[](batchSize);
        G1Point[] memory commitments = new G1Point[](batchSize);
        uint256[] memory values = new uint256[](batchSize);

        for (uint256 i = 0; i < batchSize; ++i) {
            proofs[i] = _g1Mul(_g1Generator(), i + 3);
            values[i] = i + 11;
            commitments[i] = _g1Add(_g1Mul(_g1Generator(), values[i]), proofs[i]);
        }

        proof = abi.encode(proofs);
        pubInputs = abi.encode(commitments, values);
    }

    function _buildSampleCallData(uint256 batchSize) internal view returns (bytes memory) {
        (bytes memory proof, bytes memory pubInputs) = _sampleBatch(batchSize);
        return _encodeCallData(batchSize, proof, pubInputs);
    }

    function _encodeCallData(uint256 batchSize, bytes memory proof, bytes memory pubInputs) internal view returns (bytes memory) {
        if (batchSize == 1) {
            return abi.encodeCall(this.verifyBatch_1, (proof, pubInputs));
        }
        if (batchSize == 8) {
            return abi.encodeCall(this.verifyBatch_8, (proof, pubInputs));
        }
        if (batchSize == 32) {
            return abi.encodeCall(this.verifyBatch_32, (proof, pubInputs));
        }
        if (batchSize == 128) {
            return abi.encodeCall(this.verifyBatch_128, (proof, pubInputs));
        }
        revert UnsupportedBatch(batchSize);
    }

    function _pairingEq(G1Point memory lhs, G1Point memory rhs) internal view returns (bool) {
        G2Point memory generator = _g2Generator();
        G2Point memory negGenerator = _g2Neg(generator);
        uint256[12] memory input;

        input[0] = lhs.x;
        input[1] = lhs.y;
        input[2] = negGenerator.x[0];
        input[3] = negGenerator.x[1];
        input[4] = negGenerator.y[0];
        input[5] = negGenerator.y[1];
        input[6] = rhs.x;
        input[7] = rhs.y;
        input[8] = generator.x[0];
        input[9] = generator.x[1];
        input[10] = generator.y[0];
        input[11] = generator.y[1];

        uint256[1] memory output;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x08, input, 0x180, output, 0x20)
        }
        return ok && output[0] == 1;
    }

    function _g1Add(G1Point memory a, G1Point memory b) internal view returns (G1Point memory result) {
        uint256[4] memory input;
        input[0] = a.x;
        input[1] = a.y;
        input[2] = b.x;
        input[3] = b.y;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x06, input, 0x80, result, 0x40)
        }
        require(ok, "ecadd failed");
    }

    function _g1Mul(G1Point memory point, uint256 scalar) internal view returns (G1Point memory result) {
        uint256[3] memory input;
        input[0] = point.x;
        input[1] = point.y;
        input[2] = scalar % GROUP_ORDER;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x07, input, 0x60, result, 0x40)
        }
        require(ok, "ecmul failed");
    }

    function _g1Neg(G1Point memory point) internal pure returns (G1Point memory) {
        if (point.x == 0 && point.y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(point.x, FIELD_MODULUS - (point.y % FIELD_MODULUS));
    }

    function _g1Generator() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    function _g2Generator() internal pure returns (G2Point memory) {
        return G2Point({
            x: [
                11559732032986387107991004021392285783925812861821192530917403151452391805634,
                10857046999023057135944570762232829481370756359578518086990519993285655852781
            ],
            y: [
                4082367875863433681332203403145435568316851327593401208105741076214120093531,
                8495653923123431417604973247489272438418190587263600148770280649306958101930
            ]
        });
    }

    function _g2Neg(G2Point memory point) internal pure returns (G2Point memory) {
        return G2Point({
            x: point.x,
            y: [FIELD_MODULUS - (point.y[0] % FIELD_MODULUS), FIELD_MODULUS - (point.y[1] % FIELD_MODULUS)]
        });
    }

    function _calldataGas(bytes memory callData) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < callData.length; ++i) {
            total += callData[i] == bytes1(0) ? 4 : 16;
        }
    }
}
