// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseVerifierTest.t.sol";

contract SmokeTest is BaseVerifierTest {
    function test_fixtures_initialized() public pure {
        assertEq(SAMPLE_EPOCH, 1);
        assertNotEq(SAMPLE_HASH, bytes32(0));
    }
}
