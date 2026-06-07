// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/IvcChainDecider.sol";

contract IvcChainDeciderTest is Test {
    IvcChainDecider decider;

    address registrar = address(0x1000);
    address nonRegistrar = address(0xBEEF);

    bytes32 constant TEST_VK_HASH = bytes32(uint256(1));
    bytes32 constant TEST_PP_HASH = bytes32(uint256(2));
    bytes32 constant TEST_Z0 = bytes32(uint256(3));
    uint64 constant TEST_STEPS = 42;
    bytes32 constant TEST_STATEMENT = bytes32(uint256(4));

    function setUp() public {
        vm.prank(registrar);
        decider = new IvcChainDecider(registrar);
    }

    // ── Registration ──

    function test_registerConfig() public {
        vm.prank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        assertTrue(decider.isRegistered(TEST_VK_HASH));

        (
            bytes32 cfgPpHash,
            bytes32 cfgZ0Commitment,
            uint64 cfgExpectedSteps
        ) = decider.configs(TEST_VK_HASH);
        assertEq(cfgPpHash, TEST_PP_HASH);
        assertEq(cfgZ0Commitment, TEST_Z0);
        assertEq(cfgExpectedSteps, TEST_STEPS);
    }

    function test_registerConfig_revert_nonRegistrar() public {
        vm.prank(nonRegistrar);
        vm.expectRevert("IvcChainDecider: only registrar");
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
    }

    function test_registerConfig_revert_zeroParams() public {
        vm.startPrank(registrar);
        vm.expectRevert("IvcChainDecider: zero vkHash");
        decider.registerConfig(bytes32(0), TEST_PP_HASH, TEST_Z0, TEST_STEPS);

        vm.expectRevert("IvcChainDecider: zero ppHash");
        decider.registerConfig(TEST_VK_HASH, bytes32(0), TEST_Z0, TEST_STEPS);

        vm.expectRevert("IvcChainDecider: zero z0");
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, bytes32(0), TEST_STEPS);

        vm.expectRevert("IvcChainDecider: zero steps");
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, 0);
        vm.stopPrank();
    }

    function test_deregisterConfig() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        assertTrue(decider.isRegistered(TEST_VK_HASH));

        decider.deregisterConfig(TEST_VK_HASH);
        assertFalse(decider.isRegistered(TEST_VK_HASH));
        vm.stopPrank();
    }

    // ── Verification ──

    function test_verifyCorrectConfig() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        vm.stopPrank();

        bytes32 expectedZi = keccak256(
            abi.encodePacked("pvthfhe-ivc-chain/v1", TEST_Z0, TEST_STEPS, TEST_VK_HASH)
        );

        bytes memory proof = hex"00010203";
        bool result = decider.verify(
            proof, TEST_STATEMENT, TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, expectedZi, TEST_STEPS
        );
        assertTrue(result);
    }

    function test_verify_revert_unregisteredVk() public {
        bytes memory proof = hex"00010203";
        vm.expectRevert("IvcChainDecider: unregistered vkHash");
        decider.verify(proof, TEST_STATEMENT, TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_Z0, TEST_STEPS);
    }

    function test_verify_revert_wrongPpHash() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        vm.stopPrank();

        bytes32 expectedZi = keccak256(
            abi.encodePacked("pvthfhe-ivc-chain/v1", TEST_Z0, TEST_STEPS, TEST_VK_HASH)
        );

        bytes memory proof = hex"00010203";
        vm.expectRevert("IvcChainDecider: ppHash mismatch");
        decider.verify(proof, TEST_STATEMENT, TEST_VK_HASH, bytes32(uint256(99)), TEST_Z0, expectedZi, TEST_STEPS);
    }

    function test_verify_revert_wrongZ0() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        vm.stopPrank();

        bytes32 expectedZi = keccak256(
            abi.encodePacked("pvthfhe-ivc-chain/v1", TEST_Z0, TEST_STEPS, TEST_VK_HASH)
        );

        bytes memory proof = hex"00010203";
        vm.expectRevert("IvcChainDecider: z0 mismatch");
        decider.verify(proof, TEST_STATEMENT, TEST_VK_HASH, TEST_PP_HASH, bytes32(uint256(99)), expectedZi, TEST_STEPS);
    }

    function test_verify_revert_wrongSteps() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        vm.stopPrank();

        bytes32 expectedZi = keccak256(
            abi.encodePacked("pvthfhe-ivc-chain/v1", TEST_Z0, uint64(99), TEST_VK_HASH)
        );

        bytes memory proof = hex"00010203";
        vm.expectRevert("IvcChainDecider: steps mismatch");
        decider.verify(proof, TEST_STATEMENT, TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, expectedZi, 99);
    }

    function test_verify_revert_wrongZi() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        vm.stopPrank();

        bytes memory proof = hex"00010203";
        vm.expectRevert("IvcChainDecider: zi chain mismatch");
        decider.verify(proof, TEST_STATEMENT, TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, bytes32(uint256(99)), TEST_STEPS);
    }

    function test_verify_revert_replay() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        vm.stopPrank();

        bytes32 expectedZi = keccak256(
            abi.encodePacked("pvthfhe-ivc-chain/v1", TEST_Z0, TEST_STEPS, TEST_VK_HASH)
        );

        bytes memory proof = hex"00010203";
        // First verify succeeds
        assertTrue(decider.verify(proof, TEST_STATEMENT, TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, expectedZi, TEST_STEPS));

        // Same proof replay reverts
        vm.expectRevert("IvcChainDecider: proof already consumed");
        decider.verify(proof, TEST_STATEMENT, TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, expectedZi, TEST_STEPS);
    }

    function test_verify_differentProofSameConfig() public {
        vm.startPrank(registrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        vm.stopPrank();

        bytes32 expectedZi = keccak256(
            abi.encodePacked("pvthfhe-ivc-chain/v1", TEST_Z0, TEST_STEPS, TEST_VK_HASH)
        );

        // Different statement produces different proofId → both should succeed
        bytes memory proofA = hex"AAAA";
        bytes memory proofB = hex"BBBB";
        assertTrue(decider.verify(proofA, bytes32(uint256(100)), TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, expectedZi, TEST_STEPS));
        assertTrue(decider.verify(proofB, bytes32(uint256(200)), TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, expectedZi, TEST_STEPS));
    }

    // ── Registrar rotation ──

    function test_setRegistrar() public {
        address newRegistrar = address(0x9999);
        vm.prank(registrar);
        decider.setRegistrar(newRegistrar);

        // Old registrar can no longer register
        vm.prank(registrar);
        vm.expectRevert("IvcChainDecider: only registrar");
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);

        // New registrar can
        vm.prank(newRegistrar);
        decider.registerConfig(TEST_VK_HASH, TEST_PP_HASH, TEST_Z0, TEST_STEPS);
        assertTrue(decider.isRegistered(TEST_VK_HASH));
    }
}
