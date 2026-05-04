// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract P3RealVerifierNoEcrecoverTest is Test {
    function test_no_ecrecover_or_trusted_signer_in_source() public view {
        string memory sourcePath = string.concat(vm.projectRoot(), "/src/P3RealVerifier.sol");
        string memory source = vm.readFile(sourcePath);

        assertFalse(vm.contains(source, "ecrecover"), "P3RealVerifier must not reference ecrecover");
        assertFalse(
            vm.contains(source, "TRUSTED_SIGNER"),
            "P3RealVerifier must not reference TRUSTED_SIGNER"
        );
    }
}
