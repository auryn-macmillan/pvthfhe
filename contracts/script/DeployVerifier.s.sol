// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/PvtFheVerifier.sol";

contract DeployVerifier is Script {
    function run() external {
        vm.startBroadcast();
        new PvtFheVerifier();
        vm.stopBroadcast();
    }
}
