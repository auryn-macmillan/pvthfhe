// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

contract DeployVerifier is Script {
    function run() external {
        vm.startBroadcast();
        SessionRegistry reg = new SessionRegistry();
        new PvtFheVerifier(address(reg), address(0)); // timelock: deploy TimelockController first in production (R6.4)
        vm.stopBroadcast();
    }
}
