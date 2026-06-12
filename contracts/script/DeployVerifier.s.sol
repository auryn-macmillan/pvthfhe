// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/PvtFheVerifier.sol";
import "../src/SessionRegistry.sol";

/// Deploy script for PvtFheVerifier + SessionRegistry.
///
/// GAP-4 FIX (MPC-AUDIT-2026-06-12): Previously passed `address(0)` as
/// timelock, permanently disabling attestor and IVC-decider configuration.
/// Now uses `msg.sender` as the initial timelock owner.  Production
/// deployment should use a real OpenZeppelin `TimelockController` (R6.4).
contract DeployVerifier is Script {
    function run() external {
        vm.startBroadcast();
        SessionRegistry reg = new SessionRegistry();
        // msg.sender controls attestor/IVC-decider configuration.
        // Replace with TimelockController address for production.
        new PvtFheVerifier(address(reg), msg.sender);
        vm.stopBroadcast();
    }
}
