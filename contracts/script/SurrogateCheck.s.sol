// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SURROGATE ACTIVE: HonkVerifier, micronova_wrap, aggregator_final are research surrogates — do not deploy

import "forge-std/Script.sol";

contract SurrogateCheck is Script {
    function run() external view {
        console.log("SURROGATE ACTIVE: HonkVerifier, micronova_wrap, aggregator_final are research surrogates - do not deploy");
    }
}
