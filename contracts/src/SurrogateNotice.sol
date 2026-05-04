// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SURROGATE ACTIVE: HonkVerifier, micronova_wrap, aggregator_final are research surrogates — do not deploy
// This file intentionally triggers a compiler warning so that every `forge build` emits the notice above.

contract SurrogateNotice {
    /// @dev Intentional unused-variable warning: solc will quote this line in its warning output,
    ///      making "SURROGATE ACTIVE" appear on stderr for every `forge build` invocation.
    function _surrogateActiveTripwire() internal pure {
        // solc will warn "Unused local variable" and quote the line below:
        bool SURROGATE_ACTIVE_HonkVerifier_micronova_wrap_aggregator_final = false; // SURROGATE ACTIVE: research surrogates — do not deploy
    }
}
