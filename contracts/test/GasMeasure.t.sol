// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./P3RealVerifierBase.t.sol";

contract GasMeasureTest is P3RealVerifierBase {
    function test_gas_within_cap() public {
        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(validProof, validPublicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "valid proof must verify before gas is recorded");
        assertLt(gasUsed, 5_000_000, "gas exceeds 5M cap");

        string memory outputPath = string.concat(vm.projectRoot(), "/../bench/results/gas_measurement.json");
        string memory objectKey = "gas_measurement";
        string memory json = vm.serializeUint(objectKey, "verify_gas", gasUsed);
        json = vm.serializeUint(objectKey, "gas_budget", 5_000_000);
        json = vm.serializeUint(objectKey, "proof_bytes", validProof.length);
        json = vm.serializeUint(objectKey, "public_inputs_bytes", validPublicInputs.length);
        json = vm.serializeUint(objectKey, "calldata_bytes", validProof.length + validPublicInputs.length);
        json = vm.serializeBool(objectKey, "within_cap", true);
        json = vm.serializeString(objectKey, "stack", "UltraHonk-HonkVerifier-adapter");
        json = vm.serializeString(
            objectKey,
            "note",
            "measured via forge test --root contracts --match-test test_gas_within_cap"
        );
        vm.writeJson(json, outputPath);
    }
}
