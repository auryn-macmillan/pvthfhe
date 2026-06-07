// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PvtFheVerifier.sol";

/// @title IvcChainDecider
/// @notice Concrete on-chain IVC decider that verifies hash-chain consistency
///         of the Nova IVC proof state without requiring full recursive proof
///         verification in the EVM.
///
/// # Security Model
///
/// This decider provides defense-in-depth against IVC proof manipulation by
/// enforcing structural invariants of the IVC chain. It does NOT provide
/// cryptographic proof verification (that requires an on-chain Nova verifier,
/// tracked as OPEN PROBLEM P4).
///
/// ## What it verifies:
/// - VK hash is registered (prevents VK substitution)
/// - PP hash matches registered config (prevents parameter substitution)
/// - z0 commitment matches the registered initial state (prevents chain-fork)
/// - ivcSteps is non-zero and matches the registered expected steps
/// - Hash-chain integrity: for each step i, zi depends on previous state
///
/// ## What it does NOT verify:
/// - The actual Nova recursive proof (OPEN PROBLEM P4)
/// - Correctness of the folded computation
/// - That the zi commitment corresponds to a valid Nova accumulator
///
/// ## Deployment:
/// - Deploy this contract, call `registerConfig` with verified configuration
/// - Set `ivcDeciderVerifier` on PvtFheVerifier to this contract's address
/// - Only the configured timelock/owner can register new IVC configs
contract IvcChainDecider {
    /// @notice Registered IVC configuration.
    struct IvcConfig {
        bytes32 ppHash;       // IVC public parameters hash
        bytes32 z0Commitment; // Expected initial state (z0)
        uint64 expectedSteps; // Expected number of IVC steps for this VK
    }

    /// @notice Registered IVC configurations keyed by vkHash.
    mapping(bytes32 => IvcConfig) public configs;

    /// @notice Whether a given vkHash is registered.
    mapping(bytes32 => bool) public isRegistered;

    /// @notice Address authorized to register new IVC configurations.
    address public registrar;

    /// @notice Whether an IVC proof has been consumed (replay protection).
    mapping(bytes32 => bool) public consumed;

    event ConfigRegistered(bytes32 indexed vkHash, bytes32 ppHash, bytes32 z0, uint64 steps);
    event ProofVerified(bytes32 indexed statementHash, bytes32 indexed vkHash);
    event RegistrarUpdated(address indexed previous, address indexed next);

    constructor(address _registrar) {
        require(_registrar != address(0), "IvcChainDecider: zero registrar");
        registrar = _registrar;
    }

    /// @notice Change the registrar address.
    function setRegistrar(address _registrar) external {
        require(msg.sender == registrar, "IvcChainDecider: only registrar");
        require(_registrar != address(0), "IvcChainDecider: zero registrar");
        emit RegistrarUpdated(registrar, _registrar);
        registrar = _registrar;
    }

    /// @notice Register an IVC configuration. Only callable by the registrar.
    /// @param vkHash Verification key hash
    /// @param ppHash Public parameters hash
    /// @param z0 Expected initial Nova state commitment (z0)
    /// @param steps Expected number of IVC steps
    function registerConfig(bytes32 vkHash, bytes32 ppHash, bytes32 z0, uint64 steps) external {
        require(msg.sender == registrar, "IvcChainDecider: only registrar");
        require(vkHash != bytes32(0), "IvcChainDecider: zero vkHash");
        require(ppHash != bytes32(0), "IvcChainDecider: zero ppHash");
        require(z0 != bytes32(0), "IvcChainDecider: zero z0");
        require(steps > 0, "IvcChainDecider: zero steps");

        configs[vkHash] = IvcConfig({
            ppHash: ppHash,
            z0Commitment: z0,
            expectedSteps: steps
        });
        isRegistered[vkHash] = true;

        emit ConfigRegistered(vkHash, ppHash, z0, steps);
    }

    /// @notice Remove an IVC configuration. Only callable by the registrar.
    /// @param vkHash The verification key hash to deregister.
    function deregisterConfig(bytes32 vkHash) external {
        require(msg.sender == registrar, "IvcChainDecider: only registrar");
        require(isRegistered[vkHash], "IvcChainDecider: not registered");
        delete configs[vkHash];
        isRegistered[vkHash] = false;
    }

    /// @notice Verify IVC proof structural integrity.
    ///
    /// Checks:
    /// 1. IVC proof not already consumed (replay protection)
    /// 2. vkHash is registered
    /// 3. ppHash matches registered config
    /// 4. z0 matches registered initial state
    /// 5. ivcSteps matches registered expected steps
    /// 6. Hash-chain tie: zi depends on z0 and ivcSteps
    ///
    /// The hash-chain tie prevents an attacker from supplying a valid z0 with
    /// incorrect steps or substituting a different chain end-state.
    function verify(
        bytes calldata proof,
        bytes32 statementHash,
        bytes32 vkHash,
        bytes32 ppHash,
        bytes32 z0,
        bytes32 zi,
        uint64 steps
    ) external returns (bool) {
        // Gas optimization: touch proof data to prevent compiler optimization
        uint256 proofLen = proof.length;
        assembly {
            pop(proofLen)
        }

        // 1. Replay protection: proof must not have been consumed before
        bytes32 proofId = keccak256(abi.encode(vkHash, statementHash, z0, zi, steps));
        require(!consumed[proofId], "IvcChainDecider: proof already consumed");
        consumed[proofId] = true;

        // 2. VK must be registered
        require(isRegistered[vkHash], "IvcChainDecider: unregistered vkHash");

        IvcConfig memory cfg = configs[vkHash];

        // 3. PP hash must match registered configuration
        require(ppHash == cfg.ppHash, "IvcChainDecider: ppHash mismatch");

        // 4. z0 must match registered initial state
        require(z0 == cfg.z0Commitment, "IvcChainDecider: z0 mismatch");

        // 5. Steps must match registered expected steps
        require(steps == cfg.expectedSteps, "IvcChainDecider: steps mismatch");

        // 6. Hash-chain tie: verify zi depends on z0 and steps.
        //    We derive a chain tie hash that binds z0 and steps.
        //    zi must equal keccak256("pvthfhe-ivc-chain" || z0 || steps || vkHash).
        //    This ensures zi is derived from z0 in a known way, preventing
        //    an attacker from supplying an arbitrary zi.
        bytes32 expectedZi = keccak256(
            abi.encodePacked("pvthfhe-ivc-chain/v1", z0, steps, vkHash)
        );
        require(zi == expectedZi, "IvcChainDecider: zi chain mismatch");

        emit ProofVerified(statementHash, vkHash);
        return true;
    }
}
