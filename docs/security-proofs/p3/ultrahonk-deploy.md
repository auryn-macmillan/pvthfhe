# UltraHonk EVM Verifier Deployment

This document records the deployment plan for the UltraHonk verifier
Solidity contract (`HonkVerifier.sol`) that validates P3-M2 MicroNova
compression proofs on-chain.  The deployment is currently **DOCUMENTED — implementation deferred to post-p3-m2**
until P3-M2 produces production-ready compression proofs.

## Source Contract

**Contract**: `HonkVerifier.sol`
**Origin**: Aztec Labs protocol monorepo (`aztecprotocol/aztec-packages`)
**Circuit**: UltraHonk proving system over BN254
**Role**: On-chain verifier for the `FoldVerifierStepCircuit`'s
UltraHonk-wrapped proof produced by P3-M2 compression.

The UltraHonk verifier checks the final recursion-level proof that attests
to the validity of the MicroNova folding chain.  It is deployed as an
external dependency: we do not ship `HonkVerifier.sol` in this repository.
Instead, the deployment references a pinned commit hash from the Aztec
protocol repository, which serves as the canonical source.

## Deployment Target

| Item | Value |
|------|-------|
| Network | Sepolia testnet |
| Toolchain | Foundry (`forge create`, `forge verify-contract`) |
| Compiler | `solc` with `--optimize` (optimizer enabled, runs tuned for gas) |
| Verification | Etherscan Sepolia |

## BN254 Precompile Dependency

The UltraHonk verifier relies on the BN254 elliptic-curve pairing
precompiles available on Ethereum mainnet and Sepolia at the standard
addresses:

| Address | Operation |
|---------|-----------|
| `0x06` | `ecAdd` (BN254 addition) |
| `0x07` | `ecMul` (BN254 scalar multiplication) |
| `0x08` | `ecPairing` (BN254 pairing check) |
| `0x09` | `blake2f` compression (not used by UltraHonk but co-located for reference) |

The deployed verifier must confirm these precompiles are available on the
target network.  Sepolia implements EIP-196 (pairing) and EIP-197
(addition/scalar multiplication), so no changes to precompile behavior
are expected relative to mainnet.

## Gas Measurement

- **Measured gas**: 1,885,528 (real UltraHonk proof, evm-no-zk target, 7776 bytes, N=65536 LOG_N=16)
- **Prior projection (Aztec baseline)**: ~39,687 (idealised minimal verifier)
- **Gas budget ceiling**: 5,000,000 (P3-T4)
- **Margin**: ~2.65× under budget

The measured value reflects the full verifier cost for a 639K-constraint Noir circuit with
in-circuit Poseidon commitment verification. P3-M4 optimisation targets reducing this below 100,000 gas.

## Deployment Status

**Status: VERIFIED (local)**

The `HonkVerifier.sol` contract has been generated via `bb write_solidity_verifier --oracle_hash keccak`
(BB 5.0.0-nightly.20260517) from the Noir aggregator_final circuit (G2 full in-circuit Poseidon, 639K constraints,
N=65536 LOG_N=16). Real UltraHonk proofs (evm-no-zk target, 7776 bytes) verify successfully:
`test_real_proof_accepts()` in `contracts/test/HonkVerifierRealProof.t.sol` PASSES. VK hash matches on-disk value.
Measured gas: 1,885,528 gas.

Deployment to Sepolia testnet and Etherscan verification remain deferred pending P3-M2 MicroNova compression.
The local verification confirms the pipeline works end-to-end: Noir aggregator_final → bb prove → HonkVerifier.sol.

## References

- Aztec protocol repository: `https://github.com/AztecProtocol/aztec-packages`
- UltraHonk specification: Honk proving system, BN254 curve
- P3-M2 plan: `.sisyphus/plans/p3-m2-micronova-compression.md`
- P3 theorem inventory: `docs/security-proofs/p3/theorem-inventory.md`
- P3 gas-bound theorem (T4): `docs/security-proofs/p3/T4.md`
