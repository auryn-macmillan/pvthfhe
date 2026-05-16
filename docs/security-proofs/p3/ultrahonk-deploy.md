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

## Gas Projection

Aztec Labs has published a baseline gas measurement for a subset
UltraHonk verifier:

- **Projected gas**: ~39,687

This figure should be treated as a floor, not a ceiling.  The actual
gas consumption depends on the exact proof structure produced by
P3-M2 compression, including proof size, number of public inputs, and
any additional calldata framing.  Measurement and confirmation against
a real MicroNova root proof will be part of the post-deployment
acceptance criteria.

The P3 gas budget ceiling is 5,000,000 (set by P3-T4), and this
projection sits comfortably within that bound.

## Deployment Status

**Status: DEFERRED**

The deployment is blocked on P3-M2 (MicroNova compression).  Until P3-M2
produces a production-ready compression proof with the correct
`FoldVerifierStepCircuit` UltraHonk wrap, there is no meaningful proof
to submit on-chain.  Deploying the verifier contract ahead of that
milestone would serve only as a dry-run exercise and is not prioritized.

Once P3-M2 delivers, the deployment checklist is:

1. Pin the Aztec protocol commit hash for the `HonkVerifier.sol`
   release used.
2. Compile with `solc --optimize` and record bytecode hash.
3. Deploy to Sepolia via `forge create`.
4. Submit a sample UltraHonk proof from P3-M2 to the deployed contract.
5. Measure and record actual gas consumption.
6. Verify the contract on Etherscan Sepolia.
7. Update `docs/security-proofs/p3/proof-skeletons.md` with the
   measured gas figure.

## References

- Aztec protocol repository: `https://github.com/AztecProtocol/aztec-packages`
- UltraHonk specification: Honk proving system, BN254 curve
- P3-M2 plan: `.sisyphus/plans/p3-m2-micronova-compression.md`
- P3 theorem inventory: `docs/security-proofs/p3/theorem-inventory.md`
- P3 gas-bound theorem (T4): `docs/security-proofs/p3/T4.md`
