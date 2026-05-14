# P3-T4 — Gas-Bound Theorem for UltraHonk On-Chain Verification

**Theorem ID**: P3-T4 (UltraHonk refinement)
**Status**: **DEFERRED — awaiting prerequisite milestone P3-M3 (EVM deployment with real HonkVerifier)**
**Reduction target**: Static EVM gas schedule (EIP-196/197/1108); no hardness assumption
**Replaces**: P3-T4 in `proof-skeletons.md` (SP1 + Groth16 variant)

---

## Statement

**Theorem P3-T4 (Gas-Bound and DoS Security, UltraHonk refinement).** Let `verifyP3(bytes calldata proof, bytes calldata publicInputs)` be the deployed Solidity verifier entry-point (BB-generated `HonkVerifier.sol`) for the Option B UltraHonk on-chain verifier. For every call with `publicInputs` of length exactly 200 bytes and `proof` of length at most 14,336 bytes (14 KB), the EVM execution of `verifyP3` terminates with total gas consumption `G ≤ 5,000,000`, regardless of whether the call accepts, rejects, or reverts on malformed input.

This is a **security theorem**, not merely a performance note. Violating the gas bound creates a denial-of-service surface: an adversary submitting adversarially crafted `proof` bytes could force gas consumption beyond the block gas limit, preventing honest verifications from landing on-chain.

### Baseline Projection

The Aztec Protocol reference implementation of a **subset UltraHonk verifier** (without lookup arguments) has a published baseline gas measurement of **39,687 gas** (source: `.sisyphus/design/p3/gas-optimization.md` §2).

This baseline represents a floor, not a ceiling. The actual gas consumption depends on:

- The final proof structure produced by P3-M2 compression.
- The exact number of public inputs (7 fixed, 200 bytes total).
- Any LatticeFold+-specific additions layered on top of the standard UltraHonk verifier.
- Whether the LatticeFold+ proof uses the zero-pairing, single-pairing, or double-pairing path.

The P3-M4 gas optimisation plan sets an internal target of **< 100,000 gas**, well within the 5,000,000 gas budget mandated by P3-T4.

## P3 Stack Context

The on-chain verifier for the Option B stack is the BB-generated `HonkVerifier.sol` contract. This contract evaluates an UltraHonk proof over BN254 using:

- BN254 pairing precompiles (`ecPairing` at address `0x08`, EIP-197): ~45,000 gas base + ~34,000 gas per pairing.
- BN254 scalar multiplication precompile (`ecMul` at address `0x07`, EIP-196): ~6,000 gas each.
- No lookup-argument verification (LatticeFold+ proofs do not use lookups, so log-derivative checks are stripped per P3-M4 §3.1).

The UltraHonk verifier is a fixed-depth computation: there are no loops parameterised by fold depth (which is compressed into the constant-size proof), adversary-chosen public-input content (public inputs are fixed-width scalars), or proof size (bounded by the Solidity ABI decoder).

## Gas Measurement Methodology

### Tooling

1. **Primary**: Foundry gas profiler:
   ```
   forge test --gas-report --match-contract HonkVerifierTest
   ```

2. **Per-opcode granularity**: Custom Foundry test using `gasleft()` snapshots before and after each logical verification phase:
   - Calldata decoding
   - Public-input hashing
   - Sumcheck verification
   - Multilinear opening evaluation
   - Pairing check(s)

### Statistical Protocol

1. Generate **100 proof submissions** with real LatticeFold+ proofs from the P3-M2 pipeline.
2. Record gas consumption per submission.
3. Report: mean, median, p95, p99, minimum, maximum.
4. Confirm the worst-case measurement stays under the 5,000,000 gas ceiling.
5. If the maximum exceeds 5,000,000, the theorem is violated and the P3 stack must be re-evaluated (see rollback criteria in `.sisyphus/design/p3/stack-decision.md`).

### Adversarial Worst-Case Testing

Beyond valid proofs, the measurement suite must include:

- **Oversized calldata**: Proof bytes exceeding 14 KB. The Solidity ABI decoder must reject these before any cryptographic computation. Measurement confirms gas stays below the budget on the reject path.
- **Malformed proof bytes**: Random byte strings of valid length. The verifier must reject early (ideally at sumcheck or opening evaluation) without consuming pairing precompile gas proportional to valid proof verification.
- **Boundary case**: Exactly 14 KB of proof bytes with valid structure but invalid content. Gas should not exceed the valid-proof case by more than a small constant factor.

### Regression Gate

After each P3-M4 optimisation round, re-run the full 100-proof suite. Any regression that pushes the mean above 100,000 gas or the maximum above 5,000,000 gas fails the gate.

## Conservative Gas Decomposition (Projected)

Using the Aztec baseline of 39,687 gas as a starting point, the expected gas breakdown for the LatticeFold+ UltraHonk verifier is:

| Component | Projected gas | Source |
|---|---|---|
| Calldata decoding (proof + public inputs) | ~3,500 | EIP-2028 calldata schedule |
| Public-input hashing (Keccak/Poseidon) | ~1,000 | Fixed 200-byte input |
| UltraHonk sumcheck (on-chain portion) | ~15,000 | Aztec baseline partitioning |
| Multilinear opening evaluation | ~8,000 | Aztec baseline partitioning |
| BN254 pairing checks (0–2) | 0–113,000 | EIP-197: 45k base + 34k/pairing |
| Overhead (function dispatch, memory, returns) | ~3,000 | Fixed |
| LatticeFold+-specific additions | 0–12,000 | TBD from P3-M2 proof structure |
| **Conservative upper bound** | **30,500–155,500** | Depends on pairing count |

Even in the worst case (double pairing, 155,500 gas), the margin under the 5,000,000 gas budget exceeds **32×**. The baseline projection of 39,687 gas for a zero-pairing subset verifier provides a **126× margin** under the budget.

## Absence of Dynamic Loops

The `HonkVerifier.sol` contract, as generated by Barretenberg, contains no loops over adversary-controlled data. Every opcode path is bounded by compile-time constants derived from the fixed circuit structure. Specifically:

- The sumcheck loop iterates over a fixed number of rounds determined by the circuit's log-degree, not the proof content.
- The multivariate opening evaluation iterates over a fixed number of opening points.
- The pairing check iterates over a fixed number of pairings (0–2).

This static structure means the gas cost cannot grow with adversary-chosen data beyond the worst-case calldata decoding cost.

## Dependencies

| Dependency | Role |
|---|---|
| EIP-197 (Byzantium): BN254 pairing precompile | Pairing gas schedule (45k base + 34k/pairing) |
| EIP-196 (Byzantium): BN254 scalar multiplication precompile | Scalar multiplication gas |
| EIP-2028 (Istanbul): calldata gas schedule | Calldata cost computation |
| BB UltraHonk verifier generator (`bb write_solidity_verifier`) | Produces the deployed `HonkVerifier.sol` |
| P3-M2 (MicroNova compression) | Produces the real proofs to measure |
| P3-M3 (EVM deployment) | Deploys the verifier for measurement |
| P3-M4 (gas optimisation) | Strips unused UltraHonk features, applies optimisations |
| `.sisyphus/design/p3/gas-optimization.md` | Optimisation strategy and measurement protocol |
| `.sisyphus/design/p3/stack-decision.md` | Rollback criteria if gas budget is exceeded |

## Deferral Rationale

This document is marked **DEFERRED** because:

1. **P3-M3 (EVM deployment)** has not completed. The `HonkVerifier.sol` contract has not been deployed to Sepolia and cannot be measured.
2. **P3-M2 (MicroNova compression)** has not produced real LatticeFold+ proofs. Without real proofs, there is nothing meaningful to submit to the verifier for gas measurement.
3. The BB Solidity verifier generator (`bb write_solidity_verifier`) in the currently pinned version (5.0.0-nightly.20260324) produces a verifier with incorrect VK shape and requires an upgrade before deployment (per `.sisyphus/design/p3/gas-optimization.md` §5).
4. The exact pairing count (0, 1, or 2) for the LatticeFold+ proof has not been finalised; this is the dominant variable in the gas budget.

Once P3-M3 deploys the real verifier and P3-M4 completes the baseline profiling, this document will be updated to include:

- The measured gas mean, median, p95, p99, min, and max from the 100-proof suite.
- The confirmed pairing count and its impact on the budget.
- A concrete upper bound `G_max` verified by adversarial test vectors.
- Confirmation that `G_max ≤ 5,000,000` gas under all input conditions.

---

**References**

- `.sisyphus/design/p3/gas-optimization.md` (P3-M4 gas optimisation plan, measurement methodology).
- `.sisyphus/design/p3/stack-decision.md` (Option B stack, rollback criteria).
- `docs/security-proofs/p3/ultrahonk-deploy.md` (UltraHonk verifier deployment plan).
- `docs/security-proofs/p3/proof-skeletons.md` (original P3-T4 skeleton, SP1 + Groth16 variant).
- Aztec Protocol. UltraHonk verifier gas benchmarks (baseline: 39,687 gas).
- Ethereum Yellow Paper §F (EIP-196/197 precompile specification).
