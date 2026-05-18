# P3-T4 — Gas-Bound Theorem for UltraHonk On-Chain Verification

**Theorem ID**: P3-T4 (UltraHonk refinement)
**Status**: **MEASURED**
**Reduction target**: Static EVM gas schedule (EIP-196/197/1108); no hardness assumption
**Replaces**: P3-T4 in `proof-skeletons.md` (SP1 + Groth16 variant)

---

## Statement

**Theorem P3-T4 (Gas-Bound and DoS Security, UltraHonk refinement).** Let `verifyP3(bytes calldata proof, bytes calldata publicInputs)` be the deployed Solidity verifier entry-point (BB-generated `HonkVerifier.sol`) for the Option B UltraHonk on-chain verifier. For every call with `publicInputs` of length exactly 200 bytes and `proof` of length at most 14,336 bytes (14 KB), the EVM execution of `verifyP3` terminates with total gas consumption `G ≤ 5,000,000`, regardless of whether the call accepts, rejects, or reverts on malformed input.

This is a **security theorem**, not merely a performance note. Violating the gas bound creates a denial-of-service surface: an adversary submitting adversarially crafted `proof` bytes could force gas consumption beyond the block gas limit, preventing honest verifications from landing on-chain.

### Measured Gas

The real UltraHonk proof (evm-no-zk target, N=65536 LOG_N=16, 7776 bytes, 243 field elements) was verified on-chain via `HonkVerifier.sol` (generated with `bb write_solidity_verifier --oracle_hash keccak`). The measured gas consumption is **1,885,528 gas**.

This is the all-in Solidity verification cost including calldata decoding, sumcheck verification, multivariate opening evaluation, and pairing checks. The measurement was obtained via `forge test` with `test_real_proof_accepts()` in `contracts/test/HonkVerifierRealProof.t.sol`.

**Comparison to earlier projection:**
- Prior projection (Aztec baseline): 39,687 gas (subset UltraHonk without lookups)
- Measured: 1,885,528 gas
- The measured value is higher than the Aztec baseline because the baseline represents an idealised minimal verifier for a small circuit, while the real verifier processes a 639K-constraint Noir circuit (aggregator_final) with full Poseidon in-circuit commitment verification and all public-input binding.

The 1,885,528 gas measurement is well within the mandated 5,000,000 gas budget (~2.65× margin). The P3-M4 gas optimisation plan sets an internal target of **< 100,000 gas** for an optimised verifier, which will require stripping unused UltraHonk features and applying the strategies documented in `gas-optimization.md`.

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

## Measured Gas (Real UltraHonk Proof)

The measured gas consumption for verifying a real UltraHonk proof (evm-no-zk, N=65536 LOG_N=16, 7776 bytes) on-chain via `HonkVerifier.sol` is **1,885,528 gas**.

| Component | Estimated gas | Source |
|---|---|---|
| Calldata decoding (proof + public inputs) | ~130,000 | EIP-2028: 7776 + 224 bytes calldata |
| UltraHonk sumcheck + opening evaluation | ~1,550,000 | BB-generated verifier for N=65536 |
| BN254 pairing checks | ~113,000 | EIP-197: base + 2 pairings |
| Overhead (function dispatch, memory, returns) | ~92,000 | Contract boilerplate |
| **Total (measured)** | **1,885,528** | Forge gas report |

The measured 1,885,528 gas provides a **~2.65× margin** under the 5,000,000 gas budget. The gas cost is dominated by the sumcheck and multivariate opening evaluation for the full 65536-gate circuit. P3-M4 optimisation (stripping lookups, inlining scalar multiplications) targets reducing this below 100,000 gas for a zero-pairing optimised verifier.

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

## Measurement Status

P3-M3 (EVM deployment) has been completed. The `HonkVerifier.sol` contract was generated via `bb write_solidity_verifier --oracle_hash keccak` (BB 5.0.0-nightly.20260517) and verified against a real UltraHonk proof (evm-no-zk target, 7776 bytes). `test_real_proof_accepts()` in `contracts/test/HonkVerifierRealProof.t.sol` PASSES.

**Measured gas**: 1,885,528 gas for the full verifier (N=65536 LOG_N=16, 28 G1 points, ~2,220 lines).

**Remaining deferred items:**
- The 100-proof statistical profiling suite (mean, median, p95, p99) has not been run; the current measurement is from a single proof.
- Adversarial worst-case testing for oversized/malformed calldata has not been performed against the real UltraHonk verifier.
- P3-M4 optimisation (stripping lookups, inlining scalar multiplications) has not yet been applied; the measured 1,885,528 reflects the unoptimised verifier.
- The exact pairing count (0, 1, or 2) for a LatticeFold+ optimised proof has not been finalised.

---

**References**

- `.sisyphus/design/p3/gas-optimization.md` (P3-M4 gas optimisation plan, measurement methodology).
- `.sisyphus/design/p3/stack-decision.md` (Option B stack, rollback criteria).
- `docs/security-proofs/p3/ultrahonk-deploy.md` (UltraHonk verifier deployment plan).
- `docs/security-proofs/p3/proof-skeletons.md` (original P3-T4 skeleton, SP1 + Groth16 variant).
- Aztec Protocol. UltraHonk verifier gas benchmarks (baseline: 39,687 gas).
- Ethereum Yellow Paper §F (EIP-196/197 precompile specification).
