# Comparison: Interfold Cost Model vs. PVTHFHE

This document compares the cost model and guarantee surface of The Interfold monorepo against the PVTHFHE research prototype.

## 1. Cost Model Comparison

The following table compares the proof count model for a system with $n$ parties and threshold $t$.

| Aspect | Interfold (Noir / Recursive) | PVTHFHE (Batched / Folding) |
|---|---|---|
| **DKG Share Generation** | $2 \cdot n(n-1)$ circuits (C2a, C2b, C3 per share) | $n$ batched two track NIZK instances |
| **DKG Aggregation** | $n$ aggregation circuits (C4) | $n$ batched aggregation instances |
| **Public Key Aggregation** | 1 threshold PK circuit (C5) | 1 aggregation instance |
| **Partial Decryption** | $t$ decryption circuits (C6) | $t$ decryption instances |
| **Final Aggregation** | 1 final aggregation circuit (C7) | 1 final aggregation instance |
| **Proof Compression** | Recursive wrapper circuits | Sonobe Nova IVC (Folding) |
| **Verifier Cost** | Depends on recursion depth | $O(\text{polylog } n)$ or constant |

### Batched Two Track Design
PVTHFHE achieves efficiency by treating the secret key (`sk`) and smudging noise (`e_sm`) material as parallel tracks within the same lattice statement.
* **Batched Relations**: Instead of separate C2a (SK) and C2b (ESM) circuits, PVTHFHE uses `R-share-computation-batched-sk-esm`.
* **Folded Instances**: Per recipient share encryption proofs (C3 equivalent) are folded into a single compressed proof.

## 2. Measured Local Costs (I.1)

Based on benchmarks from `bench/results/i1-one-vs-two-track.json`.

**Hardware**: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S (8 cores, 64GB RAM)

| Metric | One Track (Measured) | Two Track (Measured / Target) |
|---|---|---|
| DKG Prover Time (per party) | 507.4 ms | [unavailable] (Target: $\le 1.5\times$) |
| DKG Prover Time (per share) | 126.85 ms | [unavailable] |
| Decryption Proof Time | [unavailable] | 2713.54 ms (focused API test) |
| Peak Memory | 78,040 kB | 210,732 kB |

**Note on Measurement Status**:
* DKG measurements for one track use a `fallback-dryrun` mode with `demo-seeded-rng` to bypass the `D.1` fail-closed verifier.
* Two track DKG proof producing path is not yet integrated into the e2e benchmark runner.
* The gate status for the two track overhead ratio is `not_fairly_measurable_current_branch`.
* These measurements do **not** demonstrate the intended PVTHFHE performance advantage. They quantify available fallback costs only; a fair advantage claim requires a current-branch real-BFV one-track/two-track runner that emits comparable DKG prover time, verifier time, fold/compression time, proof/wire size, and peak memory without bypassing D.1.

## 3. Guarantee Surface Mapping (C0-C7)

| Interfold ID | Guarantee Role | PVTHFHE Relation / Module | Equivalence Status |
|---|---|---|---|
| **C0** | BFV PK Commitment | `R3.4.1` (encryption binding) | Partial |
| **C1** | PK Generation / Secret Commitment | `R3.4.1` (sk/esm batched) | Partial |
| **C2a** | SK Share Computation | `R3.4.2` (batched) | Implemented |
| **C2b** | ESM Share Computation | `R3.4.2` (batched) | Implemented |
| **C3** | Share Encryption | `R3.4.1` (batched) | Partial (D.1 blocker) |
| **C4** | DKG Share Decryption / Aggregation | `R3.4.3` (aggregate) | Partial |
| **C5** | Threshold PK Aggregation | `R-pk-aggregation` (planned) | Partial |
| **C6** | Threshold Share Decryption | `R3.4.4` (committed smudge) | Partial |
| **C7** | Final Decryption Aggregation | `R3.4.5` (final agg) | Partial |

### Key Caveats and Open Issues
* **D.1 Soundness Blocker**: The `v3` share encryption proof currently lacks a verifier checkable BFV encryption relation. The verifier fails closed by default.
* **Prototype Status**: This is a research prototype, not a production ready or audited system.
* **Backend Differences**: Costs are measured on different toolchains and hardware than the original Interfold benchmarks.
* **Committed Smudging**: While the architecture now supports committed smudging (F.1), the full e2e path remains restricted by the D.1 verifier status.

## 4. Conclusion
PVTHFHE's intended performance advantage remains architecture-driven, not benchmark-demonstrated on the current branch. The available I.1 artifact quantifies fallback/dry-run one-track costs and focused non-comparable two-track probes, but it cannot fairly measure the `<= 1.5x` two-track DKG overhead target because D.1 fails closed and no integrated real-BFV two-track benchmark runner emits comparable metrics. Complete functional equivalence and benchmark-driven overhead validation are deferred until the D.1 fail-closed blocker and missing benchmark path are resolved.
