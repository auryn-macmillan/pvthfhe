# P2 Folding Code-Path Reachability (T8)

## Feature flag analysis

From `crates/pvthfhe-aggregator/Cargo.toml`:
```
real-folding = []
real-verifier = ["real-folding"]
```

- `real-folding` is **NOT in default features** — default features list is empty
- Binary targets in the crate use `required-features = ["real-folding"]`
- Dependents:
  - `pvthfhe-bench/Cargo.toml`: `pvthfhe-aggregator = { path = "../pvthfhe-aggregator" }` — no `features` → only default features (empty) → `real-folding` is **NOT enabled**
  - `pvthfhe-cli/Cargo.toml`: same — `real-folding` **NOT enabled**
  - No crate enables `real-folding` as a dependency feature

**Conclusion: `real-folding` is NEVER activated from any production binary or downstream crate.**

## cfg-gate coverage

Every folding type and function in `src/folding/mod.rs` is gated `#[cfg(feature = "real-folding")]`:
- Lines 83, 92, 99, 109, 115, 120, 128, 134, 150, 153, 202, 211, 219, 224, 263, 281, 296, 307, 324, 335

This means **the entire folding module is dead code** in default, test (without explicit `--features real-folding`), and release builds from downstream crates.

## Public folding API reachability

| Function / Type | Defined at | Feature gate | Callers | Path type | Classification |
|---|---|---|---|---|---|
| `PartyProof` (struct) | `src/folding/mod.rs:19` | `real-folding` | `tests/folding*.rs` | test-only | TEST-ONLY |
| `FinalSnark` (struct) | `src/folding/mod.rs:26` | `real-folding` | `tests/folding*.rs` | test-only | TEST-ONLY |
| `FoldingAccumulator` (struct) | `src/folding/mod.rs:33` | `real-folding` | none found outside folding/ | — | DEAD in production |
| `FoldStatement` (struct) | `src/folding/mod.rs:85` | `real-folding` | `tests/folding*.rs`, `tests/folding_adversarial.rs`, `tests/p2_bench.rs` | test-only | TEST-ONLY |
| `FoldWitness` (struct) | `src/folding/mod.rs:94` | `real-folding` | same | test-only | TEST-ONLY |
| `FoldAccumulator` (struct) | `src/folding/mod.rs:101` | `real-folding` | same | test-only | TEST-ONLY |
| `FinalProof` (struct) | `src/folding/mod.rs:111` | `real-folding` | `tests/p2_bench.rs` | test-only | TEST-ONLY |
| `FoldError` (struct) | `src/folding/mod.rs:118` | `real-folding` | `tests/*` | test-only | TEST-ONLY |
| `NizkStatement` (struct) | `src/folding/mod.rs:122` | `real-folding` | `tests/folding*.rs` | test-only | TEST-ONLY |
| `NizkProof` (struct) | `src/folding/mod.rs:130` | `real-folding` | `tests/folding*.rs` | test-only | TEST-ONLY |
| `FoldingScheme` (trait) | `src/folding/mod.rs:135` | `real-folding` | internally only | — | TEST-ONLY |
| `RealFoldingScheme` (struct) | `src/folding/mod.rs:151` | `real-folding` | internally via free fns | — | TEST-ONLY |
| `fold` (free fn) | `src/folding/mod.rs:203` | `real-folding` | `tests/folding*.rs` | test-only | TEST-ONLY |
| `verify_acc` (free fn) | `src/folding/mod.rs:212` | `real-folding` | `tests/folding*.rs` | test-only | TEST-ONLY |
| `finalize` (free fn) | `src/folding/mod.rs:220` | `real-folding` | `tests/p2_bench.rs` | test-only | TEST-ONLY |

## `RealFoldingScheme` implementation note

From `tests/p2_bench.rs:3`: _"NOTE: All measurements use the surrogate hash-chain implementation of RealFoldingScheme."_
From `tests/p2_bench.rs:135`: _"Surrogate hash-chain implementation of RealFoldingScheme."_

The `RealFoldingScheme` struct is a surrogate using SHA-256 hash chains, not a real LatticeFold+ implementation.

## Summary

- `real-folding` is **never enabled in production** — not in any downstream Cargo.toml
- All folding code is `TEST-ONLY` (requires `--features real-folding` to compile)
- `RealFoldingScheme` uses a hash-chain surrogate, not a real cryptographic folding scheme
- Paper's P2 performance claims (O(polylog n) accumulator verification) apply to the surrogate only

## Evidence files
- `.sisyphus/evidence/audit-p2/build.log` — Cargo.toml feature lines + pub API grep
