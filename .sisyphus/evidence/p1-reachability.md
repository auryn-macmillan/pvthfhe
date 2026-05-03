# P1 NIZK Code-Path Reachability (T7)

## Feature flag analysis

- `crates/pvthfhe-fhe/Cargo.toml`: `default = ["real-nizk"]` — feature is defined and ON by default
- `real-nizk = []` — empty feature (no extra dependencies gated)
- `#[cfg(feature = "real-nizk")]` gates the `pub mod real_nizk` in `lib.rs:13-15`
- `#[cfg(feature = "mock")]` gates `pub mod mock` in `lib.rs:20`
- **Dependents** of `pvthfhe-fhe`:
  - `pvthfhe-aggregator/Cargo.toml`: `features = ["mock"]` — default-features preserved → `real-nizk` IS enabled
  - `pvthfhe-cli/Cargo.toml`: `features = ["mock"]` — same, `real-nizk` IS enabled
  - No dependent explicitly disables default features

Conclusion: **`real_nizk` module compiles in all build modes** (default, test, release).

## Public API reachability

| Function / Type | Defined at | Callers | Classification |
|---|---|---|---|
| `FhersBackend` (struct) | `crates/pvthfhe-fhe/src/fhers.rs:21` | see fhers.rs — delegates all methods to MockBackend | LIVE (but delegates to mock) |
| `FheBackend` (trait) | `crates/pvthfhe-fhe/src/lib.rs:32` | pvthfhe-aggregator, pvthfhe-cli | LIVE-PRODUCTION |
| `FheError` (enum) | `crates/pvthfhe-fhe/src/error.rs:14` | via FheBackend error path | LIVE |
| `MockBackend` (type alias) | `crates/pvthfhe-fhe/src/mock.rs:16` | pvthfhe-aggregator tests | TEST-ONLY |
| `MockBackendInner` (struct) | `crates/pvthfhe-fhe/src/mock_impl.rs:63` | via MockBackend | TEST-ONLY |
| `NizkStatement` (struct) | `crates/pvthfhe-fhe/src/real_nizk.rs:11` | `pvthfhe-bench/src/bin/bench_nizk.rs:4`, `pvthfhe-aggregator/tests/folding*.rs` | BENCH + TEST-ONLY |
| `NizkWitness` (struct) | `crates/pvthfhe-fhe/src/real_nizk.rs:28` | `pvthfhe-bench/src/bin/bench_nizk.rs:44` | BENCH-ONLY |
| `NizkProof` (struct) | `crates/pvthfhe-fhe/src/real_nizk.rs:39` | `pvthfhe-aggregator/tests/folding.rs`, `folding_adversarial.rs`, `p2_bench.rs` | TEST-ONLY |
| `NizkError` (enum) | `crates/pvthfhe-fhe/src/real_nizk.rs:55` | used in LatticeNizk trait bounds | TEST + BENCH |
| `LatticeNizk` (trait) | `crates/pvthfhe-fhe/src/real_nizk.rs:68` | `pvthfhe-bench/src/bin/bench_nizk.rs:4` | BENCH-ONLY |
| `RealNizkAdapter` (struct) | `crates/pvthfhe-fhe/src/real_nizk.rs:85` | `pvthfhe-bench/src/bin/bench_nizk.rs:111,122,133` | BENCH-ONLY |
| `KeygenShare`, `PublicKey`, `Ciphertext`, `DecryptShare`, `Params` | `crates/pvthfhe-fhe/src/types.rs` | via FheBackend trait in aggregator/cli | LIVE-PRODUCTION |

## Summary

- **`real_nizk` module**: compiles under default features but is **BENCH + TEST-ONLY** at the call site — no production binary invokes `LatticeNizk::prove` or `RealNizkAdapter::*` except `bench_nizk` (a benchmark, not a production binary).
- **FheBackend trait**: LIVE in production but implemented by `FhersBackend` which SURROGATE-delegates to `MockBackend` (see T5 finding). No real lattice NIZK is exercised at runtime.
- **Test gate status**: Tests in `crates/pvthfhe-fhe/tests/lattice_nizk*.rs` are gated `#[cfg(feature = "real-nizk")]` — since this feature IS in defaults, the tests DO compile and run under `cargo test`.
- **DEAD candidates**: None — all public items are reachable from at least bench/test. But zero production code exercises the actual lattice NIZK.

## Evidence files
- `.sisyphus/evidence/audit-p1/api.log` — raw pub API grep output
