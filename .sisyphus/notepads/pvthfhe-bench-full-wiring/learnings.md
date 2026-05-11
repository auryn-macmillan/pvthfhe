# Learnings — pvthfhe-bench-full-wiring

## 2026-05-07 Session bootstrap

### Architecture decisions (user-confirmed)
- Approach: Artifact contract — pvthfhe-e2e writes bench/results/e2e_timings.json; bench_comparison reads it
- Scope: All 11 unwired rows
- Aggregation: sum across instances for 1:N rows; per_instance_ms array also stored

### Key file locations
- Schema types: crates/pvthfhe-bench/src/e2e_timings.rs (to be created in A1)
- E2e binary: crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs
- bench_comparison: crates/pvthfhe-bench/src/bin/bench_comparison.rs
- pvss_support: crates/pvthfhe-cli/src/pvss_support.rs
- comparison_map: crates/pvthfhe-bench/src/comparison_map.rs
- Existing tests: crates/pvthfhe-bench/tests/comparison_json_shape.rs, circuit_name_map.rs
- Policy tests: tests/integration/policy_invariants.rs

### Critical constraints
- measure_pvss() in bench_comparison has exactly ONE caller (main); safe to delete atomically in A3
- bench_comparison does NOT currently parse e2e stdout — it runs its own measure_pvss()
- COMPARISON_ROW_NAMES ordering must be preserved (shape test enforces it)
- Every row needs either a real timing OR an explicit gap_reason in CIRCUIT_MAP
- bench-comparison-gate: no surrogate rows; real-fallback only on on-chain row when verdict=NoGo

## 2026-05-07 Task A1 — E2eTimings schema

- Wrote RED integration test first at `crates/pvthfhe-bench/tests/e2e_timings_schema.rs`; initial failure was unresolved import for `pvthfhe_bench::e2e_timings`.
- `E2eTimings::new(...)` should mirror `BenchEnv::capture()` for git SHA capture and use `chrono::Utc::now().timestamp()` for unix seconds.
- Zero-value helpers on nested timing structs make it easy to guarantee all 12 `phases` keys are always present in serialized JSON.
- Verification for A1: `cargo test -p pvthfhe-bench --test e2e_timings_schema` and full `cargo test -p pvthfhe-bench` both passed from repo root.

## 2026-05-07 Task A2 — e2e writes timings artifact
- The `pvthfhe-e2e` binary correctly serializes and atomically writes the `E2eTimings` struct to `bench/results/e2e_timings.json`.
- It uses the mock backend correctly when tested with `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` and `surrogate-compressor`.
- Testing verified the `pvss_share_encrypt` phase timings are populated appropriately.

## 2026-05-07 Task A3 — bench_comparison reads artifact
- Added a RED-to-GREEN integration test covering successful artifact ingestion, missing artifact failure, and schema version mismatch failure for `bench_comparison`.
- `bench_comparison` now accepts `--e2e-timings` (default `bench/results/e2e_timings.json`), validates the artifact schema version up front, and populates the `ZkShareEncryption` row plus phase totals from artifact data instead of running PVSS inline.
- Removed the inline PVSS measurement path (`measure_pvss` and helper/dependency code), which keeps dry-run/test flows dependent on the A2-produced timings artifact rather than recomputing benchmark data.
- Existing comparison-shape/name-map tests stayed green after preserving row ordering and deferring non-wired rows to `CIRCUIT_MAP` gap reasons.

## 2026-05-07 Tasks B1-B5 — phase timing instrumentation
- Added `crates/pvthfhe-cli/tests/e2e_phase_timing.rs` with five RED-first integration tests that run mock e2e, then `bench_comparison`, and assert both artifact fields and comparison rows.
- `pvthfhe_e2e.rs` now records wall-clock timings with `Instant::now()` for `compressor_prove`, the second `compressor.verify` as `onchain_verify`, per-party `partial_decrypt`, and merged `aggregate_decrypt`; partial decrypt returns `(shares, per_instance_ms)` so the artifact can preserve both sum and per-instance timings.
- `bench_comparison.rs` now wires `ZkDkgAggregation`, `onchain_verify`, `ZkThresholdShareDecryption`, `ZkDecryptedSharesAggregation`, `ZkDecryptionAggregation`, and `ZkVerifyShareProofs` from artifact data; merged decrypt rows share the same timing and explicitly mention `merged`, while `onchain_verify` stays `real-fallback`.
- `crates/pvthfhe-bench/tests/comparison_json_shape.rs` needed a shape-rule adjustment: rows with some populated timing fields but null size fields are valid, so `gap_reason` is only mandatory when *all* timing/size fields are null.
- Verification passed with: mock `cargo test -p pvthfhe-cli --no-default-features --features "mock surrogate-compressor" --test e2e_phase_timing`, `cargo test -p pvthfhe-bench`, and `just bench-comparison-gate`.

## 2026-05-07 Tasks C1-C6 — remaining phase timing instrumentation
- Added five RED-first integration tests in `crates/pvthfhe-cli/tests/e2e_phase_timing.rs` for `nizk_prove`, `keygen`, `pvss_decrypt_prove`, `cyclo_fold`, and the `noir_sonobe_wrap` marker; the full mock test target now passes all 10 timing tests.
- `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` now records aggregate keygen time, per-dealer NIZK prove timings, merged `cyclo_fold` time, and a marker-only `noir_sonobe_wrap` phase; `run_lattice_pvss` artifacts are also copied into `phases.pvss_decrypt_prove`.
- `crates/pvthfhe-cli/src/pvss_support.rs` now measures decrypt-side PVSS proof generation per instance and totals via `decrypt_prove_total_ms` plus `decrypt_prove_per_instance_ms`; the current comparison/test setup expects only the first `t` decrypt proofs to be surfaced.
- `crates/pvthfhe-bench/src/bin/bench_comparison.rs` now wires `ZkPkBfv`, `ZkShareComputation`, `ZkDkgShareDecryption`, `ZkNodeDkgFold`, and `ZkPkAggregation` as real rows, with explicit merged notes for the Cyclo rows and a reader-adjustment note for full keygen vs. isolated share computation.
- `crates/pvthfhe-bench/src/comparison_map.rs` no longer contains any `not wired` gap reasons; remaining gap reasons are either merged rows or the allowed on-chain `real-fallback` note.
- Added `crates/pvthfhe-bench/tests/no_unwired_rows.rs` to assert `comparison-dryrun.json` contains zero rows where `status == "n/a"` and `gap_reason` contains `"not wired"`.
- Verification passed with `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 cargo test -p pvthfhe-cli --no-default-features --features "mock surrogate-compressor" --test e2e_phase_timing`, `cargo test -p pvthfhe-bench`, and `just bench-comparison-gate`.

## 2026-05-07 Test-failure follow-up — float tolerance and fixture-backed bench tests
- `crates/pvthfhe-cli/tests/e2e_phase_timing.rs::nizk_prove_ms_populated` needed an inline epsilon comparison because serialized/deserialized timing sums can differ at the 1e-13 scale; `(a - b).abs() < 1e-6` is sufficient here without adding a dependency.
- `crates/pvthfhe-bench/tests/circuit_name_map.rs`, `comparison_json_shape.rs`, and `no_unwired_rows.rs` cannot rely on `bench/results/e2e_timings.json` existing in isolated test environments; each test now creates its own minimal valid `e2e_timings.json` fixture in a unique temp directory and passes `--e2e-timings` explicitly to `bench_comparison`.
- Reusing the existing fixture shape from `bench_comparison_reads_artifact.rs` keeps the tests aligned with the artifact schema and avoids accidental dependence on repo-local generated artifacts.
- Verification passed with `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 cargo test -p pvthfhe-cli --no-default-features --features "mock surrogate-compressor" --test e2e_phase_timing`, `cargo test -p pvthfhe-bench`, and `just bench-comparison-gate`.

## 2026-05-07 Tasks D1-D2 — renderer and docs
- Added `crates/pvthfhe-bench/tests/render_comparison_smoke.rs` as a fixture-backed smoke test that invokes the `render_comparison` binary against `bench/results/comparison-dryrun.json`, normalizes the commit SHA for deterministic output naming, then parses the rendered Markdown table to assert zero `n/a` cells in the PVTHFHE column and at least one `merged` note in the Notes column.
- The existing renderer/template path already exposed `comparability_note` and merge wording in the Notes column, so D1 only needed a confirmation test; no template change was required.
- Extended `tests/integration/docs_truthful.rs` to resolve the comparison report linked from `README.md`, assert the file exists, and verify its table contains zero `not wired` rows.
- Updated `README.md` to keep the current `comparison-5d7853a.md` link while explicitly stating that all 12 comparison rows are populated, and added an `ARCHITECTURE.md` Benchmarking section documenting the `e2e_timings.json` → `comparison.json` → rendered comparison Markdown artifact chain plus the `schema_version` `1.0.0` / 12-phase contract.
- Because the checked-in comparison report was stale, regenerating `bench/results/comparison.json` and `bench/results/comparison-5d7853a.md` was necessary before the truthful-docs assertion could pass.
- Verification passed with `cargo test -p pvthfhe-bench`, `cargo test --test docs_truthful`, and `just bench-comparison-gate`.

## 2026-05-07 Probe P0' — Sonobe isolated memory investigation
- `crates/pvthfhe-compressor/tests/sonobe_isolated_mem.rs` currently samples `/proc/self/statm` every 100ms around `SonobeCompressor::new(1)`, `prove`, and `verify`; the test compiles/runs and is being held RED intentionally by a terminal panic after reporting the observed peak RSS.
- `crates/pvthfhe-compressor/src/sonobe/mod.rs` now emits `tracing::info!` RSS markers after parameter serialization, at `deserialize_params` start / post-prover-deserialize / post-verifier-deserialize, after `Nova::init`, after each `prove_step`, and after IVC proof serialization.
- `crates/pvthfhe-compressor/examples/sonobe_isolated.rs` plus `.sisyphus/scripts/run-sonobe-isolated.sh` produced runnable evidence under `.sisyphus/evidence/bench-comparison-mem/p0p/`; the captured run showed RSS rising from ~93 MiB after `new()` to ~223 MiB after `prove()`, while `/usr/bin/time -v` reported max RSS 244112 KiB.
- Post-change verification succeeded for `cargo build --release --example sonobe_isolated -p pvthfhe-compressor`, `cargo test -p pvthfhe-compressor --test sonobe_roundtrip`, `--test spec_addendum_present`, and `--test trait_object`; the full `cargo test -p pvthfhe-compressor` now fails only because the new RED probe test is intentionally failing.
