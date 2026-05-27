# pvthfhe-bench-full-wiring — Wire All 11 Unwired Circuits Into bench_comparison

> **Status**: ACTIVE — Phase A ready to start
> **Predecessor**: `pvthfhe-benchmark-loop-closure.md` (CLOSED 2026-05-07)
> **Goal**: replace 11 `n/a` rows in `bench/results/comparison-*.md` with real, e2e-derived timings.
> **Decisions (user-confirmed 2026-05-07)**:
>   1. **Approach**: Artifact contract — `pvthfhe-e2e` writes `bench/results/e2e_timings.json`; `bench_comparison` reads it. `bench_comparison` no longer self-measures.
>   2. **Scope**: All 11 unwired rows in one plan.
>   3. **Aggregation**: For 1:N rows, `prove_ms = sum across instances`, `instances_run = N`. Matches Interfold's `aggregation_rule="sum"`.

---

## 1. Architectural Contract

### 1.1 Artifact: `bench/results/e2e_timings.json`

Produced by every `pvthfhe-e2e` run (when not `--dry-run`). Schema:

```json
{
  "schema_version": "1.0.0",
  "n": 3,
  "t": 1,
  "seed": 1,
  "compressor_backend_id": "nova-bn254-grumpkin",
  "phases": {
    "keygen":               { "total_ms": <f64>, "instances_run": 1 },
    "nizk_prove":           { "total_ms": <f64>, "instances_run": <N>, "per_instance_ms": [<f64>; N] },
    "nizk_verify":          { "total_ms": <f64>, "instances_run": <N*(N-1)>, "per_instance_ms": [<f64>; ...] },
    "pvss_share_encrypt":   { "total_ms": <f64>, "instances_run": <N*(N-1)>, "deal_ms": <f64>, "verify_ms": <f64>, "recover_ms": <f64> },
    "pvss_decrypt_prove":   { "total_ms": <f64>, "instances_run": <t>, "per_instance_ms": [<f64>; t] },
    "cyclo_fold":           { "total_ms": <f64>, "instances_run": 1, "fold_depth": <u32> },
    "compressor_prove":     { "total_ms": <f64>, "instances_run": 1 },
    "compressor_verify":    { "total_ms": <f64>, "instances_run": 1 },
    "partial_decrypt":      { "total_ms": <f64>, "instances_run": <t>, "per_instance_ms": [<f64>; t] },
    "aggregate_decrypt":    { "total_ms": <f64>, "instances_run": 1 },
    "noir_nova_wrap":     { "total_ms": <f64>, "instances_run": 1 },
    "onchain_verify":       { "total_ms": <f64>, "instances_run": 1 }
  },
  "produced_at_unix_secs": <u64>,
  "git_sha": "<7-char>"
}
```

**Schema versioning**: `schema_version` is checked by `bench_comparison`; mismatch is a hard error. Bump major on incompatible changes.

**Multiple-run handling**: the Justfile recipe runs e2e 3×. The contract: **last writer wins**. `bench_comparison` reads the most recent file. (Alternative: median across runs — deferred to Phase B if needed.)

### 1.2 Row Mapping (e2e phase → comparison row)

| Comparison Row | E2e Phase Source | Aggregation | instances_run |
|---|---|---|---|
| ZkPkBfv | `nizk_prove` | sum | N |
| ZkShareComputation | `keygen` | n/a (single) | 1 |
| ZkShareEncryption | `pvss_share_encrypt.deal_ms` | sum | N*(N-1) |
| ZkVerifyShareProofs | `pvss_share_encrypt.verify_ms` | sum | N*(N-1) |
| ZkNodeDkgFold | `cyclo_fold` (merged; comparability_note) | sum | 1 (merged) |
| ZkPkAggregation | `cyclo_fold` (merged; comparability_note) | sum | 1 (merged) |
| ZkDkgAggregation | `compressor_prove` | n/a | 1 |
| ZkThresholdShareDecryption | `partial_decrypt` | sum | t |
| ZkDkgShareDecryption | `pvss_decrypt_prove` | sum | t |
| ZkDecryptedSharesAggregation | `aggregate_decrypt` (merged) | sum | 1 (merged) |
| ZkDecryptionAggregation | `aggregate_decrypt` (merged) | sum | 1 (merged) |
| onchain_verify | `onchain_verify` | n/a | 1 |

**Cyclo merge note**: ZkNodeDkgFold and ZkPkAggregation both consume the same `cyclo_fold.total_ms`. Each row's `comparability_note` will state: *"PVTHFHE merges this stage into a single Cyclo fold pass; total_ms is reported in both rows; reader should not double-count."*

**Decrypt-aggregation merge note**: same treatment for ZkDecryptedSharesAggregation and ZkDecryptionAggregation, both pointing to `aggregate_decrypt.total_ms`.

---

## 2. Constraints (carried from predecessor plan)

- **TDD strict**: RED test committed before every implementation change.
- **ZERO new `#[allow(...)]`**.
- `cargo ... -p <crate>` from repo root; never `--workspace` for tests.
- Stub protocol: replace stubs in place; never delete-and-recreate.
- Plan file is read-only for sub-agents; only orchestrator marks completion.
- Existing tests must continue to pass:
  - `crates/pvthfhe-bench/tests/comparison_json_shape.rs` — JSON shape & ordering
  - `crates/pvthfhe-bench/tests/circuit_name_map.rs` — every row has timing OR gap_reason
  - `tests/integration/policy_invariants.rs`
  - `cargo test -p pvthfhe-bench`
  - `cargo test -p pvthfhe-cli`
  - `just bench-comparison-gate`
- `bench-comparison-gate` must stay green: no `surrogate` rows; `real-fallback` only on on-chain row when `verdict: NoGo`.

---

## 3. Phase A — Foundation: schema, artifact contract, one wired phase

### Task A1 — Define `e2e_timings.json` schema crate type ✅ DONE

| Field | Value |
|---|---|
| **ID** | A1 |
| **Owner** | new module `crates/pvthfhe-bench/src/e2e_timings.rs` |
| **Depends on** | — |
| **Gate** | A1 unit tests |

**RED test** (`crates/pvthfhe-bench/tests/e2e_timings_schema.rs`):
1. `e2e_timings::E2eTimings::SCHEMA_VERSION == "1.0.0"`.
2. Round-trip: serialize a fixture → JSON → deserialize → equal.
3. Deserializing a JSON with `"schema_version": "0.9.0"` returns an error mentioning version mismatch.
4. Required phase keys (12 from §1.1 table) are present in serialized output of `E2eTimings::new(n=3, t=1, seed=1)`.

**GREEN criteria**: new types `E2eTimings`, `PhaseTiming` in `pvthfhe_bench::e2e_timings`, used by both producers and consumers. `serde::{Serialize, Deserialize}` derived. No `#[allow]`. All 4 tests pass.

---

### Task A2 — Wire `pvthfhe-e2e` to write `e2e_timings.json` (PVSS phase only) ✅ DONE

| Field | Value |
|---|---|
| **ID** | A2 |
| **Owner** | `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` |
| **Depends on** | A1 |
| **Gate** | A2 integration test |

**RED test** (`crates/pvthfhe-cli/tests/e2e_writes_timings.rs`): run the e2e binary in-process or via `Command`, n=3 t=1 seed=1, assert `bench/results/e2e_timings.json` exists, deserializes via `pvthfhe_bench::e2e_timings::E2eTimings`, and `phases.pvss_share_encrypt.deal_ms > 0.0`. All other phase entries may have `total_ms: 0.0` and `instances_run: 0` for now.

**GREEN criteria**: `pvthfhe-e2e` (non-dry-run path) calls `run_lattice_pvss`, captures `share_encryption_proof_ms` (= deal_ms), `verify_ms`, `recover_ms` into the artifact, writes `bench/results/e2e_timings.json` atomically (write to `.tmp` then rename). Other phase entries are zeroed placeholders. Stdout output unchanged (back-compat).

---

### Task A3 — Refactor `bench_comparison` to consume the artifact ✅ DONE

| Field | Value |
|---|---|
| **ID** | A3 |
| **Owner** | `crates/pvthfhe-bench/src/bin/bench_comparison.rs` |
| **Depends on** | A1, A2 |
| **Gate** | `cargo test -p pvthfhe-bench` + bench-comparison-gate |

**RED test** (`crates/pvthfhe-bench/tests/bench_comparison_reads_artifact.rs`):
1. Place a fixture `e2e_timings.json` in a tempdir; run `bench_comparison` with `--e2e-timings <path>`; assert the produced `comparison.json` ZkShareEncryption row has `prove_ms` matching the fixture's `pvss_share_encrypt.deal_ms`.
2. With missing artifact, `bench_comparison` exits non-zero with a clear error mentioning the artifact path.
3. With `schema_version` mismatch in fixture, `bench_comparison` exits non-zero with a version-mismatch error.

**GREEN criteria**:
- `measure_pvss()` is **deleted** (replaced by artifact read). Per stub-protocol: replace the function body in place, do not delete the function name without callers — but `measure_pvss` has only one caller (main); remove call site and function together in one atomic edit.
- New `--e2e-timings <path>` CLI flag (default `bench/results/e2e_timings.json`).
- `row_for("ZkShareEncryption")` reads from `e2e_timings.phases.pvss_share_encrypt`.
- All other rows still emit `n/a` with their existing `gap_reason` from CIRCUIT_MAP.
- `comparison_json_shape.rs` and `circuit_name_map.rs` tests still pass.
- `just bench-comparison-gate` exits 0.

---

### Task A4 — Update Justfile recipe ✅ DONE

| Field | Value |
|---|---|
| **ID** | A4 |
| **Owner** | `Justfile` |
| **Depends on** | A3 |
| **Gate** | A4 itself |

**GREEN criteria**: `bench-comparison` recipe unchanged externally (still runs e2e 3×, then bench_comparison, then render_comparison) — but now `bench_comparison` consumes `bench/results/e2e_timings.json` written by the last e2e run. Run `just bench-comparison-dryrun 3 1 1` and `just bench-comparison-gate`; both exit 0.

---

## 4. Phase B — Wire the easy 5 rows

Each task: instrument the e2e phase with `Instant::now()` / `elapsed()`, populate the artifact, update `bench_comparison::row_for(...)` to read the new field. Each task owns its own RED test asserting (a) the artifact field is populated post-run and (b) the comparison JSON row has the populated `prove_ms`.

### Task B1 — `compressor_prove` → ZkDkgAggregation ✅ DONE

| Field | Value |
|---|---|
| **ID** | B1 |
| **Depends on** | A4 |

**RED test**: `tests/integration/e2e_phase_timing.rs::compressor_prove_ms_populated`. Asserts `phases.compressor_prove.total_ms > 0.0` after a real e2e run, and the rendered comparison row `ZkDkgAggregation` shows status=`real`, `prove_ms` matching the artifact.

**GREEN criteria**: `Instant::now()` wraps `compressor.prove(&report)` call in `pvthfhe_e2e.rs:~192`. `row_for("ZkDkgAggregation")` reads `phases.compressor_prove.total_ms`. Status flips from `n/a` → `real`. CIRCUIT_MAP entry's `gap_reason` removed (or set to `None`).

---

### Task B2 — `compressor_verify` reused as `onchain_verify` → onchain_verify ✅ DONE

| Field | Value |
|---|---|
| **ID** | B2 |
| **Depends on** | A4 |

**RED test**: `tests/integration/e2e_phase_timing.rs::onchain_verify_ms_populated`. Asserts `phases.onchain_verify.total_ms > 0.0` and the onchain_verify comparison row shows `real-fallback` (because N3a verdict is NoGo per `nova-wrap-feasibility.md`) and the gate accepts it.

**GREEN criteria**: `Instant::now()` wraps the **second** `compressor.verify` call in `pvthfhe_e2e.rs:~219-221` (the one logged as `onchain_verify`). `row_for("onchain_verify")` reads `phases.onchain_verify.total_ms`. Status = `real-fallback` (gate already permits this on the on-chain row when verdict=NoGo). `gap_reason` updated to clarify the fallback path rather than removed.

---

### Task B3 — `partial_decrypt` loop → ZkThresholdShareDecryption ✅ DONE

| Field | Value |
|---|---|
| **ID** | B3 |
| **Depends on** | A4 |

**RED test**: `tests/integration/e2e_phase_timing.rs::partial_decrypt_ms_populated`. Asserts `phases.partial_decrypt.total_ms > 0.0`, `instances_run == t`, `per_instance_ms.len() == t`, and ZkThresholdShareDecryption row's `prove_ms == sum(per_instance_ms)`.

**GREEN criteria**: `decrypt_shares()` (`pvthfhe_e2e.rs:~283-299`) measures each `partial_decrypt` call individually; sum is reported as `total_ms`. Row populated; CIRCUIT_MAP `gap_reason` cleared.

---

### Task B4 — `aggregate_decrypt` (merged) → ZkDecryptedSharesAggregation + ZkDecryptionAggregation ✅ DONE

| Field | Value |
|---|---|
| **ID** | B4 |
| **Depends on** | A4 |

**RED test**: `tests/integration/e2e_phase_timing.rs::aggregate_decrypt_ms_populated`. Asserts `phases.aggregate_decrypt.total_ms > 0.0` and **both** comparison rows ZkDecryptedSharesAggregation and ZkDecryptionAggregation have the same `prove_ms` and a `comparability_note` containing the substring `"merged"`.

**GREEN criteria**: `Instant::now()` wraps `backend.aggregate_decrypt(...)` call. Both rows populated from the same field with explicit merge note. `gap_reason` retained but reworded from `"not wired"` to `"merged into single PVTHFHE aggregate_decrypt pass"`.

---

### Task B5 — `pvss verify_ms` split → ZkVerifyShareProofs ✅ DONE

| Field | Value |
|---|---|
| **ID** | B5 |
| **Depends on** | A4 |

**RED test**: `tests/integration/e2e_phase_timing.rs::pvss_verify_ms_populated`. Asserts ZkVerifyShareProofs row's `prove_ms == phases.pvss_share_encrypt.verify_ms` (already in the artifact since A2). Row status = `real`.

**GREEN criteria**: No new instrumentation needed in e2e (verify_ms already in the artifact from A2). Update `row_for("ZkVerifyShareProofs")` to read `phases.pvss_share_encrypt.verify_ms`. `gap_reason` removed.

---

## 5. Phase C — Wire the harder 6 rows

### Task C1 — Per-dealer NIZK prove timing → ZkPkBfv ✅ DONE

| Field | Value |
|---|---|
| **ID** | C1 |
| **Depends on** | B5 |

**RED test**: `phases.nizk_prove.instances_run == N`, `per_instance_ms.len() == N`, ZkPkBfv `prove_ms = sum(per_instance_ms)`, `instances_run = N`.

**GREEN criteria**: instrument the NIZK loop in `pvthfhe_e2e.rs:~118-130`. Capture per-dealer `Instant::elapsed()` around `RealNizkAdapter::prove`. Aggregate sum. Row populated.

---

### Task C2 — keygen total time → ZkShareComputation ✅ DONE

| Field | Value |
|---|---|
| **ID** | C2 |
| **Depends on** | B5 |

**RED test**: `phases.keygen.total_ms > 0.0`, `instances_run == 1`. ZkShareComputation row populated with `prove_ms = phases.keygen.total_ms`, status=`real`.

**GREEN criteria**: `Instant::now()` wraps `simulator.run()` in `pvthfhe_e2e.rs:~110-113`. Note in `comparability_note`: *"PVTHFHE measures full keygen simulator (Round1+Round2+Round3); Interfold ZkShareComputation is the share-computation step in isolation. Reader-side adjustment may be needed."*

---

### Task C3 — Per-share PVSS decrypt-prove timing → ZkDkgShareDecryption ✅ DONE

| Field | Value |
|---|---|
| **ID** | C3 |
| **Depends on** | B5 |

**RED test**: `phases.pvss_decrypt_prove.instances_run == t`, `per_instance_ms.len() == t`, ZkDkgShareDecryption row populated.

**GREEN criteria**: instrument the `prove_decrypted_share` calls inside `crates/pvthfhe-cli/src/pvss_support.rs:~56-81`. Add a new field `decrypt_prove_total_ms` and `decrypt_prove_per_instance_ms` to `PvssRunArtifacts`. e2e copies these into the timings artifact under `phases.pvss_decrypt_prove`.

---

### Task C4 — `cyclo_fold` (merged) → ZkNodeDkgFold + ZkPkAggregation ✅ DONE

| Field | Value |
|---|---|
| **ID** | C4 |
| **Depends on** | B5 |

**RED test**: `phases.cyclo_fold.total_ms > 0.0`. Both ZkNodeDkgFold and ZkPkAggregation rows populated with the same `prove_ms`, both have `comparability_note` containing `"merged"`.

**GREEN criteria**: `Instant::now()` wraps `folding.fold_all(...)` in `pvthfhe_e2e.rs:~179-184`. Both rows read the same field; explicit merge note added (analogous to B4).

---

### Task C5 — `noir_nova_wrap` instrumentation ✅ DONE

| Field | Value |
|---|---|
| **ID** | C5 |
| **Depends on** | B5 |

**RED test**: `phases.noir_nova_wrap.total_ms >= 0.0` and the artifact field is present. (No comparison row maps directly — this is for completeness and future on-chain wiring.)

**GREEN criteria**: instrument the `noir_nova_wrap` info marker in `pvthfhe_e2e.rs:~217`. Currently this phase logs a digest but does no real work distinct from `compressor_prove`/`onchain_verify`. Decision: capture the wall time between the marker and the next phase start (effectively zero for now). Document in `comparability_note` that this stage is currently a marker, not measurable work, and may be unified with `noir_aggregator_final` in a future revision. **Acceptance**: artifact field present, even if 0.0; no comparison row affected.

---

### Task C6 — Sweep all `n/a` rows ✅ DONE

| Field | Value |
|---|---|
| **ID** | C6 |
| **Depends on** | C1–C5 |

**RED test** (`crates/pvthfhe-bench/tests/no_unwired_rows.rs`): asserts the latest `comparison.json` has zero rows with status `n/a` AND `gap_reason` containing the substring `"not wired"`. (`real-fallback` rows and `merged` `gap_reason`s are still permitted.)

**GREEN criteria**: every CIRCUIT_MAP entry's `gap_reason` is either `None`, mentions `"merged"`, or mentions `"real-fallback"`. No `"not wired"` string remains.

---

## 6. Phase D — Renderer & docs

### Task D1 — Renderer handles new statuses & merge notes ✅ DONE

| Field | Value |
|---|---|
| **ID** | D1 |
| **Depends on** | C6 |

**RED test** (`crates/pvthfhe-bench/tests/render_comparison_smoke.rs`): rendered Markdown contains zero rows with `n/a` in the PVTHFHE column except where explicitly designed (none, after C6). Merge notes appear verbatim in the Notes column.

**GREEN criteria**: `render_comparison.rs` already handles arbitrary `prove_ms`/`status`/`gap_reason`; no changes expected unless a test fails. If a change is needed, update the template and re-run the renderer.

---

### Task D2 — README & ARCHITECTURE updates ✅ DONE

| Field | Value |
|---|---|
| **ID** | D2 |
| **Depends on** | D1 |

**RED test** (`tests/integration/docs_truthful.rs`, extended): assert README's link to `bench/results/comparison-*.md` points to a file with zero `not wired` rows.

**GREEN criteria**: README updated to point at the new comparison report; ARCHITECTURE.md describes the `e2e_timings.json` artifact contract under "Benchmarking".

---

## 7. Phase E — Final review & acceptance

### Task E1 — `/review-work` 5-agent gate

| Field | Value |
|---|---|
| **ID** | E1 |
| **Depends on** | D2 |
| **Gate** | terminal |

**GREEN criteria**: Oracle (goals/constraints), Oracle (code quality), Oracle (security), unspecified-high (hands-on QA), unspecified-high (context mining) all pass. Failures loop back.

---

### Task E2 — User acceptance

| Field | Value |
|---|---|
| **ID** | E2 |
| **Depends on** | E1 |
| **Gate** | terminal |

**GREEN criteria**: user runs `just bench-comparison`, reviews the new `bench/results/comparison-*.md` showing 12/12 rows populated (or with `merged`/`real-fallback` annotations), and signs off.

---

## 8. Dependency Graph

```
A1 ─► A2 ─► A3 ─► A4 ──┬─► B1 ──┐
                       ├─► B2 ──┤
                       ├─► B3 ──┤
                       ├─► B4 ──┤
                       └─► B5 ──┴─► C1 ─┐
                                  C2 ──┤
                                  C3 ──┤
                                  C4 ──┤
                                  C5 ──┘
                                       │
                                       ▼
                                      C6 ─► D1 ─► D2 ─► E1 ─► E2
```

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| `e2e_timings.json` schema drift between binaries | `schema_version` constant; mismatch is a hard error in `bench_comparison` |
| Justfile runs e2e 3× → 3 overwrites of artifact; only last counts | Documented "last writer wins"; future Phase F could median across runs |
| Cyclo merge confusion (one timing → two rows) | Explicit `comparability_note` on both rows; `no_unwired_rows.rs` allows `merged` substring |
| `compressor.verify` is called twice in e2e (compressor_verify + onchain_verify) | Two distinct `Instant::now()` blocks; two distinct artifact fields |
| `noir_nova_wrap` has no measurable distinct work | Acceptance allows 0.0 with a note; no comparison row mapped |
| Test churn: shape/order tests may need updating | Done in A1 fixture; subsequent tasks only update field values |
| Removing `measure_pvss()` orphans existing bench code paths | A3 deletes the call site and function atomically; no external callers exist (verified in exploration) |

---

## 10. Out of Scope (deferred to follow-on plan)

- Median-of-3 aggregation across e2e runs (currently last-writer-wins)
- Per-instance variance/p99 statistics in the comparison JSON
- Real on-chain (forge) gas measurement for `onchain_verify` — currently uses `compressor.verify` as a proxy
- Splitting `keygen` into Round1/Round2/Round3 sub-timings to better match Interfold's `ZkShareComputation`
- Verifier key (`vk_kb`) and proof size (`proof_kb`) population — schema supports it, no instrumentation in this plan
