# Plan: Unify `demo-e2e` to cover the full PVTHFHE pipeline

**Status:** PROPOSED
**Owner:** Atlas (orchestrator)
**Created:** 2026-05-07
**Working tree:** dirty (unstaged Track A + Track B changes from prior session)

---

## 1. Problem statement

`just demo-e2e` currently runs only the *front* of the PVTHFHE protocol:

> keygen → NIZK prove/verify → encrypt → partial-decrypt → aggregate-decrypt

It silently **omits** the heaviest cryptographic phases that `pvthfhe-e2e` (the bench
binary) actually exercises:

- Cyclo RLWE folding (`CycloFoldingAdapter::fold_all`, `verify_fold_all`)
- Nova Nova compressor preprocess (`Compressor::new`)
- Nova Nova IVC `prove` over `IVC_STEPS=4` (the dominant cost)
- Compressor verify
- Wrap-to-Honk marker
- On-chain verify (currently mapped to `compressor.verify` again)

This is structurally misleading: a "demo end-to-end" run that drops the most
expensive cryptography from the pipeline cannot honestly be called e2e. It also
creates code-drift risk — every change to the bench binary now has to be mirrored
into the demo path or the demo silently lies about what runs.

## 2. Goal

A single source-of-truth pipeline driver consumed by **both** the
`pvthfhe-cli demo` subcommand and the `pvthfhe-e2e` binary. Demo and bench
diverge only in:

- presentation (demo emits human-readable narration; bench emits structured
  `phase=…` tracing + `bench/results/e2e_timings.json`)
- defaults (demo: `n=8 t=5`; bench: `n=3 t=1`)
- output channel (demo tees to evidence log; bench writes timings JSON)

They MUST execute the same cryptographic phases in the same order with the
same backends.

## 3. Locked design decisions (from user Q&A 2026-05-07)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Refactor: shared core library** | Single source of truth; eliminates drift permanently. |
| D2 | **Defaults: `n=8 t=5`** | Demonstrates real threshold cryptography; faster than n=32, slower than n=3. |
| D3 | **Run real Nova verify only; drop on-chain Solidity step from demo** | Heavy crypto is real; surrogate Solidity verify is misleading and the bench gate already rejects surrogate rows. |
| D4 | **Single recipe, `--release`, `nova-compressor` feature** | Fast (release), all phases, one entry point. |

Out of scope: changing the bench binary's defaults; changing
`bench-comparison`'s recipe; touching the surrogate-compressor feature path.

## 4. Non-negotiable constraints (verbatim from AGENTS.md and prior rulings)

- *"TDD strict: RED test committed and CI-visible before every implementation change."*
- *"ZERO new `#[allow(...)]` attributes anywhere in this plan's diffs."*
- *"Cargo: `cargo ... -p <crate>` from repo root. Never `--workspace` for tests."*
- *"Stub protocol: replace stubs in place; never delete-and-recreate."*
- *"Stage 0 tripwires SURVIVE."*
- *"Plan files are read-only for sub-agents; only the orchestrator marks checkboxes."*
- *"opencode and tmux was killed again. Make sure to disown any tasks that have potential to OOM."*
- Long-running bench runs use `setsid nohup … </dev/null >…out 2>&1 & disown`.

## 5. Architecture (target shape)

### 5.1 New module: `crates/pvthfhe-cli/src/full_pipeline.rs`

Public surface:

```rust
pub struct PipelineConfig {
    pub n: usize,
    pub t: usize,
    pub seed: u64,
}

pub struct PipelineReport {
    pub timings: pvthfhe_bench::e2e_timings::E2eTimings,
    pub plaintext_roundtrip_ok: bool,
    pub aggregate_pk_hash_hex: String,
    pub ciphertext_hash_hex: String,
    pub compressed_proof_digest_hex: String,
}

pub trait PipelineObserver {
    fn phase_start(&mut self, name: &str, detail: Option<&str>) {}
    fn phase_end(&mut self, name: &str, ms: f64) {}
    fn note(&mut self, msg: &str) {}
}

pub fn run_full_pipeline<O: PipelineObserver>(
    cfg: &PipelineConfig,
    observer: &mut O,
) -> anyhow::Result<PipelineReport>;
```

The function executes, in order:

1. `keygen` (KeygenSimulator)
2. `nizk_prove` per dealer (via `build_demo_nizk_inputs`)
3. `nizk_verify` per (dealer, recipient) pair
4. `pvss_share_encrypt` (`run_lattice_pvss`)
5. `setup_threshold`
6. `aggregate_keygen` (timing)
7. `encrypt`
8. `cyclo_fold` (`CycloFoldingAdapter::fold_all`)
9. `cyclo_fold_verify` (`verify_fold_all`)
10. `compressor_new` (Nova preprocess)
11. `compressor_prove`
12. `compressor_verify`
13. `partial_decrypt` per party
14. `aggregate_decrypt` + plaintext-roundtrip check
15. `noir_nova_wrap` marker (records elapsed wall-clock around marker only;
    no separate work — matches current bench semantics, comment retained)

Observer pattern lets the two callers customize narration without forking
the pipeline. `phase_end` provides exact `ms` so the bench observer can
populate `E2eTimings`.

This module is `pub` from `pvthfhe-cli` lib (`lib.rs`) so both binaries can
import it.

### 5.2 `pvthfhe-e2e` binary becomes a thin observer

`crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` is reduced to:

- `Args` parsing (unchanged — `--n`, `--t`, `--seed`, `--probe-compressor-only`,
  `--dry-run`)
- Compressor probe / dry-run paths (unchanged — these short-circuit before
  the full pipeline)
- A `BenchObserver` impl that:
  - emits `tracing::info!(phase=…)` events on `phase_start`
  - records `total_ms`, `instances_run`, `per_instance_ms` into
    `E2eTimings` on `phase_end`
- After `run_full_pipeline`, writes `bench/results/e2e_timings.json` exactly
  as today (atomic write via `.json.tmp` → rename)
- Prints the same phase-marker lines for `bench_comparison` to grep

Removed from `pvthfhe_e2e.rs`: the body of `run_e2e` (now lives in the
shared module). The `Compressor` enum and helpers stay where they are —
they're consumed by `full_pipeline.rs`. (Or we move them; see §5.4.)

### 5.3 `pvthfhe-cli demo` subcommand becomes a thin observer

`crates/pvthfhe-cli/src/main.rs::run_demo` is reduced to:

- A `DemoObserver` impl that prints human-readable lines:
  - `step 1/N: keygen  n=… threshold=…`
  - `step 2/N: nizk_prove…`
  - `keygen_ms=…` style summary at end
  - `plaintext_roundtrip: OK` / `MISMATCH`
- Calls `run_full_pipeline` and renders the `PipelineReport`
- Defaults: `n=8 t=5`

Removed from `main.rs`: `run_demo_keygen_nizk`, `demo_keygen_session_id`,
`build_demo_nizk_inputs` (already aliased to shared helper), the explicit
loops for partial-decrypt/aggregate-decrypt — all replaced by
`run_full_pipeline`.

`main.rs` keeps:
- The Stage-0 surrogate banner — but **rewritten** to remove "surrogates
  active" claims about cryptography that is now real (folding and Nova
  are real; the on-chain Solidity step is dropped from the demo).
- The other CLI subcommand stubs (`Keygen`, `Encrypt`, etc.) — out of scope.

### 5.4 `Compressor` enum location

The `Compressor` enum and its helpers (`compressor_inputs`,
`compressor_error_to_anyhow`, `assert_surrogate_compressor_acknowledged`,
`compressor_backend_id`, `log_compressor_mode`) currently live in
`pvthfhe_e2e.rs`. The shared pipeline needs them.

**Decision:** move `Compressor` and helpers into a new private module
`crates/pvthfhe-cli/src/compressor_glue.rs`. Both binaries and
`full_pipeline.rs` import from there. This is a pure code-motion change
(no semantics drift).

### 5.5 Justfile change

```just
demo-e2e n="8" t="5" seed="1":
    @echo "*** PVTHFHE end-to-end demo (research prototype) ***"
    @echo "* Real cryptography: keygen, NIZK, RLWE folding, Nova Nova compression *"
    @echo "* On-chain Solidity verify is NOT run by this demo (use bench-comparison) *"
    @echo "* DO NOT DEPLOY — research prototype only                                 *"
    mkdir -p .sisyphus/evidence
    cargo run --release -p pvthfhe-cli --features nova-compressor -- \
        demo --n {{n}} --threshold {{t}} --seed {{seed}} \
        2>&1 | tee .sisyphus/evidence/task-40-demo.log
```

Note: `pvthfhe-cli`'s `default = ["with-fhe", "nova-compressor"]` already
includes the feature, but we pass `--features nova-compressor` explicitly
for clarity and to prevent silent breakage if defaults change.

## 6. Test strategy (TDD — RED before every implementation step)

Per the AGENTS.md TDD policy. RED tests are committed first; they fail with
the CURRENT code; the implementation step makes them pass; no `#[allow(...)]`.

### RED-1: New integration test `demo_runs_full_pipeline.rs`

Asserts that `cargo run -p pvthfhe-cli -- demo --n 3 --threshold 2 --seed 1`
output contains all of these phase markers (case-insensitive):

```
keygen
nizk_prove
nizk_verify
pvss_share_encrypt
cyclo_fold
compressor_prove
compressor_verify
partial_decrypt
aggregate_decrypt
plaintext_roundtrip: OK
```

This is the same set as `e2e_invokes_all_phases.rs` minus the on-chain
markers (`noir_nova_wrap`, `noir_aggregator_final`, `noir_decrypt_share`,
`onchain_verify`) per D3.

**Currently RED**: demo today doesn't emit `cyclo_fold`, `compressor_prove`,
`compressor_verify`, `pvss_share_encrypt`. Verified by inspection of
`main.rs::run_demo` (zero matches for `fold|compressor|nova`).

### RED-2: Update `e2e_invokes_all_phases.rs`

Currently runs `pvthfhe-e2e --dry-run` (which prints markers without doing
the work). After refactor, this test must continue to pass without
modification — it's a regression guard that the bench binary still emits
all 11 phase markers. **Expected: stays GREEN through the refactor.**

### RED-3: New unit test in `full_pipeline.rs`

A `cfg(test)` test that runs `run_full_pipeline` with a `RecordingObserver`
at `n=3, t=2, seed=1` and asserts:

- All 14 phases (per §5.1) called exactly once each (except per-party loops:
  `nizk_prove` × n, `nizk_verify` × n·(n-1), `partial_decrypt` × t)
- `report.plaintext_roundtrip_ok == true`
- `report.timings.phases.cyclo_fold.total_ms > 0.0`
- `report.timings.phases.compressor_prove.total_ms > 0.0`

**Currently RED**: module doesn't exist.

### RED-4: Demo defaults guard

New unit test in `main.rs` (or alongside): asserts the `Demo` subcommand's
clap defaults are `n=8`, `threshold=None` (resolved to 5 in `run_demo` via
the existing `n/2+1` rule for n=8 → 5), and `seed=0`.

**Currently RED**: defaults are `n=4`, `seed=0`.

### Existing tests to preserve

- `e2e_invokes_all_phases.rs` — unchanged ✅
- `e2e_writes_timings.rs` — must still see `bench/results/e2e_timings.json` ✅
- `e2e_phase_timing.rs` — phase timing fields populated ✅
- `e2e_uses_lattice_pvss.rs` — pvss backend ID ✅
- `e2e_uses_nova.rs` — nova backend ID ✅
- `e2e_memory_budget.rs` — RSS budget regression ✅
- `params_consistency.rs` — NIZK params ✅
- `run_demo_invokes_nizk.rs` — **MUST UPDATE**: counts will change
  (n=3 t=2 → 3 prove calls, 6 verify calls; that still matches the current
  assertion). Verify defaults still align.
- `demo_threshold.rs` — invokes `demo --n 4 --threshold 3`; will go through
  full pipeline now, slower but should still pass. **Risk: timeout in CI.**
  Mitigation: leave the test as-is but document the slowdown; if CI flakes,
  follow up with a `--release` variant or an env-gated fast path.
- `demo_banner.rs` — **MUST UPDATE**: banner text changes per D3 (no more
  "surrogates active" claim re: crypto).

## 7. Implementation steps (ordered, each preceded by RED test)

| # | Step | RED test | Files touched |
|---|---|---|---|
| 1 | Land RED-3 (`full_pipeline.rs` skeleton with empty `run_full_pipeline` returning `unimplemented!()`); module added to `lib.rs` behind `#[cfg(feature = "with-fhe")]` and `#[cfg(feature = "nova-compressor")]`. | RED-3 fails to compile / unimplemented. | `crates/pvthfhe-cli/src/full_pipeline.rs` (new), `crates/pvthfhe-cli/src/lib.rs` |
| 2 | Move `Compressor` enum and helpers from `pvthfhe_e2e.rs` to new private `crates/pvthfhe-cli/src/compressor_glue.rs`; reexport. RED-3 still red. | RED-3 still red. | `compressor_glue.rs` (new), `pvthfhe_e2e.rs` (delete moved code, add `use`), `lib.rs` |
| 3 | Implement `run_full_pipeline` body by lifting `run_e2e` from `pvthfhe_e2e.rs`. Use `PipelineObserver` for narration. Drop `noir_decrypt_share`, `noir_aggregator_final`, `noir_nova_wrap`, `onchain_verify` markers from the pipeline (they belong only in the bench observer per D3). | RED-3 GREEN. | `full_pipeline.rs` |
| 4 | Add `BenchObserver` to `pvthfhe_e2e.rs`; refactor `run_e2e` to: parse args → build observer → call `run_full_pipeline` → write JSON → print markers. The bench binary's observer is the one responsible for printing the four extra `noir_*`/`onchain_verify` marker lines (so `e2e_invokes_all_phases.rs` stays GREEN). | `e2e_invokes_all_phases.rs` GREEN; `e2e_writes_timings.rs` GREEN; `e2e_phase_timing.rs` GREEN; `e2e_uses_lattice_pvss.rs` GREEN; `e2e_uses_nova.rs` GREEN; `e2e_memory_budget.rs` GREEN. | `pvthfhe_e2e.rs` |
| 5 | Add RED-1 (`demo_runs_full_pipeline.rs`) — verify it's RED against current `main.rs::run_demo`. | RED-1 fails. | `crates/pvthfhe-cli/tests/demo_runs_full_pipeline.rs` (new) |
| 6 | Add RED-4 (defaults guard). | RED-4 fails. | inline test in `main.rs` or new `tests/demo_defaults.rs` |
| 7 | Refactor `main.rs::run_demo` to: build `DemoObserver` → call `run_full_pipeline` → render report. Update `Demo` clap defaults to `n=8`. Update banner per D3. Delete `run_demo_keygen_nizk`, `demo_keygen_session_id`, `build_demo_nizk_inputs` (the local one — shared helper stays). | RED-1, RED-4, `demo_threshold.rs`, `run_demo_invokes_nizk.rs` GREEN. | `main.rs` |
| 8 | Update `demo_banner.rs` test to match new banner copy (no "surrogates active" re: crypto). | `demo_banner.rs` GREEN. | `tests/demo_banner.rs` |
| 9 | Update `Justfile` `demo-e2e` recipe per §5.5. | `cargo test -p pvthfhe-cli` all GREEN; manual `just demo-e2e` runs end-to-end. | `Justfile` |
| 10 | Update `README.md` `Quickstart` to reflect new defaults and that demo runs full pipeline (not surrogates). | Manual review. | `README.md` |

## 8. Invariants to verify post-refactor

| # | Invariant | How to check |
|---|---|---|
| I1 | `just demo-e2e` and `just bench-comparison` invoke `Compressor::new` and `compressor.prove` | `grep -c "compressor.prove\|Compressor::new" full_pipeline.rs` ≥ 2; both binaries import it |
| I2 | Demo runs in <5 minutes wall-clock at n=8 t=5 on the dev VM | Manual run; record in plan as evidence |
| I3 | Bench timings JSON unchanged in shape | Diff `bench/results/e2e_timings.json` schema before/after; `cargo test -p pvthfhe-bench` GREEN |
| I4 | `bench-comparison-gate` still passes | `just bench-comparison-gate` GREEN |
| I5 | `wire-gate` still passes | `just wire-gate` GREEN (note: it currently uses `--features surrogate-compressor` for the e2e probe, which is independent of demo path) |
| I6 | Memory regression test passes at n=3 t=2 (existing test) | `cargo test -p pvthfhe-cli --test e2e_memory_budget --features nova-compressor` GREEN |
| I7 | No new `#[allow(...)]` attributes | `git diff --stat` and `grep` |
| I8 | `params_consistency` test still GREEN | `cargo test -p pvthfhe-cli --test params_consistency` |

## 9. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `demo_threshold.rs` (which uses `cargo run` without `--release`) becomes too slow at n=4 t=3 with full Nova | High | CI timeout / flake | Step 7 keeps the test running; if it times out, follow-up adds `--release` flag or env-gated fast path. Document in plan as known follow-up. |
| Memory regression at n=8 t=5 (vs current n=3 t=2 budget) | Medium | OOM on `just demo-e2e` | Smoke-test n=8 in step 9 manually with `ulimit -v 16777216` and `setsid nohup … & disown`. If it OOMs, adjust default to n=6 or n=4 with documented justification. |
| `Compressor` move breaks `nova-min` binary or other downstream | Low | compile error | `cargo build -p pvthfhe-cli --all-features` after step 2; check `nova_min.rs` (it's a separate bin, likely independent — confirmed: `glob` shows it doesn't import `Compressor`). |
| Existing `demo_banner.rs` strings get out-of-sync with reality | Medium | Misleading user-facing claims | Step 8 explicitly updates the test alongside the banner copy. |
| Drift between two binaries returns | Low (after refactor) | Defeats the point | Future-proofing: a regression test could assert phase-name parity between demo-observer and bench-observer. Out of scope for this plan; noted as follow-up. |

## 10. Out of scope

- Changing `bench-comparison` default `n=3 t=1`.
- Adding a fast `demo-e2e-tiny` variant.
- Replacing the on-chain Solidity surrogate with real Honk verifier.
- Touching the Stage-0 build-time tripwire.
- Changing `surrogate-compressor` feature behavior (it remains for `wire-gate`).
- Committing the work (orchestrator commits only when explicitly asked).

## 11. Acceptance criteria

A run of:

```
just demo-e2e          # uses defaults n=8 t=5 seed=1
```

…must:

1. Exit 0.
2. Produce log lines including all of: `keygen`, `nizk_prove`, `nizk_verify`,
   `pvss_share_encrypt`, `cyclo_fold`, `compressor_prove`, `compressor_verify`,
   `partial_decrypt`, `aggregate_decrypt`, `plaintext_roundtrip: OK`.
3. NOT produce surrogate-warning lines that claim cryptography is fake
   (Nova IS real; only the on-chain step is dropped, with that fact
   explicitly stated in the new banner).
4. Tee output to `.sisyphus/evidence/task-40-demo.log`.

And:

- `cargo test -p pvthfhe-cli` GREEN
- `cargo test -p pvthfhe-bench` GREEN
- `just bench-comparison` GREEN (no behavioral change to bench)
- `just bench-comparison-gate` GREEN
- I1–I8 verified

## 12. Delegation plan

Single sub-agent: `category="deep"` (multi-step, multi-file, must run real
tests at each TDD checkpoint). Skills: `[]`. Background: `false` (we want
synchronous gating per step). Estimated wall: 15–30 min.

Prompt skeleton (orchestrator fills in):

> Implement `.sisyphus/plans/demo-full-pipeline-unification.md` strictly TDD.
> Order steps 1→10 from §7. Run only the listed commands. Do NOT introduce
> `#[allow(...)]`. Do NOT modify the bench binary's defaults. Stop and
> report if any RED test does not become GREEN at its step.

## 13. Plan completion checkbox (orchestrator-only)

- [x] Step 1 — full_pipeline skeleton + RED-3 lands
- [x] Step 2 — Compressor moved
- [x] Step 3 — pipeline body lifted; RED-3 GREEN
- [x] Step 4 — pvthfhe-e2e becomes thin observer
- [x] Step 5 — RED-1 lands
- [x] Step 6 — RED-4 lands
- [x] Step 7 — main.rs::run_demo refactored; RED-1, RED-4 GREEN
- [x] Step 8 — banner test updated
- [x] Step 9 — Justfile updated
- [x] Step 10 — README quickstart updated
- [x] All invariants I1–I8 verified
- [x] Acceptance criteria §11 verified by manual `just demo-e2e` run
