# Plan: Diagnose & Fix `bench-comparison` Memory Growth

**Status**: REVISED 2026-05-07 (probe ordering locked by user: 1 → 3 → 2 = instrument → bump rev → IVC_STEPS=1)
**Owner**: Prometheus
**Created**: 2026-05-07
**Trigger**: Real `pvthfhe-e2e --n 3 --t 1 --seed 1` showed linear memory growth from 3.3 GB → 33+ GB over 5 minutes during the post-`nizk_verify` / `compressor_prove` window with no plateau. Aborted at 33 GB before OOM.

**Updated evidence (2026-05-07, agent `bg_2f11b3a3`)**: Quantitative budget for n=3, N=8192:
- FHE persistent state (party_states, sk_poly_sum, sk_shamir_shares, sk_poly_sum_poly): ~1.31 MiB
- NIZK proofs (3 × ~600 KiB each): ~1.85 MiB
- PVSS ciphertexts: ~2.36 MiB
- CycloFoldAllReport at compressor.prove input boundary: ~64 bytes (two 32-byte digests)
- **Total non-Sonobe persistent state: ~5–6 MiB**
- Therefore **H3 (FHE residue) is essentially DISPROVEN** as primary cause; cannot account for >~10 MiB.
- The only candidate for tens-of-GiB growth is **Sonobe (`SonobeCompressor::prove` → `deserialize_params` + `Nova::init` + 4× `prove_step`)**.

**Background research status**:
- `bg_7ad87d74` (call-path map): COMPLETE — confirmed per-call deserialize + IVC=4
- `bg_2f11b3a3` (FHE alloc hotspots): COMPLETE — see budget above
- `bg_bcc7d6a6` (arkworks Pedersen sizing): FAILED PERMANENTLY (6 retry attempts; all fallback models unavailable)
- `bg_56d19937` (Sonobe Nova memory issues): FAILED PERMANENTLY (6 retry attempts; all fallback models unavailable)

The two failed agents will be **replaced by direct probes** (P0' instrumentation + P3 newer-rev attempt) rather than retried.

---

## 1. Observed Symptoms (verbatim)

- `mem.log` from `.sisyphus/evidence/bench-comparison-real/`:
  | t | mem_used_mb | swap_used_mb | latest log phase |
  |---|---|---|---|
  | 0s | 3,304 | 33 | start |
  | 30s | 5,472 | 33 | post-nizk_verify (last log line) |
  | 60s | 7,701 | 33 | (no log) |
  | 90s | 9,836 | 33 | (no log) |
  | 120s | 14,110 | 33 | (no log) |
  | 180s | 18,882 | 33 | (no log) |
  | 240s | 24,861 | 33 | (no log) |
  | 300s | 28,881 | 33 | (no log) |
  | 320s | 33,247 | 33 | (no log, aborted) |
- Log silent for ~5 minutes after `nizk_verify dealer=3 recipient=2` (line in `run.log`)
- `RAYON_NUM_THREADS=4`, `--release` build, `IVC_STEPS=4` in `SonobeCompressor::prove`
- Swap NEVER touched — pure RAM growth
- Linear (~5 GB/min), no plateau → suggests bounded-but-large allocation OR genuine leak

## 2. Goal

Get `just bench-comparison 3 1 1` to complete on the 62 GB host without OOM, producing real timings for `bench/results/comparison-*.md` populated for all 12 rows.

## 3. Hypothesis Space

**Update from bg_7ad87d74**: Compressor construction (`Compressor::new(seed)`) at e2e.rs line 160 runs `SonobeNova::preprocess` ONCE, very early. Memory growth starts AFTER `nizk_verify`, so preprocess is NOT the trigger. The growth window aligns with `compressor.prove(&report)` (line 216), which:
- re-deserializes prover+verifier params from in-memory bytes EVERY call (mod.rs:127-140 → 149)
- runs `SonobeNova::init` + 4× `prove_step`
- inputs are tiny (two 32-byte digests), so input data is irrelevant

Sharpened hypothesis space:

| H# | Hypothesis | Discriminator |
|---|---|---|
| **H1** | `pp_deserialize_with_mode` allocates a large prover param structure (Pedersen ck embedded). Per-thread rayon scratch multiplies it during MSM | Single-thread (RAYON_NUM_THREADS=1) drops peak proportionally; isolated `prove()` call reproduces growth |
| **H2** | `IVC_STEPS=4` per-step witness retention; each `prove_step` allocates and retains R1CS witnesses or commitment scratch | Reducing `IVC_STEPS=1` reduces peak ~4× |
| **H3** | FHE state (PVSS shares, NIZK proofs, cyclo accumulator at N=8192) is held in scope when `compressor.prove` runs, dominating peak | Pre-compressor RSS measurement (no Sonobe call) shows multi-GB FHE residue |
| **H4** | A newer Sonobe rev fixed a known memory regression / leak | Switching rev resolves it |
| **H5** | `--release` codegen of arkworks MSM monomorphizations holds per-thread scratch in `ark-poly` FFT/`ark-ec` MSM | RAYON_NUM_THREADS=1 curative; perf trace shows bulk in MSM |
| **H6** *(new)* | Per-call `pp_deserialize`/`vp_deserialize` is the leak — params are deserialized fresh each call but never freed (ownership escapes via stored Nova handle) | Calling `prove` twice in same process doubles RSS without halving on second call |

Background agents (launched 2026-05-07T13:35Z) are gathering evidence for all five hypotheses in parallel.

## 4. Method (locked execution order: P0' → P3 → P2)

User-confirmed sequence on 2026-05-07: **(1) instrument and run isolated Sonobe probe → (3) bump Sonobe rev if instrumentation shows recoverable issue upstream → (2) reduce IVC_STEPS as final mitigation**. P1 (RAYON_NUM_THREADS=1) and P4 (pre-compressor RSS) are now redundant given the FHE budget evidence and merged into P0'.

Each probe is **detached via `setsid nohup ... & disown`** with `STATUS` / `mem.log` / `*.time` capture so the OOM-killer cannot reach OpenCode/tmux. Each probe writes evidence under `.sisyphus/evidence/bench-comparison-mem/<probe-id>/`.

### Probe P0' — Instrument Sonobe + isolated Nova reproducer  *(STEP 1, was option "1")*

**Goal**: Pinpoint which of `pp_deserialize_with_mode`, `vp_deserialize_with_mode`, `Nova::init`, `nova.prove_step` (×4), or `nova.compress` is the dominant allocator and how much per call.

**Sub-tasks**:
1. **P0'.a — RED test (numeric memory threshold)**: Add `crates/pvthfhe-compressor/tests/sonobe_isolated_mem.rs` that:
   - Creates `SonobeCompressor::new(1)`
   - Calls `prove(&[0u8;32], &[0u8;32])`
   - Calls `verify(...)`
   - Asserts peak RSS < 12 GB (will FAIL on current code → RED)
   - Use `peak_alloc::PeakAlloc` global allocator OR poll `/proc/self/statm` in a background thread.
2. **P0'.b — Instrument SonobeCompressor**: In `crates/pvthfhe-compressor/src/sonobe/mod.rs`, add `tracing::info!` log lines at:
   - After serialization in `new()` (~line 86): `prover_key_bytes_len = ?`, `verifier_key_bytes_len = ?`
   - Start of `deserialize_params` (~line 127): RSS_before
   - End of `deserialize_params`: RSS_after, delta
   - After `Nova::init`: RSS_after_init
   - After each `prove_step` iteration (i=0..3): RSS_after_step_i
   - After serialize of IVC proof: final RSS, total bytes emitted
   - **No new `#[allow(...)]`**. Use existing `tracing` setup.
3. **P0'.c — Stand-alone reproducer**: Add `crates/pvthfhe-compressor/examples/sonobe_isolated.rs` that drives the same code path independently of `pvthfhe-cli`. Build with `cargo build --release --example sonobe_isolated -p pvthfhe-compressor`.
4. **P0'.d — Run detached**: `setsid nohup .sisyphus/scripts/run-sonobe-isolated.sh & disown` (script to be written), capturing `/usr/bin/time -v`, RSS sampler, and the new tracing log.

**Discriminators**:
- If `deserialize_params` delta is multi-GB and grows on second call → **H6 confirmed** (per-call leak in deserialize)
- If `Nova::init` delta is the bulk → **H1 variant** (SRS expansion at init)
- If each `prove_step` adds GBs cumulatively → **H2 confirmed** (per-step retention)
- If isolated reproducer stays < 8 GB but full e2e bloats → **integration interaction**, escalate

**Cost**: ~30 min instrumentation + 5 min run.

### Probe P3 — Newer Sonobe rev  *(STEP 2, was option "3")*

**Goal**: Test whether an upstream fix exists for whichever call P0' identified as the leak.

**Pre-condition**: P0' identified a specific call (deserialize / init / step) as the dominant allocator. If P0' shows the leak is intrinsic (e.g. SRS at chosen security parameter), skip directly to P2.

**How**:
1. Snapshot current rev `63f2930d363150d4490ce2c4be8e0c25c2e1d92c` in `.sisyphus/evidence/bench-comparison-mem/p3/before-rev.txt`.
2. Update `crates/pvthfhe-compressor/Cargo.toml` `folding-schemes` rev to `main` HEAD (look up via `gh` or `git ls-remote https://github.com/privacy-scaling-explorations/sonobe HEAD`).
3. `cargo update -p folding-schemes` then `cargo build --release -p pvthfhe-compressor`. If API broke → revert + record blockers + jump to P2.
4. Re-run P0' isolated reproducer with new rev.

**Discriminators**:
- peak RSS < 10 GB → **H4 confirmed**, mitigation = bump rev
- peak RSS unchanged → H4 rejected, proceed to P2
- compile breaks → H4 unactionable, proceed to P2

**Cost**: 15–60 min (uncertain on API drift).

### Probe P2 — IVC_STEPS=1 reduction  *(STEP 3, was option "2")*

**Goal**: Final mitigation if upstream rev didn't help. Reduce per-step retention from 4 → 1.

**Pre-condition**: P3 did not resolve OR P0' showed `prove_step` is the cumulative dominant allocator.

**How**:
1. **RED test**: Update `crates/pvthfhe-compressor/tests/sonobe_isolated_mem.rs` threshold to peak < 8 GB (still FAIL on IVC=4, will GREEN on IVC=1 if H2 dominant).
2. Edit `crates/pvthfhe-compressor/src/sonobe/mod.rs:27` `IVC_STEPS` 4 → 1.
3. Verify the IVC=1 trajectory still produces a valid Nova proof + Decider artifact (existing `pvthfhe-compressor` tests must still pass).
4. Re-run P0' isolated reproducer.
5. If GREEN, run full `just bench-comparison 3 1 1` end-to-end.

**Open question**: Does the protocol require ≥4 IVC steps for soundness/scope? Spec check needed. If the cyclo-fold report binds via accumulator digest only, 1 step may be sufficient — DOCUMENT decision in `.sisyphus/notepads/pvthfhe-bench-full-wiring/learnings.md` and `.sisyphus/design/spec-real-p2p3.md` addendum.

**Cost**: 5 min edit + 10 min validation + 5 min run.

### Probe P5 — Full real bench-comparison  *(unchanged)*

After P0' / P3 / P2 produce a code state where peak RSS < 30 GB on isolated reproducer, run the full `just bench-comparison 3 1 1` (3 e2e + bench + render).

**Acceptance**: completes within 60 GB cap → done; OOMs again → escalate to alternate compressor backend or recursive-fold reduction.

## 5. Decision Tree (revised)

```
P0' isolated reproducer peak RSS:
├─ < 8 GB   → integration interaction (FHE↔Sonobe), revisit H3 with full e2e instrumentation
├─ 8-20 GB  → bounded but high; instrument tracing identifies which call dominates
│             ├─ deserialize_params dominant → H6 confirmed, mitigation = restructure ownership
│             ├─ Nova::init dominant         → H1 confirmed, mitigation = smaller SRS or P3
│             ├─ prove_step cumulative       → H2 confirmed, go P2
│             └─ no clear dominant           → P3 (newer rev)
└─ > 20 GB  → reproduces full failure → P3 (newer rev) → P2 (IVC=1) → escalate
```

## 6. Mitigations Catalog (apply per H)

| If wins | Mitigation | Effort |
|---|---|---|
| H1 | `RAYON_NUM_THREADS=2` env in `Justfile` `bench-comparison` recipe | 2-line change |
| H2 | Drop `IVC_STEPS` from 4 → 1 (acceptable if 1 step is sufficient for the digest binding the toy circuit needs) | 1-line + design note |
| H3 | Drop large FHE intermediates explicitly with `drop()` before `compressor.prove`; or split `pvthfhe-e2e` into two binaries with a serialized handoff file | 30 lines + tests |
| H4 | Bump Sonobe rev in `crates/pvthfhe-compressor/Cargo.toml` and `crates/pvthfhe-bench/Cargo.toml`; document under `.sisyphus/research/sonobe-wrap-feasibility.md` addendum | 15 min if API stable, hours if API changed |
| H5 | Same as H1; possibly also `MIMALLOC` global allocator | 2 lines |

## 7. Out-of-Scope / Escalation Paths

- **N=8192 → N=4096 reduction for the comparison**: parameter change in `parameters.toml`. Defer; comparison must be at production parameters per spec.
- **Switch to surrogate-compressor for comparison numbers**: NOT ACCEPTABLE — `bench-comparison-gate` rejects surrogate rows.
- **Switch Sonobe Nova → HyperNova/Mova**: viable if H1+H2+H3+H4 all fail. Big change. Last resort.

## 8. Evidence & Provenance

All probe runs write to `.sisyphus/evidence/bench-comparison-mem/<probe-id>/`:
- `STATUS` (started/finished/rc)
- `mem.log` (10-second sampler)
- `run.log` (stdout+stderr)
- `*.time` (`/usr/bin/time -v` output with peak RSS)

This plan + final disposition will be archived to `.sisyphus/notepads/pvthfhe-bench-full-wiring/learnings.md` with the winning hypothesis and applied mitigation.

## 9. TDD Stance

This is investigative profiling work, not a feature change. RED-test policy applies once we identify a code change:
- For H1/H5 (Justfile env var): no test needed — Justfile recipe change.
- For H2 (IVC_STEPS): RED test asserting peak RSS via a `peak_alloc` measurement gate, OR a numeric-threshold integration test under `pvthfhe-compressor/tests/`.
- For H3 (drop residue): RED test that asserts pre-prove RSS < N GB.
- For H4 (bump rev): existing `pvthfhe-compressor` tests must still pass; no new test needed for memory.

## 10. Acceptance

Plan complete when:
1. `just bench-comparison 3 1 1` runs to completion on the 62 GB host
2. `bench/results/comparison-<sha>.md` contains 12/12 populated rows (no `surrogate`, `real-fallback` only on onchain row)
3. Winning hypothesis recorded in `.sisyphus/notepads/pvthfhe-bench-full-wiring/learnings.md`
4. Mitigation committed (with RED test if code change)
