# Bench-Comparison Memory Investigation — Findings

## 2026-05-07T15:15Z — Run #1: RAYON_NUM_THREADS=1, ulimit -v 16 GiB

**Setup**:
- Binary: `target/release/pvthfhe-e2e --n 3 --t 1 --seed 1`
- Env: `RAYON_NUM_THREADS=1`, `RUST_LOG=info`, `RUST_BACKTRACE=1`
- `ulimit -v 16777216` (16 GiB virtual memory cap)
- Detached: `setsid nohup ... </dev/null >...nohup.out 2>&1 & disown`
- Evidence: `.sisyphus/evidence/bench-comparison-mem/rss-phase/`

**Result**: `rc=134` (SIGABRT) at `peak_rss_kb=12662380` (12.66 GiB).
Last allocation request: `4194304` bytes (4 MiB) failed → process panicked safely. Host unaffected.

**RSS Timeline** (from `mem.log`, 5s sampler):
| t (s) | mem_avail (GB) | pvthfhe RSS (GB) |
|---|---|---|
| 0 | 60 | 0.006 |
| 5 | 62 | 0.30 |
| 10 | 62 | 0.71 |
| 15 | 62 | 0.97 |
| 20 | 61 | 1.73 |
| 30 | 60 | 2.58 |
| 60 | 56 | 6.01 |
| 90 | 55 | 8.03 |
| 120 | 51 | 11.55 |
| 130 | 51 | 12.40 → ABORT |

Linear growth ~5.5 GB/min. Process aborted at 12.66 GB peak after ~130s.

**Last log lines** (run.log):
```
2026-05-07T15:13:24.964167Z INFO rss phase=rss_checkpoint label=after_nizk_verify rss_mb=30
2026-05-07T15:13:25.025383Z INFO rss phase=rss_checkpoint label=after_pvss rss_mb=46
memory allocation of 4194304 bytes failed
stack backtrace:
```

**Critical observations**:
1. `after_pvss=46MB` was logged at line 169 of `pvthfhe_e2e.rs`.
2. The next checkpoint `after_compressor_new` (line 175) was **never** logged.
3. The `nova: params serialized` log emitted INSIDE `NovaCompressor::new` (nova/mod.rs:99) was **also never** logged.
4. Therefore the failure is INSIDE `NovaNova::preprocess` (nova/mod.rs:81–85), called from `NovaCompressor::new`.

## Refuted Hypotheses

- **H1/H5 — Rayon scratch**: REFUTED. `RAYON_NUM_THREADS=1` did not reduce growth. Same 5.5 GB/min monotonic linear pattern.
- **H1 (re-stated) — Pedersen ck embedded blowup at MSM**: REFUTED at this call site (preprocess does not run MSM).
- **H6 — `pp_deserialize_with_mode` leak**: REFUTED. The leak is in `preprocess`, not deserialize.
- **H4 (build-time)** — Different folding-schemes features in pvthfhe-e2e vs example: REFUTED. `cargo build --message-format=json` shows BOTH builds get `features: ['default', 'parallel']` for `folding-schemes`.

## Discrepancy: Same Code, 100x Different Memory

`NovaCompressor::new(1)` is called identically from:
- `examples/nova_isolated.rs` line 29 → peak ~93 MB, completes in <1s ✅
- `pvthfhe_e2e.rs` line 172 → consumes >12.6 GB before aborting ❌

Same seed, same code, same release profile, same features. The ONLY difference is what runs before it in the same process.

## New Hypotheses

- **H8** — Heap state pollution from prior phases (FHE backend init, KeygenSimulator, NIZK proofs, PVSS) somehow induces catastrophic allocation patterns inside `NovaNova::preprocess`. Mechanism unclear (allocator fragmentation alone shouldn't cause linear monotonic growth).
- **H9** — Environment variable inheritance: pvthfhe-e2e is launched via `target/release/pvthfhe-e2e`, while the example is launched via `cargo run --release --example`. Cargo sets env vars (CARGO_*, RUSTFLAGS, etc.) that may propagate. Less likely but cheap to test.
- **H10** — Static state / thread-local pollution from arkworks: some arkworks types use thread-local FFT/MSM caches. If FHE/PVSS code touched those caches with N=8192-sized objects, Nova's preprocess might allocate based on cached sizing rather than the toy circuit's sizing.

## Discriminating Probe (next)

**Probe P1** — Construct `Compressor::new` FIRST in `pvthfhe-e2e` `run_e2e()` (or via a new `--probe-compressor-only` flag) before any FHE/keygen/NIZK/PVSS work runs. If memory stays <500 MB → H8 or H10 (state-pollution) confirmed. If still >12 GB → build-environment difference (H9 or unknown).

This will sharply discriminate state-pollution hypotheses from build-environment hypotheses.

## Plan File Status

Plan `.sisyphus/plans/bench-comparison-memory-investigation.md` does not contain itemized checkboxes that map to "Run #1". It's a hypothesis/probe document. P0' is complete. P1 (the new discriminator) and the original P3/P2 remain.


## 2026-05-07 — Probe P1 launched (compressor-first bisection)
- Code change: added --probe-compressor-only flag, constructs Compressor::new immediately
- Build: success
- Detached PID: 390939
- Evidence: .sisyphus/evidence/bench-comparison-mem/probe-first/
- Status: running, awaiting completion

## 2026-05-07T15:27Z — Probe P1 RESULT (decisive)

**Outcome**: rc=134 (SIGABRT, alloc failure), peak_rss_kb=12,649,012 (12.65 GiB), wall=2:09.59
**Start RSS**: 4 MB (immediately after `Args::parse()`, before any FHE/keygen/NIZK/PVSS)
**Growth**: ~5.5 GB/min linear, IDENTICAL pattern to Run #1
**Last log**: `probe_before_compressor_new rss_mb=4` — `probe_after_compressor_new` never reached
**Crash site**: inside `NovaCompressor::new` → `NovaNova::preprocess` (unchanged from Run #1)

### Hypothesis Verdicts

| H  | Hypothesis | Verdict | Evidence |
|----|------------|---------|----------|
| H8 | Prior-phase heap pollution (FHE/PVSS/NIZK/keygen) | **REFUTED** | RSS=4 MB at `Compressor::new` entry; no prior phases ran |
| H9 | Env var inheritance (cargo vs direct exec) | **REFUTED** | P0' (`cargo run --example`) is also "direct exec" of release binary; env not the discriminator |
| H10 | arkworks thread-local FFT/MSM cache pollution | **REFUTED** | No FHE/PVSS code ran; thread-locals untouched |

### Confirmed Source: BUILD CONFIGURATION

Same `NovaCompressor::new(1)` call:
- Built into `pvthfhe-compressor/examples/nova_isolated.rs` → 93 MB ✅
- Built into `pvthfhe-cli/src/bin/pvthfhe_e2e.rs` → 12.65 GB ❌

State-pollution at runtime is eliminated. The delta MUST be one of:
- **H11** — Cargo feature unification: `pvthfhe-cli` pulls deps that activate features on `nova`/`ark-*`/`fhe-rs` causing larger preprocess buffers
- **H12** — Different transitive dep versions resolved when building from `pvthfhe-cli` vs from `pvthfhe-compressor` example
- **H13** — Codegen/profile delta (LTO, codegen-units, opt-level differences between bin and example)
- **H14** — Type monomorphization / generic instantiation: `pvthfhe-cli` instantiates Nova generics with curve/params different from the example, even though both call `NovaCompressor::new(seed)` with the same surface API

### Next Discriminator (Probe P6)

Compare the two builds' resolved feature sets and dep graphs:
1. `cargo tree -p pvthfhe-cli --target-dir /tmp/t1 -e features --no-default-features --features ...` (capture features active on `nova`, `ark-*`, `fhe`)
2. Same for `pvthfhe-compressor` example
3. Diff
4. If features identical: check `cargo build -p pvthfhe-cli --bin pvthfhe-e2e --release -v` vs example for codegen flags
5. Hypothesis H14 test: copy example source byte-for-byte into `pvthfhe-cli/src/bin/nova_min.rs` and run — if it OOMs, monomorphization context is the cause; if it's fine, something else in `pvthfhe-cli`'s dep set inflates Nova.

## 2026-05-07T15:35Z — Probe P6 result: cargo tree feature comparison

Both `pvthfhe-cli` and `pvthfhe-compressor` resolve folding-schemes/ark-* through the same workspace `[patch]` overrides. `cargo tree -p pvthfhe-cli -e features --depth 6` confirms:
- pvthfhe-cli pulls `pvthfhe-compressor` (default features) via `pvthfhe-bench` → `nova-compressor` feature ✓
- pvthfhe-cli ALSO pulls `fhe v0.1.0-beta.7` and `fhe-math v0.1.0-beta.7` from gnosisguild
- pvthfhe-compressor (and its example) does NOT pull `fhe`/`fhe-math`

Cargo feature unification: when `pvthfhe-cli` is built, `fhe-math` and Nova BOTH depend on workspace-patched `ark-poly`, `ark-ff`, `ark-ec`. Whatever features either side requests get unified into a single resolved set for the `ark-*` crates compiled into the binary. The example has no such union with `fhe-math`.

This is consistent with H11/H14 but does NOT yet identify the smoking gun.

## Probe P7 design (next, decisive for H14 vs H11)

Create `crates/pvthfhe-cli/src/bin/nova_min.rs` byte-for-byte equivalent to `crates/pvthfhe-compressor/examples/nova_isolated.rs`, plus a feature-gated entry. Build with `--bin nova_min` from the same `pvthfhe-cli` package (same dep resolution as `pvthfhe-e2e`).

Outcomes:
- If `nova_min` OOMs (>1 GB): **H11 confirmed** — feature unification (likely from fhe-math) inflates Nova preprocess buffers. Mitigation: split Nova into a separate workspace package or move the bench-comparison driver into pvthfhe-compressor (no fhe-rs deps).
- If `nova_min` stays <500 MB: **H14 confirmed** — generic monomorphization context within `pvthfhe-cli` (likely Nova Nova types reaching deeper instantiation due to other `pvthfhe-cli` types) inflates buffers. Mitigation: move Compressor::new + prove into a shim binary that has minimal dep graph and pipe artifacts via files.

Implementation scope:
- Add 1 file: `crates/pvthfhe-cli/src/bin/nova_min.rs` (~30 LOC, copy of example main)
- Add bin entry in `crates/pvthfhe-cli/Cargo.toml`
- Build with `cargo build --release -p pvthfhe-cli --bin nova_min`
- Run via `setsid nohup ... ulimit -v 16777216` capture peak RSS
- Evidence: `.sisyphus/evidence/bench-comparison-mem/probe-nova-min/`

This is a DELEGATABLE task (modifies non-`.sisyphus/` source).

## 2026-05-07T15:46:11Z — Probe P7 launched
- Build: success (`cargo build --release -p pvthfhe-cli --bin nova-min`)
- Detached PID: 395521
- Evidence: `.sisyphus/evidence/bench-comparison-mem/probe-nova-min/`
- Status: launched, detached via `setsid nohup ... & disown`

## 2026-05-07T15:48Z — Probe P7 RESULT (DECISIVE)

**Outcome**: rc=134 SIGABRT, peak_rss_kb=12,648,376 (12.65 GiB), wall=2:10.67
- `nova-min` does ONLY `NovaCompressor::new(1)` then exits (32 LOC, byte-equivalent to working example)
- Built inside `pvthfhe-cli` dep graph (same as `pvthfhe-e2e`)
- Same code path crashes here that succeeded in `examples/nova_isolated.rs` (93 MB)

**Backtrace pinpoint**: `Nova::preprocess` → `AugmentedFCircuit::compute_next_state` → `PoseidonSpongeVar::absorb` (constraint generation phase, not commitment setup)

### Hypothesis Verdict (final)

| H  | Hypothesis | Verdict |
|----|------------|---------|
| H11 | Cargo feature unification inflates ark-* features when fhe-math is co-resolved | **CONFIRMED** |
| H14 | Generic monomorphization context | partial — same generics used in both, so unlikely sole cause |
| H12/H13 | Different versions / codegen profile | refuted — same workspace, same profile |

### Mechanism

- `pvthfhe-compressor` deps: `ark-bn254`, `ark-ff`, `ark-grumpkin`, `ark-r1cs-std`, `ark-relations`, `ark-serialize`, `folding-schemes` (no parallel features by default)
- `pvthfhe-cli` deps (transitively via `pvthfhe-fhe` → `fhe-math` v0.1.0-beta.7): pulls `ark-poly`, `ark-poly-commit` with features `parallel`, `rayon`, `std`, `asm` enabled
- Cargo unifies: in the cli's binary, ark-* crates are compiled with parallel+rayon+asm
- `folding-schemes`' `Nova::preprocess` allocates dramatically larger working sets when ark-* parallel features are active (likely thread-local buffers per rayon worker or AVX-aligned allocation pools)

### Mitigation Options

**Option A (clean)**: Move bench-comparison driver out of `pvthfhe-cli` into a new `pvthfhe-bench-driver` binary in `pvthfhe-compressor` (or new crate). Driver shells out to `pvthfhe-e2e` and `fhe-baseline` via subprocess, never co-links with `fhe-math`.

**Option B (surgical)**: Make `pvthfhe-cli` invoke Nova via subprocess too. Split `pvthfhe-e2e` into:
- `pvthfhe-e2e-phases` (FHE/PVSS/NIZK/keygen, links fhe-math, NO nova)
- `pvthfhe-fold` (Nova only, links pvthfhe-compressor, NO fhe-math)
- `pvthfhe-e2e` orchestrates via `Command::spawn`, passing artifacts via temp files

**Option C (investigatory, may not work)**: Set `RAYON_NUM_THREADS=1` everywhere AND find/disable the offending ark feature. P1 Run #1 already had RAYON_NUM_THREADS=1 set in the runner — but the unified build still has the asm/parallel code paths compiled in even if rayon doesn't fan out at runtime. So this likely won't help.

**Recommended**: Option B — minimal scope, keeps existing test surfaces, separates concerns matching the actual failure mode. Subprocess boundary breaks Cargo feature unification.

### Acceptance criteria for fix

- `pvthfhe-fold` binary peak RSS < 500 MB on n=3,t=1,seed=1
- `just bench-comparison 3 1 1` completes producing 12 populated rows
- No new `#[allow(...)]` attributes
- TDD: add a memory-budget test that fails BEFORE fix and passes AFTER

## 2026-05-07T16:04:18Z — Probe P8 launched
- Cargo.toml change: added `probe-no-fhe` feature; gated FHE-linked deps behind `with-fhe`; `pvthfhe-cli`/`pvthfhe-e2e` require `with-fhe`
- Build: success (`cargo build --release -p pvthfhe-cli --bin nova-min --no-default-features --features probe-no-fhe,nova-compressor`)
- Cargo tree check: `cargo tree -p pvthfhe-cli --no-default-features --features probe-no-fhe,nova-compressor 2>&1 | grep -E fhe-math|^fhe ` returned no matches
- Detached PID: 400371
- Evidence: `.sisyphus/evidence/bench-comparison-mem/probe-no-fhe/`
- Status: launched, detached via `setsid nohup ... & disown`

## 2026-05-07T16:07Z — Probe P8 RESULT (H11 REFUTED)

**Outcome**: rc=134 SIGABRT, peak_rss_kb=12,647,792 (12.65 GiB), wall=2:10.77
- Built with ZERO `fhe`/`fhe-math` in dep tree (verified via `cargo tree`)
- Same OOM signature as Run #1 / P1 / P7 (12.65 GB, ~5.5 GB/min linear)

### Hypothesis Verdict (revised)

| H  | Hypothesis | Verdict | Evidence |
|----|-----------|---------|----------|
| H11 | fhe-math feature unification inflates ark-* | **REFUTED** | nova-min OOMs identically with NO fhe-math co-resolved |

### P8 Follow-up: dep tree diff
`cargo tree -p pvthfhe-cli --no-default-features --features probe-no-fhe,nova-compressor -e features --no-dedupe | grep -E '^(ark-|folding-schemes|rayon|crossbeam)'` vs same for `pvthfhe-compressor`:
**94 lines each, ZERO diff.** Ark/folding feature graphs are byte-identical between the OOM build (cli nova-min) and the 93 MB build (compressor example).

### Discriminator narrowed
Same crate-level deps, same features, same versions. Difference must be:
- **H14** — Target kind (`[[example]]` in compressor pkg vs `[[bin]]` in cli pkg) triggers different codegen-units / LTO / inlining
- **H15** — Package membership in `pvthfhe-cli` (extra sibling deps clap/anyhow/hex/pvthfhe-compressor) alters monomorphization for shared generics
- **H16** — `[profile.release]` overrides differ between packages (need to inspect)
- **H17** — Cargo resolver picks different versions of non-(ark/folding) transitives (crossbeam, rayon-core, getrandom, zerocopy) — diff was filtered, need unfiltered

## Probe P9 design (next)

**Goal**: Isolate target-kind vs package-membership.

**Action**: Add `[[bin]] name = "nova-min-compressor"` to `pvthfhe-compressor/Cargo.toml`, drop byte-identical `nova_min.rs` into `crates/pvthfhe-compressor/src/bin/nova_min.rs`, build with `cargo build --release -p pvthfhe-compressor --bin nova-min-compressor`, run under same `ulimit -v 16777216` regime.

**Outcomes**:
- If peak_rss < 500 MB → target-kind irrelevant; **package-membership** is the cause (H15). Mitigation: split Nova driver out of pvthfhe-cli into its own crate (mirrors Option B from prior recommendation).
- If peak_rss > 1 GB → target-kind irrelevant too; cause is something else (H17 most likely). Run unfiltered `cargo tree --no-dedupe` diff next.

**Implementation scope**:
- Add 1 file: `crates/pvthfhe-compressor/src/bin/nova_min.rs` (32 LOC, byte-identical to `crates/pvthfhe-cli/src/bin/nova_min.rs`)
- Add bin entry in `crates/pvthfhe-compressor/Cargo.toml`
- Build + run + capture peak RSS
- Evidence: `.sisyphus/evidence/bench-comparison-mem/probe-compressor-bin/`

This is DELEGATABLE (modifies non-`.sisyphus/` source).

## 2026-05-07T16:18Z — Probe P9 RESULT (target-kind/package-membership check)

**Setup**:
- Source clone: `crates/pvthfhe-compressor/src/bin/nova_min.rs` (byte-identical copy of `pvthfhe-cli` version)
- Bin target: `nova-min-compressor` in `pvthfhe-compressor`
- Build: `cargo build --release -p pvthfhe-compressor --bin nova-min-compressor`
- Run: detached via `setsid nohup ... & disown` under `ulimit -v 16777216`
- Evidence: `.sisyphus/evidence/bench-comparison-mem/probe-compressor-bin/`

**Result**: `rc=134`, `peak_rss_kb=12647692` (12.65 GiB)

**Verdict**:
- **H14 refuted**: changing target kind to `[[bin]]` in `pvthfhe-compressor` does not remove the OOM

## 2026-05-07T16:25Z — Probe P10 RESULT (trait-eagerness)

**Setup**:
- Source: `crates/pvthfhe-compressor/src/bin/nova_min.rs`
- Change: imported `ProofCompressor`, renamed `_compressor` → `compressor`, added `compressor.verifier_key()` and `compressor.vk_bytes()` after `new(1)` plus `rss_kb stage=after_vk`
- Build: `cargo build --release -p pvthfhe-compressor --bin nova-min-compressor`
- Run: detached via `setsid nohup ... & disown` under `ulimit -v 16777216`
- Evidence: `.sisyphus/evidence/bench-comparison-mem/probe-trait-ref/`

**Result**: `rc=134`, `peak_rss_kb=12647664` (12.65 GiB)

**Verdict**:
- **H18 REFUTED**: adding a visible trait reference did not change the OOM profile
- Peak RSS is still far above 5_000_000 KB, so this is not a trait-eagerness / lazy-monomorphization discriminator

**Recommended next probe**:
- Inspect codegen / dependency-resolution differences outside the source text delta, or pursue the accounting anomaly in P11 since `/proc/self/status` RSS remains tiny while `/usr/bin/time -v` reports 12.65 GiB
- **H15 refuted**: `pvthfhe-cli` package membership is not the sole cause; the same byte-identical code OOMs outside that package too
- Next discriminator should be the remaining dependency/codegen hypotheses (likely H17 / unresolved cargo resolution differences)

**TDD note**: this was an investigation probe, not an implementation change, so the RED-test-before-change rule did not apply.

## 2026-05-07T16:25Z — Smoking gun observation (post-P9 review)

After 13+ refuted hypotheses, careful side-by-side of the only two files that exercise this code path inside `pvthfhe-compressor`:

| Aspect | `examples/nova_isolated.rs` (✅ 244 MB) | `src/bin/nova_min.rs` (❌ 12.65 GB) |
|---|---|---|
| Imports `ProofCompressor` trait | YES (line 7) | NO |
| Calls `compressor.prove(...)` | YES | NO |
| Calls `compressor.verify(...)` | YES | NO |
| Calls `compressor.verifier_key()` / `compressed_proof_bytes()` | YES | NO |
| Calls `NovaCompressor::new(1)` | YES | YES |

**The version that does MORE work (full prove+verify) uses 50× LESS memory than the version that only constructs.** This contradicts every reasonable allocation model.

### Secondary anomaly: ghost RSS
P9's `mem.log` shows the child's `/proc/self/status` `VmRSS` stays at **1624 KB** for the full 2:11 wall, while `/usr/bin/time -v` reports peak = 12,647,692 KB and system `MemAvailable` drops 5.5 GB/min in lockstep. Memory is real but not attributed to the launched binary's own status file. Possibilities:
- Forked rayon/arkworks worker thread/process accumulating memory
- mmap'd anonymous regions counted by `time -v` (rusage) but not by `VmRSS`
- Launcher polls statm of the launcher shell, not the actual binary, due to `bash -lc 'exec ./target/release/nova-min-compressor'` indirection

### Hypothesis H18 (new)
**Symbol-tree pruning / lazy monomorphization**: Rust's release codegen may not instantiate certain generics from `folding-schemes` unless trait methods are referenced in the binary's call graph. The 12.65 GB OOM happens INSIDE `Nova::preprocess` (per P7 backtrace: `compute_next_state → PoseidonSpongeVar::absorb`). When `prove`/`verify` ARE referenced, the compiler may instantiate a different (smaller) specialization or precompute commitment caches that short-circuit the preprocess allocation. When ONLY `new()` is referenced, a worst-case generic path is monomorphized.

This is exotic but explains the inverted memory law. **Probe P10** discriminates definitively.

## Probe P10 design (next)

**Action**: Modify `crates/pvthfhe-compressor/src/bin/nova_min.rs` to add `use pvthfhe_compressor::ProofCompressor;` and one trivial reference: `let _vk = compressor.verifier_key();` after `new()`. Build & run under same regime.

**Outcomes**:
- If peak < 500 MB → **H18 confirmed**: trait-method reference flips codegen path. Mitigation: ensure call sites in `pvthfhe-cli` reference the trait methods (which they already do — `pvthfhe_e2e.rs` calls `compressor.prove`). If H18 is true the e2e SHOULD be 244 MB, but it isn't, so H18 must combine with another factor.
- If peak still > 1 GB → H18 refuted; the difference must be in the `ProofCompressor` trait *coercion site* (e.g., `&dyn ProofCompressor` vs concrete) or in another file in the package (e.g., `lib.rs` exports trigger different codegen).

**Probe P11 (in parallel)**: Add `cat /proc/$PID/smaps_rollup` and per-thread RSS enumeration to launcher, to localize the 12.6 GB ghost.

## [2026-05-07T16:35Z] ROOT CAUSE CONFIRMED — H_TRACING

### Decisive evidence
- **P-rerun-example** (RUST_LOG=info, cached ELF mtime 14:19): rc=134, peak=12,648,460 KB
- **P13 / probe-rust-log-off** (RUST_LOG unset, SAME cached ELF, same `ulimit -v 16777216`, same `RAYON_NUM_THREADS=1`): rc=0, peak=244,164 KB, wall ≈3s, all 4 IVC steps complete, verify=true
- Same binary, only `RUST_LOG` differs ⇒ **52× memory blowup is caused by tracing-subscriber's debug-formatting of `&&mut [FpVar]` slices inside arkworks-rs Poseidon constraint code**

### Mechanism (from P-rerun-example backtrace frames 24–33)
1. `PoseidonSpongeVar::apply_mds` calls `tracing::span!(...)` with field `&mut [FpVar]`
2. `Span::new` → fmt::format::DefaultVisitor → `record_debug` on the slice
3. `<&&mut [FpVar]>::fmt` → `DebugSet::entry` per element
4. `<FpVar as Debug>::fmt` recurses into `AllocatedFp` → `ConstraintSystemRef` → `RefCell<ConstraintSystem<Fp>>::fmt`
5. **Per-span quadratic blowup**: every Poseidon round serializes the entire (growing) R1CS constraint system. With multiple absorb steps × multiple rounds × 4 IVC steps × ~thousands of constraints, this scales catastrophically.
6. With `EnvFilter` set to `off` (RUST_LOG unset → `try_from_default_env` errors → fallback `EnvFilter::new("off")` ... but here the example had `pvthfhe_compressor=info`, which does NOT match arkworks/folding-schemes spans → spans become disabled at `Span::new` early-out path and `record_debug` is never called)

### Hypothesis status
- H1, H2, H4, H5, H6, H8, H9, H10, H11, H12, H13, H14, H15, H18: REFUTED
- **H_TRACING (NEW): CONFIRMED** — `EnvFilter::new("info")` enables ark-* / folding-schemes spans which then debug-format FpVar slices recursively walking ConstraintSystemRef

### Affected default filters
- `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs:69` → `EnvFilter::new("info")` ❌ (matches arkworks)
- `crates/pvthfhe-cli/src/main.rs:108` → `EnvFilter::new("info")` ❌
- `crates/pvthfhe-compressor/examples/nova_isolated.rs:20` → `EnvFilter::new("pvthfhe_compressor=info")` ✅ (target-scoped)
- `crates/pvthfhe-compressor/src/bin/nova_min.rs:20` → `EnvFilter::new("pvthfhe_compressor=info")` ✅
- `crates/pvthfhe-cli/src/bin/nova_min.rs:20` → `EnvFilter::new("pvthfhe_compressor=info")` ✅
- `crates/pvthfhe-cli/tests/e2e_*.rs` → `.env("RUST_LOG", "info")` ❌ (will OOM if those tests ever run with nova-compressor)

### Fix
Change unscoped `info` defaults to target-scoped filter excluding arkworks/folding-schemes:
```
EnvFilter::new("pvthfhe_cli=info,pvthfhe_compressor=info,pvthfhe_fhe=info,pvthfhe_lattice_pvss=info,pvthfhe_aggregator=info,pvthfhe_pvss=info,pvthfhe_bench=info,nova=info")
```
And in tests: `.env("RUST_LOG", "pvthfhe_cli=info,pvthfhe_compressor=info,...")`.

### Memory budget gate
RED test should assert peak<500 MB for `pvthfhe_e2e --probe-compressor-only` to permanently catch any regression that re-enables broad tracing filters.

## 2026-05-07T~16:50Z — H_TRACING fix landed (RED→GREEN)

### TDD evidence
- **RED** (`.sisyphus/evidence/bench-comparison-mem/red-test-before-fix.log`):
  - `cargo test -p pvthfhe-cli --test e2e_memory_budget --features nova-compressor`
  - Subprocess: `pvthfhe-e2e --probe-compressor-only --n 3 --t 1 --seed 1` with `RUST_LOG=info`, `ulimit -v 16777216`
  - Result: SIGABRT (signal 6), peak RSS = **12,652,960 KB** (12.65 GiB), wall ≈ 9:39
  - Test FAILED on `subprocess did not exit successfully` assertion
- **GREEN** (`.sisyphus/evidence/bench-comparison-mem/red-test-after-fix.log`):
  - Same command, same env, same ulimit
  - Result: rc=0, peak RSS = **185,736 KB** (~181 MB), wall ≈ 11.79 s
  - Test PASSED — both exit-success and `<500_000 KB` budget assertions green

### Files modified
- **NEW** `crates/pvthfhe-cli/tests/e2e_memory_budget.rs` — RED-first regression test (Linux + nova-compressor gated)
- `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` — replaced unscoped `EnvFilter::new("info")` fallback with target-scoped filter, added `build_env_filter()` that sanitizes a bare `RUST_LOG=info|debug|trace|warn|error` global level back to the safe scoped filter (so user-set RUST_LOG=info no longer reintroduces the OOM)
- `crates/pvthfhe-cli/src/main.rs` — same `build_env_filter()` change

### Notes
- 68× memory reduction (12,652,960 KB → 185,736 KB) at the same workload, confirming H_TRACING is the sole cause.
- 49× wall-clock reduction (9:39 → 11.79 s) because the constraint-system Debug walk was the dominant CPU cost too.
- `RUST_LOG=info` in tests is sanitized by the binary (treated as the safe scoped default). Users who want full granularity can still set `RUST_LOG=pvthfhe_cli=debug,nova=debug` etc.
- `cargo test -p pvthfhe-cli --lib --bins` and `cargo test -p pvthfhe-cli --test e2e_uses_nova` both still pass.
- No `#[allow(...)]` added; no stub files touched; no plan files modified.

## [2026-05-07T17:05Z] FIX VERIFIED END-TO-END

### Test outcomes
- `cargo test -p pvthfhe-cli --test e2e_memory_budget --features nova-compressor` → PASS in 0.88s, peak 175,840 KB (172 MB), well under 500 MB budget
- `just bench-comparison 3 1 1` → rc=0, peak 841,780 KB (822 MB) for entire pipeline, wall ≈3 min
- `just bench-comparison-gate` → PASS (no surrogate rows; sole real-fallback is OnChainUltraHonkVerify which is permitted per nova-wrap-feasibility verdict NoGo)
- Final artifact: `bench/results/comparison-5d7853a.md` with 12/12 rows (11 real, 1 real-fallback)

### Memory profile (nova path) under fix, IVC_STEPS=4
- params serialized: rss_kb=135,144
- pp_deserialize done: 139,636
- vp_deserialize done: 190,696
- Nova::init done: 244,588
- prove_step 0..3: 253,636 → 260,804
- ivc proof serialized: 260,804 (7,129,240 bytes)

This baseline is now the canonical "healthy" curve for the nova IVC path.

### Defense-in-depth
The `build_env_filter()` helper sanitizes bare global `RUST_LOG` levels (`trace`/`debug`/`info`/`warn`/`error`) by substituting the safe scoped filter. This is critical because:
1. Users routinely set `RUST_LOG=info` at shell level for general Rust debugging
2. The `try_from_default_env` path would otherwise honor that broad filter and re-trigger the OOM
3. Fully-scoped filters (e.g., `RUST_LOG=pvthfhe_cli=debug`) are still respected — only the unsafe bare globals are overridden

### What other binaries are at risk?
Searched the workspace for `EnvFilter::new("info")` patterns. Already-safe binaries (use scoped filter):
- `crates/pvthfhe-compressor/examples/nova_isolated.rs`
- `crates/pvthfhe-compressor/src/bin/nova_min.rs`
- `crates/pvthfhe-cli/src/bin/nova_min.rs`
Now-safe (this fix):
- `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs`
- `crates/pvthfhe-cli/src/main.rs`

### Future hardening candidates (not blocking)
- Add a workspace lint or test that scans for `EnvFilter::new("info")` / `EnvFilter::new("debug")` literals and fails build, forcing target-scoped filters
- Audit any future binaries that touch arkworks/folding-schemes for the same pattern
- Consider upstreaming a tracing fix to ark-r1cs-std to avoid debug-formatting `&[FpVar]` slices (but that's out of scope here)
