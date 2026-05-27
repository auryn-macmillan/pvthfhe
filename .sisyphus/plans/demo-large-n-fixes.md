# Plan: demo-large-n-fixes

> **Status:** READ-ONLY for sub-agents. Only the orchestrator may mark checkboxes.
> **Owner:** Atlas (orchestrator)
> **Created:** 2026-05-07
> **Predecessor:** `demo-full-pipeline-unification.md` (12/12 done)

---

## 1. Problem Statement

After unifying `just demo-e2e` with the bench pipeline, the demo crashes for any `n` larger than the locked default `n=8`:

| Command                  | Failure point                | Error                                                 |
|--------------------------|------------------------------|-------------------------------------------------------|
| `just demo-e2e 256 129`  | `step 4/9: pvss_share_encrypt` | `Error: pvss deal: PVSS backend error` (redacted)   |
| `just demo-e2e 128 65`   | `step 5/9: cyclo_fold`        | `Error: cyclo_fold` / `norm bound exceeded: got 103, max 102` |

Three distinct issues are responsible. Two are real algebraic constraints that simply need to be documented and surfaced to the user; one is a test-fixture bug in the unified pipeline.

## 2. Root Causes (verified by source inspection)

### Issue A — PVSS GF(256) cap (`n ≤ 255`)

`crates/pvthfhe-pvss/src/encrypt.rs:251-257` — `validate_context()` rejects `n > u8::MAX`:

```rust
if ctx.n == 0 || ctx.t == 0 || ctx.t > ctx.n || ctx.n > usize::from(u8::MAX) {
    return Err(PvssError::BackendError(format!(
        "invalid PVSS context: n={}, t={}", ctx.n, ctx.t
    )));
}
```

This is a **real algebraic constraint** of the current Shamir scheme: x-coordinates are `u8` (encrypt.rs:228, 272) and Lagrange arithmetic is in GF(256), supporting at most 255 distinct non-zero coordinates. **Not** going to be lifted in this plan.

### Issue B — `PvssError::BackendError` Display redacts the message

`crates/pvthfhe-pvss/src/lib.rs:104` — the `Display` impl for `BackendError(_)` discards the inner string:

```rust
Self::BackendError(_) => f.write_str("PVSS backend error"),
```

This is a UX bug: real, useful diagnostic strings (the validate_context message, FHE backend errors via `map_fhe_error`) are silently swallowed. The user sees only `"PVSS backend error"` with no clue why.

### Issue C — Stub witness bytes encode participant id (test-fixture bug)

`crates/pvthfhe-cli/src/full_pipeline.rs:309`:

```rust
ccs_witness_bytes: vec![(participant_id as u8).wrapping_add(1); 32],
```

The "witness" data fed into the Cyclo fold step is a synthetic placeholder filled with the byte value `participant_id + 1`. The Cyclo fold step computes per-step witness norm as the **max byte value** (`fold.rs:15-21`), and the per-step budget is `norm_bound_b / sequential_t = 1024 / 10 = 102` (`fold.rs:11-13`). Therefore:

- **Participant id 102 → byte 103 > budget 102 → fold step rejects**
- Demo works for any `n` whose largest participant id is `≤ 101`
- At `n=128`, the loop runs through ids 1..=128 in batches of `sequential_t=10`; the failure fires inside the chunk that contains pid=102.

The exact same buggy fixture appears in:
- `crates/pvthfhe-bench/src/bin/bench_scaling.rs:131`
- `crates/pvthfhe-bench/src/bin/gen_goldens.rs:43`

The canonical "honest" pattern used by Cyclo's own unit/adversarial tests is the participant-id-independent `vec![1u8; 32]` (e.g. `crates/pvthfhe-cyclo/tests/adversarial_norm.rs:21`).

This is **not** a cryptographic constraint — it's a stub-fixture artifact introduced when the demo wired in the real Cyclo backend with synthetic test data. Replacing the byte pattern in place is fully compatible with the AGENTS.md "Stub protocol: replace stubs in place; never delete-and-recreate" rule.

## 3. Goal

`just demo-e2e <n> <t> <seed>` succeeds for the **full supported range `1 ≤ t ≤ n ≤ 255`**, and fails fast with a clear, specific error message for `n > 255`.

## 4. Non-Goals

- Lifting the `n ≤ 255` cap (would require redesigning the Shamir layer over a larger field — out of scope; would be a separate plan).
- Making the Cyclo per-step witness "norm" semantically meaningful (currently the `max byte value` heuristic is itself a synthetic check; investigating real witness encoding is a Phase 2 cryptography task, not a demo wiring fix).
- Touching `bench_scaling.rs` or `gen_goldens.rs` cryptographic outputs — those are separate bench artifacts. We will, however, fix their identical stub-witness expression so they don't trip the same way (one-line substitution each).
- Re-running `just bench-comparison` end-to-end (already covered by predecessor plan).

## 5. Constraints (Verbatim from AGENTS.md)

- TDD strict: RED test committed and CI-visible before every implementation change.
- ZERO new `#[allow(...)]` attributes.
- `cargo ... -p <crate>` from repo root. Never `--workspace` for tests.
- Stub protocol: replace stubs in place; never delete-and-recreate.
- Plan files are read-only for sub-agents; only the orchestrator marks checkboxes.
- Working-directory protocol respected (Foundry / Noir / Cargo).
- Long-running jobs disowned (`setsid nohup ... </dev/null & disown`); not expected here since changes are small but applies to acceptance smoke runs.
- Stage 0 tripwires SURVIVE.
- Forbidden: `nargo prove`, `nargo verify`.

## 6. Design Decisions

**D1 — Surface the inner string of `PvssError::BackendError` in `Display`.**
Rationale: silent redaction of a `String` payload that is already `Clone + Eq` and not a secret obstructs debugging. The variant carries a deliberate plaintext message ("invalid PVSS context: n=X, t=Y", or `FheError::to_string()`).
Implementation: change `lib.rs:104` to `Self::BackendError(s) => write!(f, "PVSS backend error: {s}")`.
Reject-alternative: introducing a new typed variant (e.g. `ContextTooLarge { n, max }`) — more invasive, requires touching every call site, no clear win over a transparent `Display`.

**D2 — Tighten `validate_context` error message and add an early hard-cap CLI guard.**
Rationale: the user should never reach `validate_context` for `n > 255`; the CLI should reject up front with a friendly message naming the limit.
Implementation:
- `validate_context` keeps the current behaviour (defence in depth) but the message becomes more explicit: `"invalid PVSS context: n={n} exceeds maximum supported parties {max} (Shamir over GF(256))"` when the cap is the trigger; existing message retained for `n=0 / t=0 / t>n`. Use a small helper to choose the message — no new variant needed.
- `pvthfhe-cli` `Demo` subcommand validates `1 ≤ t ≤ n ≤ 255` in `run_demo` **before** invoking `run_full_pipeline`. Use `anyhow::bail!`.

**D3 — Fix the stub witness bytes in `full_pipeline.rs::build_fold_instances` in place.**
Rationale: the byte pattern is a placeholder for real CCS witness data; encoding `participant_id + 1` in every byte was an arbitrary choice that happens to alias with the Cyclo norm heuristic. Replacing with `vec![1u8; 32]` matches the canonical honest-instance pattern used by `crates/pvthfhe-cyclo/tests/adversarial_norm.rs:21` and removes any pid dependency.
Reject-alternative: clamping pid via `% 102` — preserves the (meaningless) pid-in-witness encoding but obscures the fact that this data is synthetic.
**Stub protocol compliance:** edit-in-place of one expression in one function. No deletion, no rename, no file removal.

**D4 — Apply the same fix to the two bench-side fixtures with the identical bug.**
- `crates/pvthfhe-bench/src/bin/bench_scaling.rs:131` → `vec![1u8; 32]`
- `crates/pvthfhe-bench/src/bin/gen_goldens.rs:43` → `vec![1u8; 32]`
Rationale: keep all stub fixtures coherent; otherwise `bench-scaling` will start failing at the same n threshold once anyone runs it past pid=101.

**D5 — Documentation propagation.**
- `Justfile` `demo-e2e`: comment block adds "Supported range: 1 ≤ t ≤ n ≤ 255 (Shamir over GF(256)).".
- `README.md` Quickstart bullet for `just demo-e2e`: append "(supported range: n ≤ 255)".
- `pvthfhe-cli` `Demo` clap docstring on `--n`: append "(maximum 255)".

**D6 — No changes to Cyclo `fold.rs` or `PVTHFHE_CYCLO_PARAMS`.**
The norm budget logic is locked by `Backend Lock (F1, 2026-05-04)` and the spec addendum. We treat it as an immovable constraint that the stub witness must respect.

## 7. Files Affected (exhaustive)

| File                                                          | Change                                                                                  |
|---------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| `crates/pvthfhe-pvss/src/lib.rs`                              | `Display for PvssError::BackendError` reveals inner string.                             |
| `crates/pvthfhe-pvss/src/encrypt.rs`                          | `validate_context` produces specific message when `n > 255`.                            |
| `crates/pvthfhe-cli/src/main.rs`                              | `run_demo` validates `n ≤ 255` (and `t ≤ n`, already present) before pipeline.          |
| `crates/pvthfhe-cli/src/full_pipeline.rs`                     | Line 309: `vec![1u8; 32]`.                                                              |
| `crates/pvthfhe-bench/src/bin/bench_scaling.rs`               | Line 131: `vec![1u8; 32]`.                                                              |
| `crates/pvthfhe-bench/src/bin/gen_goldens.rs`                 | Line 43: `vec![1u8; 32]`.                                                               |
| `Justfile`                                                    | `demo-e2e` recipe header comment notes `n ≤ 255`.                                       |
| `README.md`                                                   | Quickstart bullet `just demo-e2e` notes `n ≤ 255`.                                      |
| `crates/pvthfhe-cli/tests/demo_large_n.rs` *(new RED test)*   | Asserts `run_full_pipeline` succeeds at `n=128, t=65`.                                  |
| `crates/pvthfhe-cli/tests/demo_n_cap.rs` *(new RED test)*     | Asserts CLI exits with informative error mentioning `255` for `n=256`.                  |
| `crates/pvthfhe-pvss/tests/error_display.rs` *(new RED test)* | Asserts `Display` of `BackendError("foo")` contains `"foo"`.                            |
| `crates/pvthfhe-pvss/tests/context_too_large.rs` *(new RED)*  | Asserts `deal()` at `n=256` returns an error whose `Display` contains `255`.            |

## 8. Test Plan (RED-first; one test per checkbox before its impl)

### RED-1: PvssError Display surfaces inner string
File: `crates/pvthfhe-pvss/tests/error_display.rs`
```rust
use pvthfhe_pvss::PvssError;
#[test]
fn backend_error_display_includes_inner_string() {
    let e = PvssError::BackendError("invalid PVSS context: n=256, t=129".into());
    let s = format!("{e}");
    assert!(s.contains("invalid PVSS context"), "got: {s}");
    assert!(s.contains("256"), "got: {s}");
}
```
Initially RED: current Display prints only `"PVSS backend error"`.

### RED-2: PVSS context too large names the cap
File: `crates/pvthfhe-pvss/tests/context_too_large.rs`
```rust
use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};
#[test]
fn deal_at_n_256_returns_error_naming_max() {
    let adapter = LatticePvssBfvAdapter::new();
    let ctx = PvssContext { n: 256, t: 129, session_id: vec![0u8; 16] };
    let pks: Vec<Vec<u8>> = (0..256).map(|_| vec![0u8; 32]).collect();
    let err = adapter.deal(b"secret", &pks, &ctx).expect_err("must fail at n=256");
    let msg = format!("{err}");
    assert!(msg.contains("255") || msg.contains("256"), "got: {msg}");
    assert!(msg.contains("n=256") || msg.contains("Shamir") || msg.contains("GF(256)"),
            "message must explain the cap; got: {msg}");
}
```
Initially RED: current message is generic; redacted Display also blocks the assertion.

### RED-3: CLI `--n 256` exits with informative error before any phase
File: `crates/pvthfhe-cli/tests/demo_n_cap.rs`
Spawns `cargo run -- demo --n 256 --threshold 129 --seed 1` (release+nova-compressor) via `assert_cmd`, asserts:
- non-zero exit
- stderr contains `"255"` and either `"Shamir"`, `"GF(256)"`, or `"maximum"`
- stderr does **not** contain `"step 4/9"` (failure must be early, before any phase ran)
Initially RED: current behaviour gets to step 4/9 and prints the redacted message.

### RED-4: Demo runs end-to-end at `n=128, t=65`
File: `crates/pvthfhe-cli/tests/demo_large_n.rs`
Calls `run_full_pipeline(&PipelineConfig { n: 128, t: 65, seed: 1 }, &mut TestObserver::default())` directly (no subprocess), asserts:
- `Ok(report)`
- `report.plaintext_roundtrip_ok == true`
- elapsed wall time `< 600s` (envelope guard, not a perf gate)
Initially RED: fails at cyclo_fold with `NormBoundExceeded { got: 103, max: 102 }`.

> **All 4 RED tests must be added in step order, observed RED, then turned GREEN by the corresponding implementation step.**

## 9. Step-by-Step Execution

Each step below is one TDD slice: write the RED test → observe RED → make the smallest implementation change → observe GREEN. No step combines multiple changes.

### Step 1 — RED-1 lands

- Add `crates/pvthfhe-pvss/tests/error_display.rs`.
- Run `cargo test -p pvthfhe-pvss --test error_display` → MUST FAIL with the expected redaction.
- Capture failure output to `.sisyphus/evidence/demo-large-n-fixes/red-1.log`.

### Step 2 — Implement D1 (Display reveals inner string)

- Edit `crates/pvthfhe-pvss/src/lib.rs:104`:
  ```rust
  Self::BackendError(s) => write!(f, "PVSS backend error: {s}"),
  ```
- Run RED-1 → MUST PASS.
- Run `cargo test -p pvthfhe-pvss` (full crate) → MUST PASS (regression guard for any test that depended on the redacted text — fix any that did, treating those as oversight bugs).
- Search `crates/` for any test asserting the literal string `"PVSS backend error"` with no inner-string suffix; if found, decide per-case (most likely such tests are reasonable to relax).

### Step 3 — RED-2 lands

- Add `crates/pvthfhe-pvss/tests/context_too_large.rs` (uses `LatticePvssBfvAdapter::new()` — verify constructor signature first; if it requires a backend, follow the pattern used in `tests/encrypt_decrypt_roundtrip.rs`).
- Run `cargo test -p pvthfhe-pvss --test context_too_large` → MUST FAIL.

### Step 4 — Implement D2 part 1 (better message in `validate_context`)

- Edit `crates/pvthfhe-pvss/src/encrypt.rs:251-257` to branch:
  ```rust
  fn validate_context(ctx: &PvssContext) -> Result<(), PvssError> {
      const MAX_N: usize = u8::MAX as usize; // = 255; Shamir over GF(256)
      if ctx.n > MAX_N {
          return Err(PvssError::BackendError(format!(
              "invalid PVSS context: n={} exceeds maximum supported parties {} (Shamir over GF(256))",
              ctx.n, MAX_N
          )));
      }
      if ctx.n == 0 || ctx.t == 0 || ctx.t > ctx.n {
          return Err(PvssError::BackendError(format!(
              "invalid PVSS context: n={}, t={}", ctx.n, ctx.t
          )));
      }
      Ok(())
  }
  ```
- Run RED-2 → MUST PASS.
- Run `cargo test -p pvthfhe-pvss` → MUST PASS.

### Step 5 — RED-3 lands

- Add `crates/pvthfhe-cli/tests/demo_n_cap.rs` (uses `assert_cmd` like `tests/demo_threshold.rs`). Build with `--features nova-compressor`.
- Run `cargo test -p pvthfhe-cli --features nova-compressor --release --test demo_n_cap` → MUST FAIL (today the CLI lets the call through to PVSS).

### Step 6 — Implement D2 part 2 (CLI early guard) + D5 (clap docstring)

- Edit `crates/pvthfhe-cli/src/main.rs::run_demo` (line ~163). Insert before the existing threshold check:
  ```rust
  const MAX_N: usize = 255;
  if n == 0 || n > MAX_N {
      anyhow::bail!(
          "invalid n: n={n} must satisfy 1 <= n <= {MAX_N} (Shamir over GF(256))"
      );
  }
  ```
- Edit `Demo { n, .. }` clap doc (line ~78) to read `/// Number of parties (maximum 255).`.
- Run RED-3 → MUST PASS.
- Run `cargo test -p pvthfhe-cli --features nova-compressor --release` (full crate) → MUST PASS (especially `demo_threshold.rs`, which uses small n).

### Step 7 — RED-4 lands

- Add `crates/pvthfhe-cli/tests/demo_large_n.rs` calling `run_full_pipeline` in-process (no subprocess) for `n=128, t=65, seed=1`.
- Run `cargo test -p pvthfhe-cli --features nova-compressor --release --test demo_large_n` → MUST FAIL with `NormBoundExceeded` from cyclo.

### Step 8 — Implement D3 (fix stub witness bytes in pipeline)

- Edit `crates/pvthfhe-cli/src/full_pipeline.rs:309`:
  ```rust
  ccs_witness_bytes: vec![1u8; 32],
  ```
- Run RED-4 → MUST PASS.
- Run `cargo test -p pvthfhe-cli --features nova-compressor --release` (full crate) → MUST PASS.
- Run `cargo test -p pvthfhe-cyclo` → MUST PASS (sanity — should be untouched).
- Run `cargo test -p pvthfhe-aggregator` → MUST PASS (folding wiring).

### Step 9 — Implement D4 (mirror fix in bench fixtures)

- Edit `crates/pvthfhe-bench/src/bin/bench_scaling.rs:131` → `vec![1u8; 32]`.
- Edit `crates/pvthfhe-bench/src/bin/gen_goldens.rs:43` → `vec![1u8; 32]`.
- Run `cargo build -p pvthfhe-bench --release --bins` → MUST SUCCEED.
- Run `cargo test -p pvthfhe-bench` → MUST PASS.
- No new RED test required: D4 is a cosmetic fix to keep stub fixtures coherent. The runtime that would otherwise hit pid=102 is exercised indirectly by running the existing `bench-comparison-gate`.

### Step 10 — Implement D5 (Justfile + README)

- `Justfile` `demo-e2e` recipe: add a `@echo "* Supported range: 1 ≤ t ≤ n ≤ 255 (Shamir over GF(256)) *"` line in the recipe header (between existing `@echo` lines).
- `README.md` Quickstart bullet for `just demo-e2e`: append `" (supported range: n ≤ 255)"`.
- No test for Justfile prose. README test: extend `tests/integration/docs_truthful.rs` (or add a small literal-string test) asserting `README.md` contains both `"demo-e2e"` and `"255"` on the same logical bullet — only if a similar pattern already exists; otherwise skip and rely on review.

### Step 11 — Final Verification Wave

Run **all** invariants:
- I1 (lsp_diagnostics): zero new errors on the four edited files (`lib.rs`, `encrypt.rs`, `main.rs`, `full_pipeline.rs`).
- I2 (no new `#[allow]`): `policy_invariants::no_new_allow_attributes_*` GREEN.
- I3 (full pvthfhe-pvss tests): `cargo test -p pvthfhe-pvss` GREEN.
- I4 (full pvthfhe-cli tests release+nova-compressor): `cargo test -p pvthfhe-cli --features nova-compressor --release` GREEN.
- I5 (full pvthfhe-bench tests): `cargo test -p pvthfhe-bench` GREEN.
- I6 (full pvthfhe-aggregator tests): `cargo test -p pvthfhe-aggregator` GREEN.
- I7 (full pvthfhe-cyclo tests): `cargo test -p pvthfhe-cyclo` GREEN.
- I8 (`bench-comparison-gate`): `just bench-comparison-gate` GREEN.
- I9 (no scope creep): `git diff --stat` only touches the files listed in §7.

### Step 12 — Acceptance criteria (manual smoke runs)

Run all three under `ulimit -v 16777216`, disowned via `setsid nohup`, evidence under `.sisyphus/evidence/demo-large-n-fixes/`:

- **A1 — small (regression baseline):** `just demo-e2e 8 5 1` → exit 0, `plaintext_roundtrip: OK`, `verify: ACCEPT`. Wall-clock comparable to the predecessor plan's 5.15s.
- **A2 — large supported:** `just demo-e2e 128 65 1` → exit 0, `plaintext_roundtrip: OK`, `verify: ACCEPT`. Capture wall-clock; soft envelope: < 5 minutes.
- **A3 — boundary:** `just demo-e2e 255 128 1` → exit 0, `plaintext_roundtrip: OK`, `verify: ACCEPT`. Soft envelope: < 10 minutes (PVSS phase scales with n).
- **A4 — cap rejection:** `just demo-e2e 256 129 1` → non-zero exit, stderr contains `"255"` and explanation, **no** "step 4/9" line in stderr or stdout.

Each acceptance run produces:
- `STATUS` (`STARTED <ts>` then `EXIT $rc <ts>`)
- `wall.time` (from `/usr/bin/time -v`)
- `run.log` (full stdout/stderr)

## 10. Acceptance Criteria

- [x] All 12 plan checkboxes marked `- [x]`.
- [x] All four RED tests landed and now GREEN.
- [x] All eight invariants (I1–I8) verified GREEN; I9 (no scope creep) confirmed.
- [x] All four acceptance smoke runs (A1–A4) match expected outcomes.
- [x] No new `#[allow(...)]` attributes anywhere in this plan's diffs.
- [x] `git diff --stat` matches §7 exactly (plus the four new test files).
- [x] Working tree dirty until user explicitly requests commit.

## 11. Risks & Mitigations

| Risk                                                                      | Likelihood | Mitigation                                                                                          |
|---------------------------------------------------------------------------|------------|-----------------------------------------------------------------------------------------------------|
| Existing test asserts redacted "PVSS backend error" string verbatim       | Low        | Step 2 runs full `pvthfhe-pvss` test suite; relax any such test in step 2.                          |
| Demo at `n=255` exceeds 10-minute envelope                                | Medium     | A3 envelope is soft; plan acceptance is `verify: ACCEPT`, not perf. If too slow, document in notepad. |
| `bench_scaling.rs` golden values shift after D4                           | Low        | Goldens are based on output schema, not raw witness bytes; verified by I5.                         |
| Cyclo per-step heuristic semantics drift if real witness bytes added later | Out of scope | Documented in §4 Non-Goals; tracked in notepad if observed.                                       |
| `validate_context` message change breaks downstream string-equality tests | Low        | Step 4 covers full `pvthfhe-pvss`; Step 11 covers crates that import PvssError.                     |

## 12. Out-of-Scope Follow-ons (informational)

- **Lift the n ≤ 255 cap.** Would require Shamir over a larger field (GF(2^16) or a prime field), updates to `shamir_split` / `recover` / Lagrange, audit of NIZK circuits in `circuits/decrypt_share` and `circuits/aggregator_final` which may also assume `u8` indices, and witness generation updates in `crates/pvthfhe-circuit-tests/src/witness_gen.rs`. Distinct plan.
- **Real witness bytes for Cyclo CCS instances.** Currently `ccs_witness_bytes` is synthetic across the entire codebase (cli, bench, cyclo tests). Phase-2 cryptography work item.
- **Surface FHE backend errors more granularly.** `map_fhe_error` flattens FheError to a string today; once Display reveals it, structured error inspection may be desirable.

---

## Checkboxes

- [x] Step 1 — RED-1 lands (PvssError Display test)
- [x] Step 2 — D1 implemented; RED-1 GREEN
- [x] Step 3 — RED-2 lands (context-too-large names cap)
- [x] Step 4 — D2 part 1 implemented; RED-2 GREEN
- [x] Step 5 — RED-3 lands (CLI early guard)
- [x] Step 6 — D2 part 2 + D5 (clap docstring) implemented; RED-3 GREEN
- [x] Step 7 — RED-4 lands (demo n=128,t=65)
- [x] Step 8 — D3 implemented; RED-4 GREEN
- [x] Step 9 — D4 implemented (bench fixtures)
- [x] Step 10 — D5 documentation (Justfile + README)
- [x] Step 11 — All invariants I1–I9 verified
- [x] Step 12 — Acceptance criteria A1–A4 verified by manual smoke runs
