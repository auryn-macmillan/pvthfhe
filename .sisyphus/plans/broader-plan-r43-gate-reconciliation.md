# Plan: broader-plan-r43-gate-reconciliation

> **Provenance.** This plan captures the work that was explicitly OUT OF SCOPE for the
> `remediate-soundness-completeness-audit` plan (completed 2026-06-03, Final Wave APPROVED by
> Momus + Oracle). During Phase 7 of that remediation, end-to-end gates `just phase1-gate`
> and `just phase2-gate` were found to be RED due to **broader-plan R4.3 (post-Nova migration)
> debt** that predates and is unrelated to the audit remediation. Those failures were honestly
> recorded — never force-greened — in `.sisyphus/evidence/phase7-gate-evidence.md` and
> `.sisyphus/notepads/remediate-soundness-completeness-audit/problems.md` (items a–d) with git
> attribution. This plan exists to reconcile that debt and restore green end-to-end gates.

> **Honesty mandate (inherited, NON-NEGOTIABLE).** Do NOT fabricate gate greenness. Do NOT
> hardcode/stub witness data, doctor JSON artifacts, or weaken security constraints merely to
> make a gate pass. Every task below must reach green by genuinely correct means or be
> explicitly re-classified as a documented blocker. OPEN research problems P4/C7/C5/A1 remain
> BLOCKED-OPEN / fail-closed and are NOT in scope here.

> **Toolchain / environment notes.** Repo root `/home/dev/pvthfhe`. Cargo needs
> `PVTHFHE_ALLOW_RESEARCH_BUILD=1`; prefix test commands with `CI=true GIT_PAGER=cat PAGER=cat`.
> Foundry: `forge ... --root contracts` (match-path relative to `--root`). Noir:
> `(cd circuits && nargo ...)`. Disk is constrained (~63G; avoid `cargo build --workspace`,
> `just demo-e2e`, `just phase3-gate` casually — they ENOSPC / run for hours). Write RED tests
> before implementation per AGENTS.md TDD policy.

---

## Background

The R4.3 post-Nova migration (commits `83692e6`, `97d3096`, `39db19a`, plus `8998157` poison-pill,
`80a0c82` Shamir bound, `b3341ac` test, `3f6e920` F9 bench) removed the legacy hash-chain folding
surrogate and wired the real Cyclo LatticeFold+ backend under default `real-folding`, while making
`legacy-fold` a compile-time poison pill. That migration left several gate inputs internally
inconsistent. None were touched by the audit remediation; all are reproduced verbatim in the
evidence files referenced above.

---

## TODOs

### T1 — Reconcile `aggregate_1024_smoke` with the real-folding Cyclo backend (debt item a)

- [x] **RED first:** From a clean state, run
  `CI=true PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-aggregator --test aggregate_1024_smoke`
  with the legacy-fold pin temporarily removed, and confirm the current failure
  `NormBoundExceeded { got: 18446744073709551615 (=u64::MAX), max: 102 }` (sentinel from
  `crates/pvthfhe-cyclo/src/fold.rs:42`, `Err(_) => u64::MAX`). Record the verbatim output as the RED baseline.
- [x] Diagnose why the F9-era synthetic share data in `crates/pvthfhe-aggregator/tests/aggregate_1024_smoke.rs`
  parse/decode-fails under the real norm-enforcing Cyclo backend (`HashChainCycloAdapter` → real folding).
  Determine the correct, valid Cyclo witness construction (proper Ajtai commitment bytes, norm-bounded
  share encodings) that the real backend accepts. `AJTAI_COMMITMENT_BYTES = AJTAI_COMMITMENT_M * PHI_COMMIT * 8`
  (`crates/pvthfhe-cyclo/src/fold.rs:14`), NOT 32.
- [x] Rebuild the smoke test to construct GENUINELY valid witness data (no fabricated/forced values) so it
  passes under default `real-folding`. The test must exercise the real fold path, not a bypass.
- [x] Make the test actually emit `bench/results/aggregate_1024.json` itself (so phase2-gate's JSON check is
  backed by fresh output, not a stale committed artifact — see T4), OR coordinate the JSON-producing step
  with T4's decision. Do NOT keep trusting the committed F9 artifact.
- [x] **Remove the legacy-fold quarantine pin** for `aggregate_1024_smoke` in
  `crates/pvthfhe-aggregator/Cargo.toml` once the test genuinely passes under `real-folding`.
- [x] **Acceptance:** `cargo test -p pvthfhe-aggregator --test aggregate_1024_smoke` passes under default
  features; `cargo test -p pvthfhe-aggregator` (package-wide) stays green; no `legacy-fold` reference remains
  for this target.

### T2 — Resolve the `legacy-fold` poison-pill quarantine cleanup (debt item a, cleanup)

- [x] Inventory the 9 test targets still pinned to `required-features = ["legacy-fold"]` in
  `crates/pvthfhe-aggregator/Cargo.toml`: `folding`, `folding_adversarial`, `p2_bench`,
  `aggregate_1024_smoke` (handled in T1), `decrypt_real`, `keygen_real_encryption`, `folding_multi_track`,
  `folding_relation`, `folding_witness_validation`.
- [x] For each: decide its true post-R4.3 disposition — (a) migrate to real-folding and re-enable, or
  (b) genuinely obsolete → delete the test (per AGENTS.md stub protocol: replace in place, never silently
  orphan), or (c) legitimately deferred → convert to `#[ignore]` with a documented reason instead of a
  poison-pill feature pin. The poison-pill `compile_error!` at
  `crates/pvthfhe-aggregator/src/folding/mod.rs:14-17` means these targets can never compile under the pinned
  feature; that is a confusing quarantine mechanism and should be replaced.
- [x] **Acceptance:** No test target depends on the `legacy-fold` poison-pill feature; each former
  legacy-fold target is either re-enabled under real-folding, deleted, or `#[ignore]`-d with a rationale
  comment. Consider removing the now-unused `legacy-fold = []` feature definition entirely.

### T3 — Remove the phantom `pvthfhe-api` crate from gate REQUIRED_ARTIFACTS (debt item b)

- [x] Confirm `crates/pvthfhe-api/src/lib.rs` does not exist and is not a workspace member
  (verbatim: it is absent).
- [x] In `.sisyphus/scripts/phase2-gate.py` REQUIRED_ARTIFACTS (lines 17–25), either (a) remove the
  `crates/pvthfhe-api/src/lib.rs` entry if the API crate was genuinely dropped in R4.3, or (b) if an API
  surface is still intended, create the real crate — but ONLY if it genuinely exists in the architecture;
  do NOT fabricate a stub crate solely to satisfy the gate.
- [x] Cross-check the rest of REQUIRED_ARTIFACTS against the current workspace to catch any other stale
  artifact references introduced by the migration.
- [x] **Acceptance:** `python3 .sisyphus/scripts/phase2-gate.py` no longer fails on a missing
  `pvthfhe-api` artifact; every listed artifact actually exists.

### T4 — Stop phase2-gate trusting a stale committed JSON artifact (debt item d)

- [x] Confirm `aggregate_1024_smoke.rs` does not currently write `bench/results/aggregate_1024.json`
  (committed 93-byte F9 artifact from `3f6e920`, May 27).
- [x] Decide the correct design: the gate's JSON existence check at `.sisyphus/scripts/phase2-gate.py:167-177`
  should validate output FRESHLY produced by the test run (coordinate with T1), not a pre-committed file.
  Either make the test emit the JSON (preferred), or change the gate to regenerate + validate it.
- [x] Remove the stale committed `bench/results/aggregate_1024.json` from version control if it is now a
  build product (and gitignore it), unless it is an intentional fixture.
- [x] **Acceptance:** phase2-gate's aggregate_1024 JSON check passes only when the JSON is genuinely produced
  by the current test run; no stale artifact dependency remains.

### T5 — Reconcile the n=5 / t=3 threshold test with the Shamir bound (debt item c)

- [x] Reproduce the phase1-gate failure:
  `CI=true PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-fhe --test aggregate_uses_submitted_shares`
  → panic at `crates/pvthfhe-fhe/tests/aggregate_uses_submitted_shares.rs:28`:
  `"threshold t=3 exceeds max_t=2 for n=5. Must satisfy t ≤ (n-1)/2 for Shamir security."` (exit 101).
- [x] Determine the correct fix WITHOUT weakening security: the constraint `t ≤ (n-1)/2`
  (`crates/pvthfhe-fhe/src/fhers.rs:794`) was added by broader-plan `80a0c82`; the test
  `setup_threshold(5,3)` (last touched by `b3341ac`) predates/contradicts it. Decide whether the TEST
  parameters are wrong (e.g., should be n=7,t=3 or n=5,t=2 to satisfy the bound) or whether the CONSTRAINT
  is too strict for this protocol's security model. The test's INTENT (aggregate must use submitted shares,
  not internal state) must be preserved.
- [x] Update the test parameters and/or the constraint accordingly, with a comment explaining the security
  rationale. Do NOT simply relax the bound to pass the test if the bound is correct.
- [x] **Acceptance:** `cargo test -p pvthfhe-fhe --test aggregate_uses_submitted_shares` passes; the Shamir
  security bound remains sound; `just phase1-gate` is green.

### T6 — Fix pre-existing R4.3 type-migration drift in the aggregate bench

- [x] Fix LSP/type errors in `crates/pvthfhe-aggregator/benches/aggregate_1024.rs:43-46`:
  `expected ProtocolBytes/CcsWitnessSecret, found Vec<u8>` — leftover from the R4.3 `pvthfhe-types`
  newtype migration. Update the bench to construct the new wrapper types.
- [x] **Acceptance:** `cargo build -p pvthfhe-aggregator --benches` compiles cleanly; `lsp_diagnostics` on the
  file is clean.

### T7 — End-to-end gate green-up + evidence refresh

- [x] After T1–T6, run all three gates and capture verbatim evidence: `just phase1-gate`, `just phase2-gate`,
  and `just phase3-gate` (phase3 in CI or a disk-provisioned environment; do NOT run casually on the
  constrained dev box — coordinate resources first).
- [x] Update `.sisyphus/evidence/phase7-gate-evidence.md` (or write a new `r43-gate-evidence.md`) to record
  the now-GREEN state, superseding the honest RED-with-scope record once genuinely resolved.
- [x] **Acceptance:** phase1/phase2/phase3 gates all GREEN by genuinely-correct means; evidence updated.

---

## Out of scope (explicitly NOT this plan)

- OPEN research problems **P4** (on-chain IVC decider), **C7** (threshold-decrypt correctness),
  **C5** (aggregate-pk formation proof), **A1** (Cyclo accumulator transcript) — remain BLOCKED-OPEN /
  fail-closed; tracked in `docs/OPEN-PROBLEM-BLOCKERS.md`.
- Separately-tracked audit-remediation follow-ups (already filed in
  `.sisyphus/notepads/remediate-soundness-completeness-audit/problems.md`), which may warrant their own
  plan(s):
  - **Gap C** — `contracts/src/PvtFheVerifier.sol` `_ivcProofConsumed` key `(dkgRoot, epoch)` not runId-scoped
    (lines 188-191, 623-627; `_computeIvcStatementHash` ~line 542). Investigate replay-vs-intended before any
    IVC enablement. Low live risk today (IVC fail-closed).
  - **witness_gen staleness** — `crates/pvthfhe-circuit-tests/src/witness_gen.rs`
    `generate_aggregator_final_witness()` + `AggregatorFinalWitness` still use the OLD polynomial-quotient
    shape vs canonical VerificationStatementV1 (27 public inputs). Dead generator/bin only; update or delete.
  - **e2e_real broken config** — `crates/pvthfhe-aggregator/tests/e2e_real.rs` broken in its only buildable
    feature set (`real-verifier` + `mock`): `KeygenSimulator` calls `decode_pk_polys`
    (`crates/pvthfhe-aggregator/src/keygen/simulator.rs:526`) but the mock backend returns
    "decode_pk_polys not implemented" (`crates/pvthfhe-fhe/src/lib.rs:215`). Also `Justfile:302` demo runs
    `e2e_real` without `mock`.

---

## Definition of Done

- [x] T1–T7 acceptance criteria all met.
- [x] `just phase1-gate`, `just phase2-gate`, `just phase3-gate` all GREEN by genuinely-correct means
      (no fabricated greenness, no weakened security constraints, no stale-artifact trust).
- [x] No remaining `legacy-fold` poison-pill dependencies.
- [x] Gate evidence file updated to reflect the resolved state.
- [x] OPEN problems P4/C7/C5/A1 untouched and still fail-closed.
