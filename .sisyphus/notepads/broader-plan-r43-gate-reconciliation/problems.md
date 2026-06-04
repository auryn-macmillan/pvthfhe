# Problems — broader-plan-r43-gate-reconciliation

## [2026-06-03] BLOCKER: T5 reveals unresolved F67 vulnerability under the threshold panic

**T5 threshold-bound fix is DONE & correct** (6 sites → `n/2+1`, matches threat-model §2.2;
threshold assertion tests pass). BUT it unmasked a deeper problem:

`crates/pvthfhe-fhe/tests/aggregate_uses_submitted_shares.rs` is a RED test for audit finding
**F67** (`aggregate_decrypt` silently recomputes decrypt shares from internal PartyState by
party_id, DISCARDING submitted share bytes → malicious aggregator can submit garbage and still
recover plaintext; ct_hash binding meaningless). The threshold panic at line 28 was MASKING the
F67 assertion. Now the test reaches `assert!(result.is_err())` and FAILS — `aggregate_decrypt`
returns Ok() for a share taken from a DIFFERENT ciphertext (+byte flip). Verified verbatim
2026-06-03.

**Gate impact:** phase1-gate.py (L45-48) runs `cargo test -p pvthfhe-fhe --features real-nizk`
and requires exit 0. This test is in that crate → phase1-gate CANNOT be green until F67 is fixed.
The plan T5 misdiagnosed debt-item-c as purely the threshold bound; the real blocker is F67.

**Status of F67:** Known audit finding (AUDIT-2026-05-08). Prior plan `pvthfhe-remediation`
R8.2 CLAIMED a GREEN fix (pre-reveal-binding.md:203 "GREEN F67 fix at L626-654") but the prior
notepad CONTRADICTS this: learnings.md:1601 "Pre-existing RED test ...(F67) remains RED";
learnings.md:1648 "F67 — known R8.2 issue, documented in plan"; AUDIT-2026-05-09:149 lists F67
among "~15 prior audit findings remain unresolved". => F67 was never actually fixed.

**F67 vs C7:** F67 is a BOUNDED engineering fix (use submitted shares, not internal state) per
pre-reveal-binding.md §3.2 — NOT the hard open-research problem C7 (threshold-decrypt CORRECTNESS).
So F67 looks independently fixable, but it is a real security-critical change to aggregate_decrypt
(fhers.rs ~664-691) that this plan never scoped and the prior remediation deferred.

**DECISION NEEDED (escalated to user):**
(A) Expand scope: fix F67 in aggregate_decrypt (genuinely greens the test + closes a real vuln), OR
(B) Re-classify T5 gate-green as documented blocker (phase1-gate stays RED; plan DoD unmet), OR
(C) Treat F67 as out-of-scope/blocked and #[ignore] the test with rationale (gate green but vuln
    documented-deferred — borderline vs honesty mandate).
Pausing for user direction before touching aggregate_decrypt security logic.

## [2026-06-03] USER DECISION: Option A — expand scope, fix F67 now.

## [2026-06-03] CRITICAL CORRECTION to F67 diagnosis + FLAKINESS finding

On deeper inspection the original F67 diagnosis is PARTLY WRONG:

1. **Current `aggregate_decrypt` (fhers.rs ~1324-1414) ALREADY consumes submitted shares.** It
   decodes `wire::decode_decrypt_share(share.bytes)`, builds `share_polys` from the SUBMITTED
   bytes, and passes them to `ShareManager::decrypt_from_shares(share_polys, party_ids, ct)`
   (upstream `fhe::trbfv`). Internal `PartyState` is NOT consulted during aggregate_decrypt.
   Verified by reading the full function + confirming `git diff` shows fhers.rs changed ONLY for
   the T5 threshold bound (lines 788-799), NOT aggregate_decrypt.

2. **The RED test is FLAKY, not deterministically failing.** Ran the compiled test binary 20×:
   **16 PASS (is_err) / 4 FAIL (is_ok)** (~20% failure rate). Cause: the test uses `thread_rng()`,
   so the Gaussian smudging noise in `partial_decrypt` is non-deterministic. A cross-ciphertext +
   byte-flipped share3 makes Lagrange recombination produce a GARBAGE plaintext poly; whether it
   errors depends purely on whether the random garbage `slots[0]` length exceeds the
   `decode_plaintext_slots` bound (fhers.rs ~670-693). ~20% of draws decode to a short length →
   Ok(garbage) → assertion fails. So the test "passes" only by ACCIDENT of decode-length overflow,
   NOT because any real binding check rejects the bad share. My earlier handoff "FAILS" and the
   T1/T4 subagent's "1 passed" were BOTH correct — different RNG draws.

**Revised understanding of the genuine F67 gap:** there is currently NO deterministic mechanism
that rejects a valid-wire-format, valid-Poly share that is a partial decryption of the WRONG
ciphertext. "Use submitted shares" (recombination) is already done; what's missing is binding each
submitted share to THIS ciphertext and rejecting mismatches DETERMINISTICALLY.

**Action:** Consulted Oracle (ses pending) for the precise bounded fix (likely ct_hash binding in
the decrypt-share wire format + deterministic test RNG) and an explicit C7-boundary ruling —
i.e. confirm the fix does NOT stray into open-problem C7 (threshold-decrypt correctness). Awaiting
Oracle spec before delegating implementation.

## [2026-06-03] BLOCKER: phase1-gate RED from 6 PRE-EXISTING failures (NOT F67/T5)
DISCOVERY during F67 verification. phase1-gate.py:44-48 runs `cargo test -p pvthfhe-fhe --features real-nizk` (requires exit 0). F67 is necessary-NOT-sufficient. Prior handoff assumption "phase1-gate green pending F67" was WRONG.

PRE-EXISTING failures (test files + NIZK src UNMODIFIED in working tree; not caused by this session):
1. banner.rs ×2 (`banner_source_replaces_old_surrogate_wording` :124, `banner_default_backend_emits_folding_warning_and_not_old_banner` :86). build.rs UNMODIFIED and does NOT contain expected "FOLDING ACCUMULATOR IS A SURROGATE" wording (only MOCK BACKEND warning at build.rs:6). Post-Nova-migration drift: folding now real Nova, surrogate banner removed from build.rs but banner tests still expect it. Likely genuinely-fixable (update tests/build.rs to current reality) BUT edits security-warning wording -> judgment needed.
2. lattice_nizk.rs ×3 (`test_tampered_share_rejected` :93, `test_wrong_pvss_commitment_rejected` :110, `test_verify_rejects_mismatched_participant_binding` :174) + lattice_nizk_adversarial.rs ×1 (`test_nizk_accepts_wrong_witness_fails` :208). These ADVERSARIAL SOUNDNESS tests assert RealNizkAdapter::verify REJECTS tampered secret_share / wrong pvss_commitment / mismatched participant_id. They FAIL because the Cyclo-backed RealNizkAdapter does NOT enforce these bindings == OPEN PROBLEM P1 (Lattice NIZK well-formedness soundness, research-BLOCKED). Standing-red since Cyclo adapter migration (commits 1f21c59 / 28bdd4a). NOT in current T1-T7 scope; plan says "OPEN research problems remain BLOCKED-OPEN / fail-closed".

DECISION REQUIRED (escalated to user) — must NOT unilaterally weaken/delete/#[ignore] soundness tests to fake green (honesty mandate) NOR attempt P1 fix (research-blocked).

## [2026-06-03] DISCOVERED BLOCKER: phase1-gate clippy -D warnings fails (278 unwrap_used/expect_used)

**Discovered during T7 phase1-gate verification.** Independent of all prior task work (my edits
were fhe-crate test files + Justfile; this fails in nizk crate before reaching fhe).

- `phase1-gate.py:53-58` runs `cargo clippy -p pvthfhe-nizk -p pvthfhe-fhe --all-targets -- -D warnings`.
- `[workspace.lints.clippy]` (root Cargo.toml:42-44) sets `unwrap_used = "warn"`, `expect_used = "warn"`
  (no `cfg(not(test))` gating). `-D warnings` promotes ALL to hard errors.
- Fresh-build clippy scope (after `cargo clean`): **278 unwrap()/expect() violations** across ~37 files.
- Classification: **~276 are TEST code** (`tests/*.rs` integration crates + `#[cfg(test)]` modules in src,
  e.g. fhers.rs:1998-2076 under `mod tests` @1954; bootstrap_sigma.rs:266-382 under cfg(test)@239;
  bfv_sigma.rs:612/634 under cfg(test)@587; mock_impl.rs:203/222 inside `#[test] fn`@202).
- **ONLY genuine PRODUCTION-code violations: `bootstrap_sigma.rs:55,56`** — `bytes[..8].try_into().unwrap()`
  AFTER an explicit `if bytes.len() < 16 { return Err(...) }` guard (:52). Infallible; trivially fixed with
  fixed-size array + `copy_from_slice` (no unwrap/expect needed).
- Also other non-unwrap clippy warnings present (e.g. unused var `ct` fhers_partial_decrypt.rs:29;
  needless borrow bootstrap_sigma.rs:233; unreadable hex literal nizk_adversarial.rs:95) — `-D warnings`
  fails on these too. Full clean output captured: `/tmp/clippy_clean.txt`.

STATUS: Oracle disposition ruling requested (test-code lint exemption vs no-weakening mandate; cleanest
mechanism). NOT yet resolved.

### RESOLVED [2026-06-03] phase1-gate clippy blocker — FIXED + VERIFIED
Per Oracle ruling (decisions.md). Subagent ses_17049f5e5ffe implemented; orchestrator INDEPENDENTLY VERIFIED:
- Workspace lints UNCHANGED (production strict). lib.rs ×2 use `#![cfg_attr(test, allow(...))]` (cfg-gated).
- 2 production unwraps bootstrap_sigma.rs:55,56 genuinely fixed via try_into().map_err(...)? (no expect/allow).
- 32 integration-test files given bare `#![allow(clippy::unwrap_used, clippy::expect_used)]`.
- Non-unwrap warnings fixed (needless borrow stmt.bsk_hash, unused vars _-prefixed, hex grouping, etc.) — all behavior-preserving (verified by reading diffs; test-only or Copy-semantics).
- **`python3 .sisyphus/scripts/phase1-gate.py` → PHASE 1 GATE: PASS, exit 0** (all 16 checks incl. nizk --release test, fhe real-nizk test, clippy -D warnings). Run by orchestrator. phase1-gate is GENUINELY GREEN.

## [2026-06-03] T2 follow-up debts (non-blocking, surfaced during verification)

1. **folding.rs incompatible with `--features real-nizk`**: `tests/folding.rs` (migrated off legacy-fold,
   passes on DEFAULT = real-folding, 6 passed) FAILS under `--features real-nizk` (5 failed) because its
   synthetic 32-byte "valid" success witnesses are rejected by the 26,658-byte real-nizk size gate.
   NOT gate-blocking: phase2-gate runs only `--test aggregate_1024_smoke` (default); phase3-gate
   `step_workspace_tests` runs `cargo test -p pvthfhe-aggregator` on DEFAULT features (no --features).
   FIX (deferred): apply the same `VALID_SYNTHETIC_PROOF_LEN = 2+32+26624` (real-nizk) / 32 (default)
   const pattern used in folding_adversarial.rs / folding_witness_validation.rs to folding.rs positive
   witnesses, so the whole aggregator suite is production-profile-consistent.

2. **phase3 workspace clippy risk for T7**: phase3-gate.py:72 runs `cargo clippy --workspace -- -D warnings`.
   The 278-unwrap clippy fix only added `#![cfg_attr(test, allow(unwrap_used,expect_used))]` to
   pvthfhe-nizk + pvthfhe-fhe lib.rs (+ bare allow to their integration tests). Other crates
   (aggregator, cyclo, cli, micronova, ...) test code may still trip `-D warnings` under the
   workspace clippy. Verify/extend when running T7 phase3 (CI/disk-provisioned only).

## [2026-06-04] T7 phase3 workspace-clippy BLOCKER — REAL, in pvthfhe-compressor lib (NOT the expected test-unwrap debt)

Discovered running T7. phase1-gate=PASS (re-confirmed), phase2-gate=PASS (all 10 checks incl
aggregate_1024_smoke fresh-JSON + cargo check --workspace). phase3 step_clippy
(`cargo clippy --workspace -- -D warnings`, NO --all-targets) FAILS exit 101.

IMPORTANT correction to problems.md item #2 (2026-06-03): the phase3 clippy gate does NOT use
`--all-targets`, so the 278-unwrap TEST-code debt is OUT of gate scope (libs+bins only). The ACTUAL
failure is 18 PRODUCTION-LIB lints all in `pvthfhe-compressor`, 3 files:
  - src/nova/fhe_compute_circuit.rs (10): too_many_arguments@243/357/494 (9/7,10/7,8/7),
    needless_late_init@455, manual_div_ceil@461, needless_lifetimes@510, unnecessary_to_owned@761/764/770, ptr_arg@911
  - src/nova/monomial_range.rs (4): unnecessary_cast@45/53 (u64->u64), @109/137 (u32->u32 on usize::BITS)
  - src/nova/mod.rs (4): unused_mut@2205, needless_borrows_for_generic_args@938, single_match@2095/2158
All behavior-preserving style lints w/ exact clippy suggestions. Disposition: apply suggested fix for
15; the 3 too_many_arguments get targeted `#[allow(clippy::too_many_arguments)]` (Nova circuit-builder
helpers; sig refactor risky+out-of-scope; style heuristic not correctness). Full capture: /tmp/clippy_gate_exact.txt
Delegated to subagent for fix. Gate-exact command must pass after.

## [2026-06-04] T7 phase3 HEAVY steps — disk/resource constraint (per plan T7 "coordinate resources first")
Disk 30G->25G free / 80%+ used after phase1+phase2+clippy. phase3-gate has heavy steps NOT safely
runnable here: demo-e2e, bench-scaling (n128/256/512/1024 envelopes), noir-tests (nargo+bb proving),
forge-tests, adversarial-suite. Plan T7 explicitly: "phase3 in CI or a disk-provisioned environment;
do NOT run casually on the constrained dev box — coordinate resources first." These are pre-existing
infra steps NOT touched by R4.3 gate-reconciliation debt. Decision pending: run full phase3 only in
CI/disk-provisioned env; locally verify the in-scope clippy step + cheap file-check steps.
