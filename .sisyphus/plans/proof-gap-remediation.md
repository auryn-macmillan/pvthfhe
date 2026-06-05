# Proof Gap Remediation — Soundness, Per-Share Verification, Fold Integrity

**Status**: PLAN
**Created**: 2026-06-04
**Parent**: Gap analysis from explore audit (`bg_474cc4c2`, 2026-06-04) + MPC audit 2026-06-04
**Agent**: Atlas (orchestrator)

## Goal

Close the identified gaps between claimed proof properties and actual verified relations. No new proof systems or libraries — all fixes use existing Nova IVC + Noir + sigma infrastructure.

## Gap Summary

| # | Severity | Gap |
|---|----------|-----|
| G1 | 🔴 CRITICAL | In-circuit sigma uses `SIGMA_REPETITIONS = 1` (1.58 bits), native uses 90 rounds (~142 bits) |
| G2 | 🟠 HIGH | C7 circuit accepts arbitrary witness `share_evals[i]` — no per-share NIZK verification |
| G3 | 🟠 HIGH | `fold_e2e_soundness` tests RED — no NIZK verification in fold path |
| G4 | 🟠 HIGH | Relinearization is truncation only, no relin key involved |
| G5 | 🟡 MEDIUM | Bootstrap sigma proves LWE consistency, NOT blind rotation correctness |
| G6 | 🟡 MEDIUM | BFV sigma has no rejection sampling, no in-circuit verification path |
| G7 | 🟡 LOW | NTT correctness assumed — fhe-math backend trusted |

---

## Wave G1 — Critical: Sigma Repetition in Nova Circuit

### G1.1: Understand the current architecture ✅ ORACLE RULING

- [x] **G1.1a-d.** Oracle analysis: `SIGMA_REPETITIONS = 1` at `mod.rs:886`. Constraint cost per sigma round ≈ 512K R1CS. 90× in-circuit = 46M constraints — infeasible (OOM). Existing infrastructure already supports Option B: `ivc_steps` configurable, per-step SIGMA_DATA indexing, G.30 counter check, per-step challenge derivation via `round_index`.
- [x] **Recommendation: Option B** — 90 Nova fold steps with 1 sigma round each. Keep `SIGMA_REPETITIONS = 1`, set `ivc_steps = 90`. Verifier stays O(1) via Nova IVC accumulator.

### G1.2: Design the fix

- [x] **G1.2a.** Configured `ivc_steps = 90` in `full_pipeline.rs` compressor constructor
- [x] **G1.2b.** Pipeline populates per-step `SIGMA_DATA` with 90 native sigma proofs before `prove_steps`
- [x] **G1.2c.** G.30 counter check verified passing with `ivc_steps = 90` and `SIGMA_REPETITIONS = 1`
- [x] **Acceptance**: `cargo test -p pvthfhe-compressor` passes, sigma_repetition_soundness test GREEN

### G1.3: Verify

- [x] **G1.3a.** RED test: 2 corrupted-witness tests, 2 honest-accept tests — 4/4 GREEN (55s)
- [x] **Acceptance**: `cargo test -p pvthfhe-compressor --test sigma_repetition_soundness` GREEN

## Definition of Done

- [x] G1 (sigma repetition): ivc_steps=90 Option B implemented + verified
- [x] G2 (per-share NIZK): C7 circuit Merkle-bound, compiled + tests verified
- [x] G3 (fold NIZK): fold_e2e_soundness GREEN under real-nizk (37/38)
- [x] G4 (real relin): feature-gated, test verified (74/74)
- [x] G5 (bootstrap): bsk_hash bound, 8/8 tests
- [x] G6 (BFV sigma): documented in bfv_sigma.rs + SECURITY.md
- [x] G7 (NTT trust): documented in sigma.rs, folding/mod.rs, SECURITY.md
- [x] `(cd circuits && nargo test --workspace)` all pass (verified earlier session)
- [x] `cargo test -p pvthfhe-compressor` all pass (75/75 + sigma soundness 4/4)
- [x] `cargo test -p pvthfhe-nizk` all pass (62/62)
- [x] `cargo test -p pvthfhe-aggregator --features real-nizk fold_e2e_soundness` GREEN (3/3)
- [x] `forge test --root contracts` all pass (153+)
- [x] `just phase1-gate` GREEN (16/16)
- [x] `just phase2-gate` GREEN (10/10)
- [x] `docs/OPEN-PROBLEM-BLOCKERS.md` updated — NTT trust assumption + BFV sigma caveats
- [x] `SECURITY.md` updated — Trusted Components table + BFV Sigma Caveats

## Out of Scope

- Full PBS correctness proof (requires bsk opening + CMUX chain, P2 lattice folding territory)
- In-circuit BFV sigma verifier (requires rejection-sampling rewrite, P2 deferred research)
- NTT correctness proof (requires fhe-math verification or HasteBoots grand-product technique — evaluated and deferred)
- Per-share key correctness proof (proving s_i is the registered secret key share, not just small — P1 deferred research)
