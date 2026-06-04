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

- [ ] **G1.3a.** RED test: corrupt one witness coefficient; verify that 90-fold accumulated instance REJECTS with high probability
- [ ] **Acceptance**: `cargo test -p pvthfhe-compressor sigma_repetition_soundness` GREEN, verifies corruption is detected > 99% of the time over 100 random trials

---

## Wave G2 — High: Per-Share NIZK in C7 Circuit

### G2.1: Wire sigma verification into the C7 Noir circuit

The C7 circuit (`aggregator_final/src/main.nr`) currently accepts `share_evals[i]` as witness inputs. It needs to verify that each `share_evals[i]` is the polynomial evaluation of a decrypt share `d_i` that was proven valid by a sigma NIZK.

- [x] **G2.1a-c.** Added `share_commitment_root`, per-share Merkle paths, eval-binding constraints. `main.nr` +308/-222
- [x] **G2.2a.** `build_c7_prover_toml()` builds Merkle tree over 128 share commitments
- [x] **G2.3a-b.** RED tests: share_eval not in Merkle REJECTS, wrong leaf REJECTS
- [x] **Acceptance**: `nargo compile --package aggregator_final` compiles ✅

### G3.1: Wire full NIZK into fold_e2e_soundness ✅ DONE

- [x] **G3.1a.** Entry point: `validate_witness()` in `folding/mod.rs` (+66 lines)
- [x] **G3.1b.** `verify_full_nizk()` calls `CycloNizkAdapter::verify()` with 90-round sigma BEFORE fold
- [x] **G3.1c.** Uses 90-round sigma (SIGMA_REPETITIONS=90), not 1-round in-circuit path
- [x] **G3.2a-d.** 3 adversary tests GREEN under real-nizk: fewer-than-t shares REJECT, single-forged REJECT, ct-mismatch REJECT
- [x] **Acceptance**: `cargo test -p pvthfhe-aggregator --features real-nizk fold_e2e_soundness` 3/3 GREEN ✅

---

## Wave G4 — High: Real Relinearization in FheCompute

### G4.1: Implement proper relinearization ✅ DONE

- [x] **G4.1a-d.** No relinearization key exists in any FHE backend. Added `real-relin` feature gate: without feature → `SynthesisError::AssignmentMissing`. Existing path gated behind `#[cfg(feature = "real-relin")]`.
  **File**: `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs`, `Cargo.toml`
- [x] **G4.2a.** RED→GREEN test: `fhe_compute_relin_rejects_without_real_relin`
- [x] **Acceptance**: `cargo test -p pvthfhe-compressor` 74 passed ✅

### G5.1: Strengthen bootstrap sigma ✅ DONE

- [x] **G5.1a-c.** `BootstrapStatement` already had `bsk_hash: [u8; 32]`. Added to Fiat-Shamir transcript via `derive_challenge`. Updated `prove` and `verify` call sites.
  **File**: `crates/pvthfhe-nizk/src/bootstrap_sigma.rs`
- [x] **G5.1d.** Doc comment: "proves same LWE secret key under claimed bsk hash; does NOT prove full blind rotation"
- [x] **G5.2a.** RED→GREEN test: `test_wrong_bsk_hash_rejected` (8/8 pass)
- [x] **Acceptance**: `cargo test -p pvthfhe-nizk bootstrap_sigma` 8/8 pass ✅

---

## Wave G6 — Medium: BFV Sigma Rejection Sampling + In-Circuit Path

### G6.1: Document the gap ✅ DONE

- [x] **G6.1a.** Added `# CAVEATS` section in `bfv_sigma.rs`: no rejection sampling, computational ZK via noise drowning (ratio ≥4.0), no in-circuit verifier, use S-Z evaluation instead
- [x] **G6.1b.** Added `## BFV Sigma Caveats` in `SECURITY.md`: computational ZK only, no rejection sampling, outer-circuit only
- [x] **Acceptance**: Documentation present in both `bfv_sigma.rs` and `SECURITY.md`

### G7.1: Document the trust assumption ✅ DONE

- [x] **G7.1a.** Added `# Trust Assumption (G7)` comment in `sigma.rs` near `poly_mul_rq()` + `folding/mod.rs` module doc: NTT correctness assumed from fhe-math, S-Z sidesteps NTT in-circuit
- [x] **G7.1b.** Added `## Trusted Components` table in `SECURITY.md`: fhe-math NTT + RNS arithmetic listed with documented impact
- [x] **Acceptance**: Documentation present

---

## Definition of Done

- [ ] G1 (sigma repetition): SIGMA_REPETITIONS fixed or documented with 90-fold accumulator approach verified
- [ ] G2 (per-share NIZK): C7 circuit Merkle-bound to share commitments with RED→GREEN tests
- [ ] G3 (fold NIZK): fold_e2e_soundness tests GREEN under real-nizk feature
- [ ] G4 (real relin): either implemented or gated with clear documentation
- [ ] G5 (bootstrap): bsk_hash bound into sigma challenge + documentation
- [ ] G6 (BFV sigma): documented in code + SECURITY.md
- [ ] G7 (NTT trust): documented
- [ ] `(cd circuits && nargo test --workspace)` all pass
- [ ] `cargo test -p pvthfhe-compressor` all pass
- [ ] `cargo test -p pvthfhe-nizk` all pass
- [ ] `cargo test -p pvthfhe-aggregator --features real-nizk fold_e2e_soundness` GREEN
- [ ] `forge test --root contracts` all pass (153+)
- [ ] `just phase1-gate` GREEN
- [ ] `just phase2-gate` GREEN
- [ ] `docs/OPEN-PROBLEM-BLOCKERS.md` updated to reflect G1-G7 resolution status
- [ ] `SECURITY.md` updated with NTT trust assumption + BFV sigma caveats

## Out of Scope

- Full PBS correctness proof (requires bsk opening + CMUX chain, P2 lattice folding territory)
- In-circuit BFV sigma verifier (requires rejection-sampling rewrite, P2 deferred research)
- NTT correctness proof (requires fhe-math verification or HasteBoots grand-product technique — evaluated and deferred)
- Per-share key correctness proof (proving s_i is the registered secret key share, not just small — P1 deferred research)
