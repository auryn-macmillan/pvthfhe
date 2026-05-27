# Plan: Round 5 Deep Audit Remediation

**Plan**: `round5-audit-remediation`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-14
**Audits**: Track B pipeline gaps, paper-code-docs consistency, demo/benchmark integration, bugs/edge cases

---

## Findings Summary

### Critical (2)

| ID | Finding | Source |
|----|---------|--------|
| **F1** | Response witnesses (z_s, z_e) are zero placeholders in Track B norm enforcement — norm bypassed | Bugs |
| **F2** | `expect()` panics in production Track B folding path (`mod.rs:145`) | Bugs |

### High (4)

| ID | Finding | Source |
|----|---------|--------|
| **F3** | CycloFoldStepCircuit ring verification is a STUB — counter, not real R1CS | Track B |
| **F4** | "Straight-line extractor" claimed in 6 files, but actual proof is rewinding | Docs |
| **F5** | Lemma 9 self-contradiction: §0 says accepted assumption, §3 says conjecture | Docs |
| **F6** | Most Track B components (FoldVerifierStepCircuit, CompressionTree, AjtaiMatrix) are TEST-ONLY, not wired | Track B |

### Medium (7)

| ID | Finding | Source |
|----|---------|--------|
| **F7** | 7 of 13 e2e phases silently pass with no work (markers only) | Demo |
| **F8** | C7 circuits (Merkle, Nova) never run — env vars not set by Justfile | Demo |
| **F9** | Bench scripts don't use Track B flags or pipeline-extra-checks | Demo |
| **F10** | Paper P1-T3 scope stale (narrow SLAP-core) — actual scope expanded | Docs |
| **F11** | Paper "T2/T3 tension" note obsolete — no witness openings exist | Docs |
| **F12** | ARCHITECTURE.md on-chain description wrong (Nova ≠ ecrecover) | Docs |
| **F13** | `secret_share_poly` populated from raw bytes, not guaranteed ternary | Bugs |

### Low (5)

| ID | Finding | Source |
|----|---------|--------|
| **F14** | `compute_ajtai_commitment_for_track` doc falsely claims AjtaiMatrix is used | Track B |
| **F15** | i128→i64 truncation in fhers.rs:1387,1438 (safe for demo, unsafe for larger n) | Bugs |
| **F16** | claims-table footnote calls T2 a "skeleton" but T2 is proved | Docs |
| **F17** | SECURITY.md says T2 "deferred" — stale; T2 was rewritten | Docs |
| **F18** | ARCHITECTURE.md "Track B default" misleading — code Track B ≠ architectural Track B | Docs |

---

## Remediation Batches

### Batch A: Critical Fixes (F1-F2)

| ID | Task | Files |
|----|------|-------|
| A.1 | Replace zero placeholders with actual z_s, z_e from NIZK proof or compute from challenge | `full_pipeline.rs:368-369` |
| A.2 | Replace `.expect()` with `?` error propagation | `mod.rs:145` |
| A.3 | Replace `.expect()` in Ajtai commit path | `full_pipeline.rs:881,894` |
| A.4 | RED test: verify norm enforcement rejects tampered z_s/z_e | `full_pipeline tests` |

### Batch B: Track B Wiring (F3, F6, F14)

| ID | Task | Files |
|----|------|-------|
| B.1 | Wire `verify_ring_equation_r1cs` into CycloFoldStepCircuit::generate_step_constraints | `mod.rs:174-209` |
| B.2 | Wire `CompressionTree::build` as optional C7 compression path | `full_pipeline.rs`, `compressor_glue.rs` |
| B.3 | Remove or mark AjtaiMatrix as "experimental, not yet integrated" | `ajtai.rs`, `full_pipeline.rs:703-705` |
| B.4 | Fix `compute_ajtai_commitment_for_track` doc comment | `full_pipeline.rs:817-828` |

### Batch C: Demo + Benchmark Fixes (F7-F9)

| ID | Task | Files |
|----|------|-------|
| C.1 | Wire `PVTHFHE_RUN_C7_SONOBE=1` into `demo-e2e` Justfile recipe or create `demo-e2e-c7` variant | `Justfile` |
| C.2 | Remove or wire silent-pass markers (`noir_decrypt_share`, `noir_nova_wrap`, `onchain_verify`) | `pvthfhe_e2e.rs` |
| C.3 | Add `PVTHFHE_TRACK=B` and `--features pipeline-extra-checks` to bench scripts | `bench/i1_one_vs_two_track.py` |
| C.4 | Verify `just bench-comparison 10 4 1` works with C7 and Merkle timing | Manual run |

### Batch D: Paper + Docs Sync (F4-F5, F10-F12, F16-F18)

| ID | Task | Files |
|----|------|-------|
| D.1 | Fix Lemma 9 self-contradiction — align §3 with §0 (accepted assumption) | `lemma9.md:36` |
| D.2 | Replace "straight-line extractor" with "rewinding extractor" | `paper/main.tex`, `claims-table.md`, `T2.md:5`, `obligations.md` |
| D.3 | Update paper P1-T3 scope (expanded to serialized format) | `paper/main.tex:149-151` |
| D.4 | Remove obsolete "T2/T3 tension" note | `paper/main.tex:154` |
| D.5 | Fix ARCHITECTURE.md on-chain description (ecrecover, not Nova) | `ARCHITECTURE.md:5` |
| D.6 | Fix ARCHITECTURE.md Track B description (code Track B ≠ architectural Track B) | `ARCHITECTURE.md:193-196` |
| D.7 | Update claims-table footnote — T2 is proved, not a skeleton | `claims-table.md:37-38` |
| D.8 | Update SECURITY.md T2 status ("deferred" → "PROVED") | `SECURITY.md:48` |
| D.9 | Update `interfold-threat-model.md:77` — T2 not a skeleton | `interfold-threat-model.md:77` |

### Batch E: Edge Cases + Code Quality (F13, F15)

| ID | Task | Files |
|----|------|-------|
| E.1 | Audit `secret_share_poly` encoding; add ternary check ‖s‖_∞ ≤ 1 | `demo_nizk.rs`, `full_pipeline.rs` |
| E.2 | Replace `as i64` with `i64::try_from` or document safe bounds | `fhers.rs:1387,1438` |
| E.3 | Add Track parsing tests for `"a"`, `"b"`, `""` | `full_pipeline.rs tests` |

---

## Verification

### Pre-commit checks:

```bash
cargo build --workspace
cargo test -p pvthfhe-aggregator -p pvthfhe-compressor -p pvthfhe-cli -p pvthfhe-pvss
```

### End-of-plan checks:

```bash
just demo-e2e              # Track B default → ACCEPT
PVTHFHE_TRACK=A just demo-e2e  # Track A → ACCEPT
just demo-e2e 32 14        # Large n → ACCEPT
just bench-comparison 10 4 1  # Benchmark runs
```

### Cross-reference:

- [ ] `paper/main.tex` → no "straight-line extractor" for P1-T2
- [ ] `lemma9.md` → internally consistent (§0 and §3 agree)
- [ ] `ARCHITECTURE.md` → on-chain description matches paper
- [ ] `SECURITY.md` → T2 status not "deferred"

---

## Open / Deferred

| Item | Reason |
|------|--------|
| Full LatticeFold+ implementation (P2) | Multi-week research project |
| MicroNova heterogeneous circuits (P3-M2) | Deferred to P3-M2 plan |
| On-chain UltraHonk deployment (P3-M3) | Requires EVM infrastructure |
| C7 coefficient-wise check | Poly coefficient ordering blocked |

## Execution Order

Batch A (critical) → Batch B (wiring) → Batch C (demo) → Batch D (docs) → Batch E (edge cases)

Batches A and D can run in parallel (different files). Batches B + C after A completes. Batch E after all others.
