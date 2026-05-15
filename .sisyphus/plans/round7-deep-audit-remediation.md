# Plan: Round 7 — Deep Audit Remediation (MicroNova + C7 + Pipeline + Docs)

**Plan**: `round7-deep-audit-remediation`
**Status**: DRAFT
**Created**: 2026-05-14
**Audits**: MicroNova+Nova interaction, Track B+observer+compressor, C7+Poseidon R1CS, paper/docs consistency

---

## Findings Summary

### Critical (2)

| ID | Finding | Source |
|----|---------|--------|
| **F1** | Verifier key omits per-variant circuit hashes — no step-variant soundness check in MicroNova | MicroNova |
| **F2** | In-circuit Merkle ordering incompatible with native tree — only works for leaf_index=0 | C7 |

### High (6)

| ID | Finding | Source |
|----|---------|--------|
| **F3** | `merkle_leaf_index` dead witness — no constraint binding to coefficient index | C7 |
| **F4** | `PVTHFHE_COMPRESSOR=micronova` is dead code — family created but never wired | MicroNova |
| **F5** | Paper §Track A falsely claims "all theorems PROVED" (P2-A-T2 is PENDING, P2-A-T5 PARTIAL) | Docs |
| **F6** | `T3.md` self-contradiction — theorem statement (l.17) says "does NOT claim" but implementation status says PROVED | Docs |
| **F7** | ARCHITECTURE.md Track B naming collision (active default vs aspirational target) | Docs |
| **F8** | `SECURITY.md` C7 status stale — says "Poseidon placeholder" but Phase B real Poseidon is complete | Docs |

### Medium (7)

| ID | Finding | Source |
|----|---------|--------|
| **F9** | Nova preprocessor compiles only one circuit variant (works by accident) | MicroNova |
| **F10** | No runtime state_len consistency check in HeterogeneousStepCircuit | MicroNova |
| **F11** | `setup_threshold` O(n²) scaling explains n≥150 timeout | Pipeline |
| **F12** | `README.md` C7 status contradicts `claims-table.md` | Docs |
| **F13** | 4 plans still DRAFT but implementation done | Docs |
| **F14** | Constraint count documentation overestimated | C7 |
| **F15** | `p1-t2-joint-extractor.md` cross-reference says "straight-line extractor" | Docs |

### Low (5)

| ID | Finding | Source |
|----|---------|--------|
| **F16** | Compressor ivc_steps semantially misleading | Pipeline |
| **F17** | Observer flags never reset (no re-use scenario exists) | Pipeline |
| **F18** | Depth calculation correct but over-provisioned (moot since path dead) | MicroNova |
| **F19** | SECURITY.md P3 mention stale (MicroNova now available) | Docs |
| **F20** | Paper doesn't mention MicroNova heterogeneous IVC or Track B default | Docs |
| **F21** | Per-instance nizk timing still captured (just not printed) | Pipeline |

---

## Remediation Batches

### Batch A: Critical Fixes (F1-F3)

| ID | Task | Files |
|----|------|-------|
| A.1 | Add per-step circuit variant validation to `MicroNovaCompressor::verify_tree` | `micronova/compressor.rs:87-98` |
| A.2 | Add `leaf_index` constraint binding to `generate_step_constraints` | `c7_merkle_circuit.rs:209-238` |
| A.3 | Fix `verify_merkle_path` to use position-aware ordering (match native) | `c7_merkle_circuit.rs:129-162` |
| A.4 | RED test: native Merkle proof → R1CS circuit passes | `c7_merkle_circuit` tests |

### Batch B: Dead Code + Pipeline Fixes (F4, F16)

| ID | Task | Files |
|----|------|-------|
| B.1 | Wire `PVTHFHE_COMPRESSOR=micronova` to actually use HeterogeneousStepCircuit | `full_pipeline.rs:441-455` |
| B.2 | Add compressor comment explaining ivc_steps semantic | `full_pipeline.rs:455`, `compressor_glue.rs:94-98` |

### Batch C: Paper + Docs Consistency (F5-F8, F12-F13, F15, F19-F20)

| ID | Task | Files |
|----|------|-------|
| C.1 | Fix paper line 175 — replace "all theorems PROVED" with actual status per theorem | `paper/main.tex:175-177` |
| C.2 | Fix T3.md self-contradiction — reconcile theorem statement with implementation status | `T3.md:17` |
| C.3 | Resolve ARCHITECTURE.md Track B naming collision | `ARCHITECTURE.md:170-176,188-198` |
| C.4 | Update SECURITY.md C7 Poseidon status (Phase B complete) | `SECURITY.md:56` |
| C.5 | Update SECURITY.md P3 MicroNova mention | `SECURITY.md:50` |
| C.6 | Fix README.md C7 status | `README.md:31` |
| C.7 | Update SECURITY.md R6 hardening note | `SECURITY.md:62-64` |
| C.8 | Mark 4 DRAFT plans COMPLETE + tick checkboxes | 4 plan files |
| C.9 | Fix p1-t2-joint-extractor cross-reference | `p1-t2-joint-extractor.md:45` |
| C.10 | Add MicroNova mention to paper | `paper/main.tex §P2` |

### Batch D: Infrastructure Hardening (F9-F10, F14)

| ID | Task | Files |
|----|------|-------|
| D.1 | Document preprocessor variant limitation | `heterogeneous.rs:10` |
| D.2 | Add `debug_assert_eq!` state_len check in generate_step_constraints | `heterogeneous.rs:140` |
| D.3 | Fix constraint count docs | `poseidon_gadget.rs:10` |

### Batch E: Performance + Testing (F11)

| ID | Task | Files |
|----|------|-------|
| E.1 | Add visibility logging to setup_threshold (RUST_LOG=debug) | `fhers.rs:331` |
| E.2 | Document performance ceiling at n≈128 | `ARCHITECTURE.md`, `README.md` |

---

## Verification

```bash
cargo build --workspace
just demo-e2e              # Track B default → ACCEPT
cargo test -p pvthfhe-compressor --test micronova_heterogeneous
```

## Execution Order

Batch A (critical) → Batch B (dead code) → Batch C (docs, parallel with D+E) → D+E
