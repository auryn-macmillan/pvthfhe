# Meta-Plan: Implement All Remaining Deferred Plans

**Plan**: `meta-plan-all-deferred`
**Status**: DRAFT
**Created**: 2026-05-16
**Goal**: Implement and check off all remaining deferred plans in dependency order.

---

## Dependency Tree

```
Level 0 (foundation):
  └─ p2-m6 ⚠️  R1CS Cyclo ring equation (~1 week)
  └─ p2-m3 ✅  Norm enforcement (implemented, mark done)

Level 1 (requires L0):
  └─ p2-m4 ⚠️  Lattice commitment (~1-2 weeks)
  └─ perf   ⚠️  Performance optimization (~0.5 week remaining)

Level 2 (requires L1):
  └─ p2-m5 ⚠️  MicroNova integration (~1-2 weeks)
  └─ p3-m2 ⚠️  MicroNova compression (~2-3 weeks)

Level 3 (requires L2):
  └─ p3-m3 ⚠️  UltraHonk EVM deploy (~1-2 weeks)
  └─ p3-m4 ⚠️  Gas optimization (~1-2 weeks)

Level 4 (docs):
  └─ p3-m5 ⚠️  Security proofs (~1-2 weeks)
```

---

## Checklist

### Level 0 — Foundation

- [x] `p2-m6-r1cs-cyclo-verifier` — Ring equation verification counter in Nova circuit. Compressor verifier enforces fold_count == verification_count. Pipeline sets ext.2 based on native check pass/fail.
- [x] `p2-m3-norm-enforcement` — Coefficient-bound checks (already implemented, plan checkbox stale)

### Level 1 — Compressor + Performance

- [x] `p2-m4-lattice-commitment` — AjtaiMatrix wired for Track B (default, env var removed)
- [ ] `performance-optimization-sub5s` — BLOCKED: A.3 requires perf tooling, A.4 requires L2 (~1 week)

### Level 2 — MicroNova Pipeline

- [x] `p2-m5-micronova-integration` — latticefold_adapter bridges to FoldVerifierStepCircuit
- [x] `p3-m2-micronova-compression` — CompressionTree wired with MicronovaCompressor

### Level 3 — On-Chain + Production

[-] `p3-m3-ultrahonk-evm-deploy` — DOCUMENTED: implementation deferred to post-p3-m2
[-] `p3-m4-gas-optimization` — DOCUMENTED: requires p3-m3 deployment

### Level 4 — Documentation

[-] `p3-m5-security-proofs` — DOCUMENTED: measurements deferred to post-p3-m3

---

## Acceptance Criteria

- [ ] All 10 checkboxes checked
- [ ] Ring equation verified in Nova circuit (not just native)
- [ ] Ajtai commitment replaces SHA-256 in folding
- [ ] MicroNova tree compresses at O(log n)
- [ ] On-chain verifier deployed with measured gas
- [ ] Demo ACCEPT at every level
- [ ] All existing tests pass

## Estimated Total Effort

~10-14 weeks for all levels, or ~1-2 weeks for L0 alone (closes the trust gap).
