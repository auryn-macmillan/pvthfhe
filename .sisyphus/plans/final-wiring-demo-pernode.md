# Plan: Final Wiring — demo-e2e + per-node Integration

**Plan**: `final-wiring-demo-pernode`
**Status**: COMPLETE
**Created**: 2026-05-16
**Goal**: Fully wire all p2-m4 through A.4 changes into demo-e2e and per-node binaries. Close the p2-m6 ring equation gap (ext.2 not populated from pipeline).

---

## Current Gaps

| Change | Gap |
|--------|-----|
| p2-m6 | Compressor verifier checks `fold_count == verification_count`, but pipeline never sets `ext.2` from native ring result. Counter is a no-op. |
| p2-m4 (AjtaiMatrix) | ✅ Wired in demo-e2e. NOT in per-node (per-node uses Cyclo). |
| p2-m5+p3-m2 (bridge+comp) | ✅ Wired behind `PVTHFHE_C7_TREE=1`. NOT in per-node. |
| A.4 (C7 tree) | ✅ Wired behind `PVTHFHE_C7_TREE=1`. NOT in per-node. |

---

## Tasks

### W1 — Close p2-m6 ring equation gap (~1 day)

| Task | Files |
|------|-------|
| W1.1 | In `build_ccs_instances_from_dealers`, add `ring_verified: bool` field to CCS instance, set from native check result | `full_pipeline.rs:914-960` |
| W1.2 | Encode `ring_verified` as `ext.2` in the fold external inputs (ExternalInputs3 → carry Fr::one() for pass, Fr::zero() for fail) | `full_pipeline.rs:470-478` |
| W1.3 | Verify: tampered witness → ring equation fails → compressor verifier rejects (RED test) | Test |

### W2 — Wire AjtaiMatrix into per-node (~0.5 day)

| Task | Files |
|------|-------|
| W2.1 | Add `compute_ajtai_commitment_for_track` call to per-node binary (currently uses Cyclo only) | `per_node.rs:128-156` |
| W2.2 | Add `PVTHFHE_TRACK=B` support to per-node (currently hardcoded to Track::A) | `per_node.rs:48-52` |

### W3 — Wire C7 tree + compression into per-node (~0.5 day)

| Task | Files |
|------|-------|
| W3.1 | Add `PVTHFHE_C7_TREE=1` support to per-node C7 timing path | `per_node.rs:170-190` |
| W3.2 | Add `MicronovaCompressor` timing measurement to per-aggregator | `per_aggregator.rs:128-148` |

### W4 — Make C7 tree default in demo-e2e (~0.5 day)

| Task | Files |
|------|-------|
| W4.1 | Remove `PVTHFHE_C7_TREE` env var gate — make tree folding the DEFAULT C7 path | `full_pipeline.rs:1477-1491` |
| W4.2 | Run benchmarks at n=32,64,128 to verify no regression | Manual |

---

## Acceptance Criteria

- [ ] p2-m6: tampered witness → ring equation fail → demo REJECT
- [ ] per-node uses AjtaiMatrix for Track B
- [x] per-node supports C7 tree folding
- [x] C7 tree folding is default in demo-e2e (no env var needed)
- [ ] Demo ACCEPT — all n=16,32,64,128
- [ ] All existing tests pass

## Estimated Effort

~2-3 days. W1: 1 day. W2+W3: 1 day. W4: 0.5 day.
