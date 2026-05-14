# Plan: P2 M5 — LatticeFold+ Integration with MicroNova

**Plan**: `p2-m5-micronova-integration`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P2-M1 through P2-M4, P3-M1 (FoldVerifierStepCircuit)
**Goal**: Connect the completed LatticeFold+ folding pipeline (P2-M1 through P2-M4) to the MicroNova compression pipeline (P3-M1), producing an end-to-end folded-then-compressed proof.

---

## Context

### What exists

- **P2-M1**: CycloCCSAdapter — verifies ring equation
- **P2-M3**: Norm enforcement — bounds extracted witness
- **P2-M4**: Com_A lattice commitment — replaces SHA-256
- **P3-M1**: FoldVerifierStepCircuit — verifies folding steps in Nova

### What M5 connects

M5 composes the LatticeFold+ accumulator with the FoldVerifierStepCircuit so that:

1. The LatticeFold+ folding produces an accumulator commitment (Com_A)
2. The FoldVerifierStepCircuit verifies that the accumulator was correctly folded
3. The MicroNova compression pipeline reduces the tree to a constant-size proof

---

## Implementation

### P2-M5.1 — Folding-to-Verifier bridge

**File**: `crates/pvthfhe-compressor/src/sonobe/latticefold_adapter.rs` (new)

Convert LatticeFold+ accumulator state to FoldVerifierStepCircuit external inputs:

```rust
pub fn latticefold_to_fold_verifier_inputs(
    left_accumulator: &[u8],
    right_accumulator: &[u8],
    expected_parent: &[u8],
) -> ExternalInputs3<Fr> { ... }
```

### P2-M5.2 — End-to-end integration test

**File**: `crates/pvthfhe-compressor/tests/latticefold_micronova_integration.rs` (new)

| Test | Description |
|------|-------------|
| `latticefold_accumulate_then_verify` | Fold 2 leaves, verify with FoldVerifier |
| `latticefold_4_leaf_tree_to_root` | 4-leaf tree, fold all levels, verify root |

### P2-M5.3 — Documentation

- Update `p2-latticefold-target.md` — mark M5 complete
- Update `p3-micronova-target.md` — note P2 integration is ready
- Update paper: Track B status from "aspirational" to "M5 integration working"

## Acceptance Criteria

- [ ] LatticeFold+ accumulator feeds into FoldVerifierStepCircuit
- [ ] 2 integration tests pass
- [ ] Demo ACCEPT (Track A unchanged)

## Estimated Effort

~1-2 weeks. Integration engineering, not novel research.
