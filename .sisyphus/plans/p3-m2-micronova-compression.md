# Plan: P3 M2 — MicroNova Recursive Compression

**Plan**: `p3-m2-micronova-compression`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P3-M1 (FoldVerifierStepCircuit), P2-M1 (CycloCCSAdapter)
**Goal**: Implement recursive compression that reduces a depth-d LatticeFold+ tree to a constant-size MicroNova proof.

---

## Context

### Current state

FoldVerifierStepCircuit verifies one folding step. M2 stacks these verifications recursively: the output of verifying one layer becomes the input to verifying the next layer up.

### Target

A `CompressionTree` that builds a Merkle tree of folding verifications, with each internal node proving that its two children correctly fold.

---

## Implementation

### P3-M2.1 — CompressionTree

**File**: `crates/pvthfhe-compressor/src/micronova/tree.rs` (new)

```rust
pub struct CompressionTree<F: PrimeField> {
    pub leaves: Vec<AccumulatorState>,
    pub proofs: Vec<CompressedProof>,  // one per internal node
    pub root_proof: CompressedProof,
}

impl<F: PrimeField> CompressionTree<F> {
    /// Build from leaf accumulators, compress bottom-up.
    pub fn build(leaves: &[AccumulatorState]) -> Result<Self, CompressorError> { ... }
}
```

### P3-M2.2 — Tests

**File**: `crates/pvthfhe-compressor/tests/micronova_compression.rs` (new)

| Test | Description |
|------|-------------|
| `compression_2_leaf` | 2 leaves → 1 root proof |
| `compression_4_leaf` | 4 leaves → 2 internal + 1 root |
| `compression_8_leaf` | 8 leaves → full tree |
| `compression_proofs_are_constant_size` | Root proof size is O(1) regardless of tree depth |

### P3-M2.3 — Documentation

- Update `p3-micronova-target.md` — mark M2 complete

## Acceptance Criteria

- [ ] Compression tree builds correctly for 2, 4, 8 leaves
- [ ] Root proof size is constant (O(1))
- [ ] 4 tests pass
- [ ] Demo ACCEPT

## Estimated Effort

~2-3 weeks. Recursive proof composition requires careful handling of Nova IVC state across tree levels.
