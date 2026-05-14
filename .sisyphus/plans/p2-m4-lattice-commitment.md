# Plan: P2 M4 — Lattice Commitment (Com_A) Replacement

**Plan**: `p2-m4-lattice-commitment`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P2-M1 (CycloCCSAdapter), P2-M3 (norm enforcement)
**Goal**: Replace the SHA-256 accumulator in LatticeFold+ with a linear lattice commitment `Com_A(w) = A·w mod q_commit`, enabling native Ajtai commitment folding.

---

## Context

### Current state: SHA-256 accumulator

The CycloFoldStepCircuit hashes accumulator state via SHA-256. This is collision-resistant but loses the algebraic structure of the Cyclo commitment — the folded commitment cannot be verified against the original Ajtai parameters.

### Target state: Com_A lattice commitment

`Com_A(w) = A·w mod q_commit` where A is an Ajtai matrix (random over R_{q_commit}), w is the witness vector. This commitment is:
- **Binding**: Under M-SIS, it's hard to find two distinct w, w' with A·w = A·w'
- **Linear**: `A·(w₁ + w₂) = A·w₁ + A·w₂`, enabling native folding
- **Short**: The committed witness has bounded norm (enforced by P2-M3)

---

## Implementation

### P2-M4.1 — Ajtai matrix generation

**File**: `crates/pvthfhe-aggregator/src/folding/ajtai.rs` (new)

Generate a deterministic Ajtai matrix from epoch hash:

```rust
use ark_ff::PrimeField;
use sha2::{Sha256, Digest};

/// Ajtai commitment matrix: A ∈ R^{m×n} over the Cyclo ring.
pub struct AjtaiMatrix<F: PrimeField> {
    pub rows: usize,  // m = 1 (single commitment)
    pub cols: usize,  // n = number of witness elements
    pub entries: Vec<Vec<F>>, // m×n matrix
}

impl<F: PrimeField> AjtaiMatrix<F> {
    /// Generate deterministic Ajtai matrix from epoch hash.
    pub fn from_epoch(epoch: &[u8; 32], rows: usize, cols: usize) -> Self { ... }
    
    /// Commit to a witness: y = A·w mod q.
    pub fn commit(&self, w: &[F]) -> Vec<F> { ... }
}
```

### P2-M4.2 — Replace SHA-256 with Com_A in folding

**File**: `crates/pvthfhe-aggregator/src/folding/mod.rs`

Add optional `ComA` accumulator path alongside SHA-256:

```rust
/// Accumulator mode: SHA-256 (Track A) or Com_A (Track B).
pub enum AccumulatorMode {
    Sha256,
    ComA(AjtaiMatrix<Fr>),
}

impl AccumulatorMode {
    pub fn accumulate(&self, state: &[u8], witness: &[Fr]) -> Vec<u8> {
        match self {
            Self::Sha256 => { /* existing hash */ }
            Self::ComA(mat) => {
                let comm = mat.commit(witness);
                // serialize commitment to bytes
            }
        }
    }
}
```

### P2-M4.3 — Tests

**File**: `crates/pvthfhe-aggregator/tests/ajtai_commitment.rs` (new)

| Test | Description |
|------|-------------|
| `ajtai_commit_is_deterministic` | Same epoch → same matrix |
| `ajtai_commit_differs_for_different_epoch` | Different epoch → different matrix |
| `ajtai_commit_is_binding_toy` | Different witnesses → different commitments (for small test) |
| `ajtai_commitment_folding_is_homomorphic` | Com_A(w₁ + w₂) = Com_A(w₁) + Com_A(w₂) |

### P2-M4.4 — Documentation

- Update `docs/security-proofs/p2/T4.md` — reference Com_A implementation
- Update `p2-latticefold-target.md` — mark M4 complete

## Acceptance Criteria

- [ ] AjtaiMatrix deterministically generated from epoch
- [ ] Com_A commit produces linear, binding commitment
- [ ] SHA-256 path preserved (Track A fallback)
- [ ] 4 RED tests pass
- [ ] Demo ACCEPT

## Estimated Effort

~1-2 weeks. Matrix generation from XOF requires careful constant derivation.
