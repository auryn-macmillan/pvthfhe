# Plan: P2 M3 — Norm Enforcement for Cyclo Witness Validation

**Plan**: `p2-m3-norm-enforcement`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P2-M1 (CycloCCSAdapter)
**Goal**: Add coefficient-bound checks (`||w||_∞ ≤ B`) to `validate_witness` in the LatticeFold+ folding harness, ensuring that only short witnesses enter the folding accumulator.

---

## Context

### Prerequisite: P2-M1 CCS adapter

The `CycloVerifierCCS` verifies the ring equation `c·z_s + z_e - t - c·d ≡ 0`. M3 adds norm enforcement: the witness must also be **short** (`||w||_∞ ≤ B`), preventing an adversary from satisfying the equation with arbitrarily large witnesses.

### Why norm enforcement matters

Lattice-based proofs rely on witness shortness for both soundness and zero-knowledge:
- **Soundness**: M-SIS hardness requires short solutions. An unbounded witness can trivially satisfy any linear equation.
- **ZK**: The sigma protocol hides the witness behind random masks; if the extracted witness has large norm, it leaks information via the response bound.

### Current state

The `validate_witness` function in `crates/pvthfhe-aggregator/src/folding/mod.rs` does basic structural validation (presence of fields, format checks) but does not enforce coefficient-level norm bounds.

---

## Implementation

### P2-M3.1 — Define norm bounds

- Parameter: `B = 1024` (initial witness bound from P1 parameters)
- Response bound: `B_z = 2·B + 1 = 2049` (masked response norm)
- Error bound: `B_e = 16` (6σ error bound)

### P2-M3.2 — Implement norm enforcement

**File**: `crates/pvthfhe-aggregator/src/folding/norm.rs` (new)

```rust
use crate::folding::ring_element::RingElement;
use ark_ff::PrimeField;

/// Enforce that a ring element's infinity norm is ≤ bound.
/// Returns Err if any coefficient exceeds the bound.
pub fn enforce_norm_inf<F: PrimeField>(
    element: &RingElement<F>,
    bound: F,
    label: &str,
) -> Result<(), String> {
    let norm = element.norm_inf();
    if norm > bound {
        return Err(format!("{} norm {} exceeds bound {}", label, norm, bound));
    }
    Ok(())
}

/// Validate a Cyclo folding witness:
/// - ‖s‖_∞ ≤ B (secret key)
/// - ‖e‖_∞ ≤ B_e (error)
/// - ‖z_s‖_∞ ≤ B_z (response)
/// - ‖z_e‖_∞ ≤ B_z (response)
pub fn validate_folding_witness<F: PrimeField>(
    s: &RingElement<F>,
    e: &RingElement<F>,
    z_s: &RingElement<F>,
    z_e: &RingElement<F>,
    b: F,
    b_e: F,
    b_z: F,
) -> Result<(), String> {
    enforce_norm_inf(s, b, "s")?;
    enforce_norm_inf(e, b_e, "e")?;
    enforce_norm_inf(z_s, b_z, "z_s")?;
    enforce_norm_inf(z_e, b_z, "z_e")?;
    Ok(())
}
```

### P2-M3.3 — Tests

**File**: `crates/pvthfhe-aggregator/tests/cyclo_norm_enforcement.rs` (new)

| Test | Description |
|------|-------------|
| `norm_enforcement_accepts_short_witness` | ‖w‖ = 5, bound = 1024 → passes |
| `norm_enforcement_rejects_large_witness` | ‖w‖ = 9999, bound = 1024 → fails |
| `norm_enforcement_boundary` | ‖w‖ = 1024, bound = 1024 → passes |
| `norm_enforcement_rejects_large_error` | ‖e‖ = 100, bound = 16 → fails |

### P2-M3.4 — Documentation

- Update `docs/security-proofs/p2/T1.md` — note norm enforcement
- Update `p2-latticefold-target.md` — mark M3 complete

## Acceptance Criteria

- [ ] `enforce_norm_inf()` rejects elements exceeding bound
- [ ] `validate_folding_witness()` checks all 4 components
- [ ] 4 RED tests pass
- [ ] Existing aggregator tests pass
- [ ] Demo ACCEPT

## Estimated Effort

~1 day. The RingElement already has `norm_inf()`. This is a thin validation layer.
