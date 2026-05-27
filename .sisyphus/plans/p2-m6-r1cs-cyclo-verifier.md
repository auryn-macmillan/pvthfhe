# Plan: P2 M6 — R1CS Constraint Encoding for Cyclo Ring Equation

**Plan**: `p2-m6-r1cs-cyclo-verifier`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P2-M1 (RingElement, CycloVerifierCCS), P2-M3 (norm enforcement)
**Goal**: Convert the native CycloVerifierCCS and RingElement to R1CS constraints (FpVar<F>), enabling real ring equation verification inside CycloFoldStepCircuit's `generate_step_constraints`.

---

## Context

### Current state

`RingElement<F>` and `CycloVerifierCCS` work natively (off-circuit). The CycloFoldStepCircuit uses Track A hash-then-fold. M6 replaces hash-then-fold with actual ring equation `c·z_s + z_e - t - c·d ≡ 0` verification IN R1CS constraints.

### What needs R1CS

For each step, the Nova circuit must verify the ring equation in constraints:

$$\forall k \in [0, N\!-\!1]: \quad c \cdot z_s[k] + z_e[k] - t[k] - c \cdot d[k] \equiv 0 \pmod{q\_commit}$$

Where all operations are over Bn254::Fr (the Nova field), and the challenge $c \in \{-1, 0, 1\}$ is a ternary constant.

For ternary $c$, no multiplication is needed:
- $c = 1$: verify $z_s[k] + z_e[k] - t[k] - d[k] = 0$ (4 additions per coefficient)
- $c = -1$: verify $-z_s[k] + z_e[k] - t[k] + d[k] = 0$ (4 additions)
- $c = 0$: verify $z_e[k] - t[k] = 0$ (2 additions)

For $N = 256$: at most $4 \times 256 = 1024$ R1CS additions per step (additions are free in R1CS). No multiplications needed.

---

## Implementation

### P2-M6.1 — R1CS RingElementVar

**File**: `crates/pvthfhe-compressor/src/nova/ring_element_var.rs` (new)

```rust
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// R1CS variable wrapper for ring elements over X^N + 1.
pub struct RingElementVar<F: PrimeField> {
    pub coeffs: Vec<FpVar<F>>,
}
```

### P2-M6.2 — R1CS CycloVerifier

**File**: `crates/pvthfhe-compressor/src/nova/cyclo_verifier.rs` (extend)

Add `verify_constraints` that verifies the ring equation in R1CS without multiplications (since c is ternary):

```rust
pub fn verify_ring_equation_constraints<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    challenge: F, // ternary: -1, 0, or 1 as Fr
    z_s: &RingElementVar<F>,
    z_e: &RingElementVar<F>,
    t: &RingElementVar<F>,
    d: &RingElementVar<F>,
) -> Result<(), SynthesisError>
```

### P2-M6.3 — Wire into CycloFoldStepCircuit

Replace hash-then-fold with constraint verification in `generate_step_constraints`. The state becomes `[verified_count, ring_passed_count, fold_count, epoch_hash]`.

### P2-M6.4 — Tests

| Test | Description |
|------|-------------|
| `r1cs_ring_equation_passes_for_honest` | Honest witness → R1CS verifier accepts |
| `r1cs_ring_equation_rejects_wrong_z_s` | Tampered z_s → constraint failure |
| `r1cs_ternary_challenge_cases` | All three challenge values (-1, 0, 1) verify |
| `r1cs_cyclo_fold_step_roundtrip` | Full NovaCompressor prove/verify with R1CS |

### P2-M6.5 — Documentation

- Update `docs/security-proofs/p2/T1.md` — note R1CS encoding
- Update `p2-latticefold-target.md` — add M6 milestone

## Acceptance Criteria

- [ ] RingElementVar<F> with coefficient-wise addition and negation
- [ ] CycloVerifierCCS::verify_constraints works for ternary c
- [ ] CycloFoldStepCircuit uses R1CS ring equation (not hash)
- [ ] 4 RED tests pass
- [ ] Demo ACCEPT (Track A unchanged)
- [ ] Existing Cyclo CCS adapter tests pass

## Non-Goals

- Full polynomial multiplication in R1CS (not needed for ternary c)
- Replacing Track A demo (Track A and Track B coexist)

## Estimated Effort

~1 week. The ternary challenge makes this much simpler than general R1CS ring arithmetic — no multiplications needed.
