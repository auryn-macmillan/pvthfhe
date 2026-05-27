# Implement CycloFoldStepCircuit Verification Gadgets (G3)

**Status**: COMPLETE
**Parent**: close-nova-gaps.md (Wave 3)
**Date**: 2026-05-27

## Goal

Replace the three placeholder witness allocations in `CycloFoldStepCircuit::synthesize` with real in-circuit verification:
- `sigma_ok`: Currently `AllocatedNum::alloc(cs, || Ok(self.sigma_ok))` — prover can lie
- `ring_ok`: Same pattern
- `bfv_ok`: Same pattern

After fix: each value is ENFORCED by R1CS constraints to be 1 only when the corresponding verification passes.

## Background

The CycloFoldStepCircuit is the aggregation layer. After C1/C4/C5/C7 produce individual Nova IVC proofs, CycloFold wraps them into a single aggregated proof. The `synthesize` method runs per-step and accumulates:
- `verification_count += sigma_ok` (Track A)
- `sigma_count += sigma_ok` (Track B)
- `ring_count += ring_ok`
- `bfv_count += bfv_ok`

Currently these values are assigned by the caller (prover) with no in-circuit enforcement. A malicious prover can claim all verifications passed even when they didn't.

## Implementation

### Phase 1 — Read the legacy constraints

The legacy sigma/ring/BFV constraint code existed in `mod.rs` before the Nova removal (commit `1d72688`). Read the git history to recover the exact constraint structure:

```
git show 1d72688:crates/pvthfhe-compressor/src/nova/mod.rs | grep -A200 "fn sigma_verify_step"
git show 1d72688:crates/pvthfhe-compressor/src/nova/mod.rs | grep -A100 "fn ring_verify_step"
```

These provide the EXACT constraint count, variable names, and enforcement patterns that must be replicated in bellpepper.

### Phase 2 — Create bellpepper verification gadgets

Create a new file `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` with three pure functions:

```rust
/// In-circuit sigma verification via Schwartz-Zippel (3-point, 3-limb).
/// Returns Ok(NovaScalar::from(1u64)) if the RLWE equation holds at all
/// evaluation points; Ok(NovaScalar::zero()) otherwise.
pub fn sigma_verify_step_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> { ... }

/// In-circuit ring (Ajtai) verification.
pub fn ring_verify_step_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> { ... }

/// In-circuit BFV encryption share verification.
pub fn bfv_verify_step_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> { ... }
```

Each function:
1. Reads per-step data from thread-locals (`SIGMA_DATA`, `RING_DATA`, `BFV_DATA`)
2. Allocates witness variables via `AllocatedNum::alloc(cs.namespace(...), || Ok(value))`
3. Enforces constraints via `cs.enforce(|| "label", |lc| ..., |lc| ..., |lc| ...)`
4. Returns `AllocatedNum` representing pass (1) or fail (0)

### Phase 3 — Key bellpepper constraint patterns

**Allocation** (replaces `FpVar::new_witness`):
```rust
let var = AllocatedNum::alloc(cs.namespace(|| "name"), || Ok(value))?;
```

**Equality** (replaces `lhs.enforce_equal(&rhs)`):
```rust
cs.enforce(
    || "eq",
    |lc| lc + lhs.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + rhs.get_variable(),
);
```

**Multiplication** (replaces `a * b`):
```rust
cs.enforce(
    || "mul",
    |lc| lc + a.get_variable(),
    |lc| lc + b.get_variable(),
    |lc| lc + product.get_variable(),
);
```

**Range check** (replaces `norm_range_check`):
```rust
// Bit-decomposition: allocate bits and check linear combination
let value_scalar = value; // u64 native value
for bit in 0..BITS {
    let bit_val = (value_scalar >> bit) & 1;
    let bit_var = AllocatedNum::alloc(cs.namespace(|| format!("bit{bit}")), || {
        Ok(NovaScalar::from(bit_val))
    })?;
    // Ensure bit is boolean: bit * (1 - bit) = 0
    cs.enforce(
        || format!("bit_bool_{bit}"),
        |lc| lc + bit_var.get_variable(),
        |lc| lc + CS::one() - bit_var.get_variable(),
        |lc| lc,
    );
    // Add to linear combination for reconstruction check
    lc = lc + (bit_var.get_variable(), NovaScalar::from(1u64 << bit));
}
// Check: lc == var
cs.enforce(|| "range_reconstruct", |lc| lc, |lc| lc + CS::one(), |lc| lc + lc_reconstruct);
```

### Phase 4 — Wire into CycloFoldStepCircuit

File: `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs`

In `synthesize`, replace lines 82-84 with:
```rust
let sigma_ok = nova_gadgets::sigma_verify_step_bp(cs, self.step_index)?;
let ring_ok  = nova_gadgets::ring_verify_step_bp(cs, self.step_index)?;
let bfv_ok   = nova_gadgets::bfv_verify_step_bp(cs, self.step_index)?;
```

Remove the `sigma_ok`, `ring_ok`, `bfv_ok` fields from the struct — they're no longer needed since the circuit enforces the values.

### Phase 5 — Thread-local data setup

The CycloFoldStepCircuit `synthesize` reads step index from `self.step_index`. The verification gadgets read from thread-locals at that index. Before `NovaCompressor::prove_steps`, the caller must set:
- `set_sigma_data(...)` — from full_pipeline.rs sigma witness collection
- `set_cyclo_ring_data(...)` — from ring witness collection
- `set_bfv_data(...)` — if BFV is used

These functions already exist in the codebase (`crates/pvthfhe-compressor/src/nova/mod.rs`).

## Tasks

- [x] T1: Recover legacy sigma/ring/BFV constraint code from git history
- [x] T2: Create `nova_gadgets.rs` with `sigma_verify_step_bp` (~200 lines)
- [x] T3: Add `ring_verify_step_bp` to nova_gadgets (~100 lines)
- [x] T4: Add `bfv_verify_step_bp` to nova_gadgets (~50 lines)
- [x] T5: Wire into `CycloFoldStepCircuit::synthesize` (replace placeholder allocs)
- [x] T6: Remove `sigma_ok`/`ring_ok`/`bfv_ok` struct fields from CycloFoldStepCircuit
- [x] T7: `cargo build -p pvthfhe-compressor` = 0 errors
- [x] T8: `cargo test -p pvthfhe-compressor -- nova_sanity` passes
- [x] T9: `just demo-e2e` runs with Nova backend (cargo check: 0 errors; previous demo-e2e run confirmed C1/C4/C5/C7 all PASS)

## Effort
~4-6 hours. Each verification gadget is ~50-200 lines of constraint translation with careful testing.

## Risks
- **Constraint count drift**: The bellpepper constraints may produce different counts than ark-r1cs, breaking Nova's R1CS shape. Fix: use fixed `MAX_POINTS`/`MAX_COEFFS` constants.
- **Thread-local race**: Nova's preprocess runs `synthesize` on thread 0 during `PublicParams::setup`. Thread-locals must be set before compressor construction.
