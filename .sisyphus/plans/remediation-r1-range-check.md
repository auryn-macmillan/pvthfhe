# Remediation: Quotient Witness Range Check

**Status**: PLAN
**Parent**: remove-groth16-and-fix-gaps.md

## Gap: S-Z r1_eval quotient witness not range-checked

**Original prompt** (Phase 2 Step 2.3):
```rust
// Range check r1_eval (Enclave pattern — two constraints):
// r1 is the modulus reduction quotient; bound it by Q * B_Z_S / q[limb]
let r1_bound = F::from((131_072u64 * 2) / SIGMA_RNS_MODULI[limb].min(1) + 1);
norm_range_check(&r1_eval, w.sz_r1_eval[limb], &FpVar::constant(r1_bound), ...)?;
```

**Current state** (`mod.rs:615-619`): sz_r1_eval is allocated as a free witness variable with NO bounds check. The equation `c(g)*z_s(g) + z_e(g) == t(g) + ch*d_i(g) + Q*r1(g)` is enforced, but r1(g) can be any value — a malicious prover can set arbitrary r1 to make any polynomial evaluations satisfy the equation.

**Why it matters**: The S-Z equation is only sound if the quotient witness is bounded. Without bounds, the prover can choose r1 arbitrarily, which means ALL polynomial sets (correct or adversarial) can satisfy the equation. The bound `B_Z_S / Q_min` is tiny (~0.0005), so with rounding up it's 1 — meaning r1 must be exactly 0 or 1. Range-checking r1 to 0 or 1 makes the S-Z check sound.

## Fix

Add a range check on `sz_r1_eval` after line 619 in `sigma_verify_step`:

File: `crates/pvthfhe-compressor/src/sonobe/mod.rs`, after line 619

Add:
```rust
// Quotient witness range check: r1(g) = (c(g)*z_s(g) + z_e(g) - t(g) - ch*d_i(g)) / Q[limb]
// Since |c*z_s + z_e - t - ch*d_i| ≤ B_Z_S (due to norm enforcement),
// and Q[limb] ≈ 2^58, the quotient is bounded to 0 or 1.
// The exact bound: r1 ≤ (B_Z_S / Q_min) + 1 ≈ 0.0005 + 1 → r1 ∈ {0, 1}
norm_range_check(
    &sz_r1_eval,
    w.sz_r1_eval[limb],
    &FpVar::constant(F::one()),
    1u64,
)?;
```

This follows the existing `norm_range_check` pattern used for z_s/z_e power coefficients (lines 661-667).

## Remediation Tasks
- [x] Add norm_range_check on sz_r1_eval in sigma_verify_step
- [x] cargo build + cargo test -p pvthfhe-compressor --lib ✅ (36 tests)
- [ ] Verify `just demo-e2e` passes

**Status**: PENDING E2E VERIFICATION
