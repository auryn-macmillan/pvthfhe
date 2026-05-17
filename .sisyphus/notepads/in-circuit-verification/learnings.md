# Learnings: G2 In-Circuit Share Evaluation Verification

## Architecture Decision: Thread-Local Coefficient Storage

**Pattern**: Used `thread_local!` + `RefCell<Option<C7StepData>>` to pass per-step share coefficients from `c7_fold_witnesses` to `generate_step_constraints`.

**Why**: Sonobe's `FCircuit` trait requires `Params = ()` for `SonobeCompressor`, preventing direct data passing through circuit struct. Thread-local storage is the same pattern used by `HeterogeneousStepCircuit` for its circuit family registry.

**Trade-off**: Data is serialized to bytes in `set_c7_step_data` and deserialized via `F::from_le_bytes_mod_order` in the circuit to enable generic type conversion between `ark_bn254::Fr` and `F: PrimeField`.

## Critical Bug: FpVar::constant Causes Incompatible Constraint Matrices

**Problem**: Using `FpVar::constant(r_pow[j])` for r^j powers embeds the actual constant values into the R1CS constraint matrices. During preprocessing (no thread-local data), all constants are zero. During proving (with real data), constants differ. Nova folding requires identical A, B, C matrices — different constants = incompatible instances → verification failure.

**Fix**: Changed r-powers from `FpVar::constant` to `FpVar::new_witness`. This ensures the constraint structure (witness × witness = result) is identical across all sessions. The power values vary but the structure doesn't.

## Horner Evaluation Direction

**Finding**: `eval_poly_bn254` uses Horner's method which computes `c₀·r^{N-1} + c₁·r^{N-2} + ... + c_{N-1}·r⁰`. The initial naive circuit implementation used `c₀·r⁰ + c₁·r¹ + ... + c_{N-1}·r^{N-1}` — the reverse order. Fixed by using power index `N_COEFFS-1-j` in the dot product.

## Residual Trust Gap: r-Power Correctness

The r^j powers are provided as witnesses but their correctness is NOT verified in-circuit (i.e., the circuit doesn't enforce `r_pow[0] == 1` and `r_pow[j+1] == r_pow[j] * r`). A malicious prover could provide arbitrary powers. The coefficients remain bound by off-circuit Merkle proofs, limiting the attack surface, but full closure requires either:
- Adding r as a public input and constraining powers (8191 additional mults per step)
- Merkle opening at the evaluation point (G2.2 stretch goal)
