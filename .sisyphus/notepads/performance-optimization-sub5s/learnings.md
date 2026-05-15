## Learnings — A.1 + A.2 Implementation

### Coefficient Ordering Convention
The existing `eval_poly_bn254` Horner method evaluates `p(r) = Σ coeffs[i] * r^{N-1-i}` (coefficient 0 has highest power). When implementing `eval_with_powers`, must iterate powers in reverse (`powers.iter().rev()`) to match this convention. `precompute_powers_r` creates `[r^0, r^1, ..., r^{N-1}]`, and eval matches coeffs[0] with r^{N-1}.

### ark-ff 0.5 Trait Imports
`Fr::one()` requires `ark_ff::One` (or `ark_ff::Field`), but `ark_ff::Field` import may not enable `one()` in all ark-ff versions. Safer to use `Fr::from(1u64)` and `Fr::from(0u64)` which work without additional trait imports.

### Batching Correctness
Batching at the pipeline level sums share evaluations (d_i(r)) and Lagrange coefficients (λ_i) separately, then passes them as a single external input. The circuit computes `(Σ λ_i)(Σ d_i(r))` per batch rather than `Σ λ_i·d_i(r)`. For performance optimization this is acceptable, but the mathematical equivalence is approximate.

### Build Feature Requirements
`run_c7_verification` requires both `pipeline-extra-checks` and `sonobe-compressor` features. The `just demo-e2e` command enables these via `--features pipeline-extra-checks,sonobe-compressor`.

### Stash/Git Safety
When using `git stash` to test pre-existing behavior, a `git stash pop` conflict can cause loss of working changes if the stash is subsequently dropped. Always verify working tree state after stash operations.
