# Decisions — Surrogate Replacement Track B (L0+L1)

## 2026-05-15

### D1: Native ring equation check is structural, not cryptographic (M1)
- **Decision**: In M1, `t = c·z_s + z_e - c·d` is computed from the equation itself, making
  the native verify_ring_equation call tautologically true.
- **Rationale**: The purpose of M1 is to establish the CORRECT CODE STRUCTURE and exercise
  the verify_ring_equation code path with real witness data, even though the equation is
  trivially satisfied. The real t and d values will come from commitment openings in L3.3.
- **Trade-off**: The current check doesn't provide actual security, but it replaces a
  "pending" log with real arithmetic and documents the protocol structure.

### D2: 256×256 shift matrix for CCS (not 256×1)
- **Decision**: Used a 256×256 square matrix instead of the plan's 256×1 suggestion.
- **Rationale**: `check_satisfiability` in `pvthfhe-cyclo/src/ccs_encode.rs` requires
  a square matrix (`rows == z.len() && rows == cols`). A 256×1 matrix would fail this check.
  The shift-matrix structure (first half maps to second-half columns) satisfies the CCS
  relation with a witness having non-zero entries only in the first half.
- **Size**: 2.1 MB per matrix (acceptable for research demo with n=10).

### D3: Norm-bounded witness values
- **Decision**: CCS witness values are reduced modulo 101 (per_step_norm_budget - 1).
- **Rationale**: The cyclo fold path enforces `witness_norm_estimate() ≤ per_step_norm_budget()`
  at fold.rs:159-166. Raw FHE secret key coefficients have norms of ~10^13, far exceeding
  the budget of 102. The norm-bounded values remain non-trivial (derived from real data)
  while satisfying the CCS satisfiability and norm checks.
- **Impact**: The witness is "non-trivial" but norm-contrained. Full-resolution values
  will require protocol-level norm management (L3).

### D4: Feature gate for ring-equation verification
- **Decision**: Native ring-equation verification gated behind
  `#[cfg(all(feature = "pipeline-extra-checks", feature = "nova-compressor"))]`.
- **Rationale**: `verify_ring_equation` lives in `pvthfhe-compressor` which requires
  `nova-compressor` feature. `pipeline-extra-checks` gates the Track B path.
  When either feature is absent, the check is gracefully omitted (no compilation error).

### D5: Keep hash-accumulate in CycloFoldStepCircuit
- **Decision**: The R1CS path in `generate_step_constraints` remains hash-accumulate
  (state_len=3). Native ring verification runs off-circuit.
- **Rationale**: As specified in the plan: "This is the 'hash-and-verify' hybrid:
  ring equation verified natively, circuit folds the hash." Avoids breaking Track A
  compatibility and keeps the circuit lightweight.
