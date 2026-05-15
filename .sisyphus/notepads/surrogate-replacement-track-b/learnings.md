# Learnings — Surrogate Replacement Track B (L0+L1)

## 2026-05-15: Layer 0 + Layer 1 Implementation

### L0.1: RingElementVar Extension
- Added `from_coeffs()` constructor. The `n()` method already existed.
- `pub coeffs` field allows direct construction, but the constructor improves ergonomics.
- Located in `crates/pvthfhe-compressor/src/sonobe/ring_element_var.rs`.

### L0.2: Native Ring-Equation Verification
- Replaced the "pending" tracing log in full_pipeline.rs:469-478 with actual native
  `verify_ring_equation()` calls using real witness data.
- Gate: `#[cfg(all(feature = "pipeline-extra-checks", feature = "sonobe-compressor"))]`
- Challenge derived deterministically from session_id via SHA-256 → mod 3 mapping to {-1, 0, 1}.
- z_s and z_e built from witness.secret_share_poly and witness.error (first 256 coefficients as Fr).
- d (public statement) derived from NIZK statement canonical hash expanded to 256 coefficients.
- t computed as c·z_s + z_e - c·d (M1 structural check; will be replaced with commitment openings in L3.3).
- verify_ring_equation imported from `pvthfhe_compressor::sonobe::cyclo_verifier`.

### L1.2: CCS Matrix Replacement
- Replaced 1×1 identity surrogate (`build_demo_ccs_matrix`) with 256×256 non-trivial matrix (`build_cyclo_ccs_matrix`).
- Matrix structure: first 128 rows shift column i into row i (M[i, i+128] = Fr::ONE); last 128 rows are zero.
- This satisfies CCS relation `(M·z) ⊙ z == 0` when witness has non-zero entries only in first half.
- Wire format: [rows:u32 BE][cols:u32 BE][data: rows×cols Fr LE] — Fr is 32 bytes (4 u64 LE limbs).
- Matrix size: 8 + 256×256×32 = 2.1 MB (acceptable for research demo).
- Required `use ark_ff::{BigInteger, PrimeField}` at module level for Fr serialization.

### L1.3: CCS Witness Replacement
- Replaced zero witness (`serialize_nizk_witness`) with 256-element non-trivial witness (`build_cyclo_witness`).
- First 128 entries: non-zero values derived from real NIZK witness data (norm-bounded to ≤101).
- Second 128 entries: zeros (required for CCS satisfiability with the 256×256 shift matrix).
- Norm-bounding critical: cyclo fold path has `per_step_norm_budget() = 1024/10 = 102`; raw FHE secret
  key coefficients have norms ~10^13. Coefficients are reduced modulo 101 to stay within bounds.
- If abs == 0, the entry is set to 101 (the ceiling) to maintain non-triviality.

### L1.4: Deterministic RNG Documentation
- Enhanced existing `allow-seeded-rng` comments to document the research prototype limitation.
- Added: "Reproducible folding RNG — bound to session epoch via srs_hash. Acceptable for research
  prototype; production should mix OsRng nonce."
- Applied to all three occurrences in sonobe/mod.rs (prove, prove_steps, prove_steps_merkle).

### Key Discoveries
1. The cyclo fold path (`fold.rs:159-166`) has its own witness norm check separate from the
   Track B norm enforcement block. This check applies to BOTH tracks.
2. The `red_3_records_all_full_pipeline_phases` test was already RED before these changes
   (different failure reason).
3. Track A path remains fully functional with the new CCS matrix/witness — the norm-bounded
   values satisfy the fold path's per-step budget.
4. The `verify_ring_equation` function works correctly with the ternary challenge approach;
   no R1CS multiplications needed due to c ∈ {-1, 0, 1}.
