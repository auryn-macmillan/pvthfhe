# G.12 Phase 2b — In-Circuit Schnorr EC Equality

**Status**: DESIGN COMPLETE  
**Decision**: In-circuit verification of s·G == R + e·PK
**Estimate**: ~1 day

## Approach

Use arkworks `ark-ec` with `r1cs` feature for in-circuit G1 operations.
The circuit verifies: `G * sig_s == R + challenge_e * PK`
where challenge_e = Poseidon(sig_r_x, pk_x, share_hash).

State stays [acc_hash, step_count]. The EC check is an additional constraint
within the existing generate_step_constraints — returns error if verification fails.

## Required dependency

Add to `crates/pvthfhe-compressor/Cargo.toml`:
```toml
ark-ec = { git = "https://github.com/arkworks-rs/algebra", features = ["r1cs"] }
```

## Pattern

From arkworks `CurveVar`:
- Represent `G1Affine` as `NonNativeAffineVar<ark_bn254::g1::Config, FpVar<Fr>>`
- `scalar_mul_le(curve_var, scalar_bits)` → result point
- Curve point addition: `a + b` works on NonNativeAffineVar
- Constrain equality: compare x/y coordinates

## Edge case

If `challenge_e == Fr::zero()`, the Schnorr equation reduces to `s·G == R`.
This is valid — the prover can still grind for this case but standard sigma
soundness applies (1/3 per fold × T=10 → 1.7e-5).

## Files modified
1. `crates/pvthfhe-compressor/Cargo.toml` — add ark-ec r1cs
2. `crates/pvthfhe-compressor/src/sonobe/share_verification_circuit.rs` — add EC check
