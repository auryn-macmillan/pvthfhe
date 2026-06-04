# Problems: C7 Correctness Plan

## 2026-06-04 — Plan creation

### P.1: Share polynomial coefficient encoding

**Problem**: The current Noir circuit operates on `[Field; N]` with N=8 (the plaintext ring dimension as field elements). For C7 correctness, we need share polynomial evaluations at the challenge point `r`. These are computed natively from 8192-coefficient polynomials via CRT reconstruction.

**Status**: The plan uses evaluation-at-a-point (Schwartz-Zippel), so the circuit only needs the scalar `d_i(r)`, not the full polynomial. The native side computes `d_i(r)` via `eval_with_powers` on CRT-reconstructed coefficients.

**Resolution**: T.1.5 documents the per-modulus-limb approach. The circuit receives pre-computed evaluations; it does not evaluate polynomials in-circuit.

### P.2: In-circuit challenge point verification

**Problem**: The challenge point `r` must be the same value used natively and in-circuit. If the prover can choose a different `r`, they can manufacture a matching evaluation point.

**Status**: `r` is a public input to the circuit. The verifier checks that `r` matches the expected Fiat-Shamir derivation. The native derivation uses `hash_all_coeffs` on the full coefficient data. The circuit doesn't need to re-derive `r`; it accepts `r` as a public input, and the verifier's external check ensures `r` is correct.

**Resolution**: Documented in T.1.2 and T.1.4. This is the standard Fiat-Shamir approach: the verifier re-derives `r` from public data and checks it matches the public input.
