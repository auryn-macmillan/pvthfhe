# Learnings: In-Circuit Verification (G2, G3)

## G2: Share coefficient witnesses — documented, deferred

- Added design documentation in `c7_circuit.rs::generate_step_constraints`
- The plan calls for 8192 share coefficients as private witnesses with Horner evaluation
- At t=114: 933K private witness values, ~933K R1CS multiplications — within Nova's range
- Deferred to M1; current ext.0 is trusted, verified off-circuit via Merkle proofs

## G3: Plaintext binding — M1 native check only

### Key finding: fhe.rs `decrypt_from_shares` applies RNS scaling
The function scales the recovered polynomial from [0, Q) down to [0, t) using `Scaler`.
`Plaintext::to_poly()` returns the SCALED (small-coefficient) polynomial, not the raw
`c0 + Σ λ_i·d_i` polynomial. Full G3 Schwartz-Zippel requires the UNSCALED polynomial.

### fhe.rs source location
`/home/dev/.cargo/git/checkouts/fhe.rs-*/crates/fhe/src/trbfv/shares.rs:249`
- Lines 268-301: Per-modulus Shamir reconstruction
- Lines 303-328: Scaler setup that converts to plaintext modulus space
- The `result_poly` BEFORE scaling is what's needed for G3

### Implementation choices
- `poly_coeffs_from_bytes()` returns 24576 RNS residues (8192 coeffs × 3 moduli)
- Must CRT-reconstruct to get actual coefficients before polynomial evaluation
- Added `poly_coeffs_fr_reconstruct()` on `FhersBackend` using BigInt arithmetic
- The CRT sum r_j·M_j·inv_j can be ~2^232, much larger than Q ≈ 2^174
- Must use BigInt with proper modulo reduction (while loop would run 2^60 iterations!)
- CRT constants and inv values computed dynamically via egcd_i128

### For M1
- G3 M1 check: verify Lagrange sum = 1 (Σ λ_i ≡ 1)
- Log accumulator z0 for trace
- Full Schwartz-Zippel plaintext binding deferred to follow-up (needs fhe.rs backend extension)

## Files changed
1. `crates/pvthfhe-compressor/src/sonobe/c7_circuit.rs` — G2 design doc
2. `crates/pvthfhe-fhe/src/fhers.rs` — `poly_coeffs_fr_reconstruct()`, made `decode_ct_polys` public
3. `crates/pvthfhe-fhe/Cargo.toml` — moved ark-bn254, ark-ff to [dependencies]
4. `crates/pvthfhe-cli/src/full_pipeline.rs` — G3 native check, CRT reconstruction, unified aggregate_decrypt path
