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

## G7: NIZK Verification Binding — SIMPLER post-hoc native check

### What was done
Added unconditional native NIZK re-verification in `full_pipeline.rs` after
`compressor.verify()`. This closes the forgery gap where a malicious prover
could provide garbage NIZK proof bytes — the compressor only hashes them
into the CCS binding but never independently verifies the sigma protocol.

### Key design decisions
- **No R1CS for commitment opening / challenge derivation / norm bounds**:
  Deferred. The native NIZK verification path already covers these checks.
- **RingVerifierCircuit already implements G7.1** (sigma equation in R1CS):
  The circuit already hashes 4×256 ring coefficients via Poseidon, enforces
  hash equality with external inputs, and verifies the ternary-challenge
  sigma equation with zero multiplications.
- **Verification is UNCONDITIONAL**: Runs in the compressor verify path and
  cannot be skipped. Previous NIZK verification runs in a separate phase
  (nizk_verify, lines 219-241) and is architecturally separable.

### Implementation
- Inserted after external compressor verify block (line 619), before decrypt phase
- Uses `RealNizkAdapter::verify(stmt, proof)` — already imported
- Reports timing via `observer.phase_start/end("g7_nizk_verify")`
- Logs `G7: NIZK verification passed for all N parties`

### Verification
- Build: `cargo build --workspace` — clean
- Demo: `just demo-e2e` — `G7: NIZK verification passed for all 10 parties (17.20ms)` + `ACCEPT`

### Files changed
5. `crates/pvthfhe-cli/src/full_pipeline.rs` — G7 post-hoc NIZK verification

## Files changed (cumulative)
1. `crates/pvthfhe-compressor/src/sonobe/c7_circuit.rs` — G2 design doc
2. `crates/pvthfhe-fhe/src/fhers.rs` — `poly_coeffs_fr_reconstruct()`, made `decode_ct_polys` public
3. `crates/pvthfhe-fhe/Cargo.toml` — moved ark-bn254, ark-ff to [dependencies]
4. `crates/pvthfhe-cli/src/full_pipeline.rs` — G3 native check, CRT reconstruction, unified aggregate_decrypt path
5. `crates/pvthfhe-cli/src/full_pipeline.rs` — G7 post-hoc NIZK verification
