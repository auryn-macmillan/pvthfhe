# Learnings: G2 In-Circuit Share Evaluation Verification

## Architecture Decision: Thread-Local Coefficient Storage

**Pattern**: Used `thread_local!` + `RefCell<Option<C7StepData>>` to pass per-step share coefficients from `c7_fold_witnesses` to `generate_step_constraints`.

**Why**: Nova's `FCircuit` trait requires `Params = ()` for `NovaCompressor`, preventing direct data passing through circuit struct. Thread-local storage is the same pattern used by `HeterogeneousStepCircuit` for its circuit family registry.

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

## G3 Scoping Session (2026-05-17)

### Current State

**`verify_c7_plaintext_binding`** (`crates/pvthfhe-cli/src/full_pipeline.rs:1650`):
- Only checks Lagrange sum `z1 == 1` and logs z0
- Does NOT compute `plaintext(r)` or enforce `z0 == plaintext(r)`
- Comment at line 1640-1642 documents the blocker: fhe.rs applies RNS scaling, returned coefficient bytes are in [0, t) not [0, Q); pre-scaling polynomial not exposed

**C7DecryptAggregationCircuit** (`crates/pvthfhe-compressor/src/nova/c7_circuit.rs`):
- State: [z0 = Σ λ_i·d_i(r), z1 = Σ λ_i, z2 = step_count]
- ExternalInputs5: (share_eval, lagrange_coeff, coeff_commitment, dkg_root_hash, r)
- G2 done: 8192 coeff witnesses + Horner eval + commitment opening + r-power constraints (P1.6-P1.8)
- G4 done: dkg_root_hash bound in circuit
- Uses thread_local!(RefCell<Option<C7StepData>>) for per-step coefficient data

**FHE backend already provides**:
- `aggregate_decrypt_with_poly()` returns (decoded_plaintext, plaintext_poly_bytes) — line 1426
- `poly_coeffs_from_bytes()` decodes Poly bytes → i64 residues
- `poly_coeffs_fr_reconstruct()` CRT-reconstructs residues → Fr (used for share coeffs at line 816)

### Key API Gap

`aggregate_decrypt_with_poly` returns the **SCALED** plaintext polynomial (after `Scaler::new` in `decrypt_from_shares`). The G3 check `Σ λ_i·d_i(r) == plaintext(r)` requires the **PRE-SCALING** result polynomial (coefficients in [0, Q)), because share evaluations `d_i(r)` are computed over the full-Q domain.

**Needed**: A new fhe.rs API that returns the result polynomial BEFORE the Scaler step is applied. The current `decrypt_from_shares` applies scaling internally and only returns the scaled `Plaintext` struct.

### Design Decision: Plaintext Finalization Step

After t Nova steps fold all shares, we add one **plaintext finalization step**:
- Receives 8192 plaintext coefficients as private witnesses (via thread-local storage, same pattern as G2)
- Computes `plaintext_eval = Σ m_j · r^{8191-j}` (Horner eval in R1CS)
- Reads old accumulator `z_i[0]` (= Σ λ_i·d_i(r))
- Enforces `z_i[0] == plaintext_eval`
- Passes state through unchanged: z0' = z0, z1' = z1, z2' = z2
- This requires the pipeline to call `prove_steps_c7` with t+1 steps (t share steps + 1 plaintext step)

This is architecturally clean because:
- Same Nova uniform step structure (no special-case step)
- Reuses existing Horner eval + r-power constraint infrastructure (lines 142-253)
- Plaintext coefficients are private witnesses, not public inputs (circuit retains soundness)

### Constraint Estimate

**Per step (already costs ~8243 constraints)**:
- 8192 coefficient witnesses: 8192 constraints
- 8192 coefficient commitment (Poseidon sponge): ~300 constraints  
- r-power correctness (8191 constraints): 8191 multiply-enforce
- Horner eval: 8192 multiply-add per step
- G2 commitment/challenge checks: ~600

**Plaintext finalization step (additional)**:
- 8192 plaintext coefficient witnesses: 8192 constraints
- Plaintext Poseidon commitment: ~300 constraints
- r-power correctness: REUSED from share steps (same r, already constrained)
- Horner eval: 8192 constraints
- Equality with z0: 1 constraint
- **Total for G3**: ~16,785 incremental constraints on the plaintext step

**Total circuit width**: State stays at 3 elements (z0, z1, z2). No external input widening needed — the plaintext step uses existing ExternalInputs5, possibly with dummy values for unused fields (or a separate ExternalInputs for the plaintext step).

**Batching**: If t=10, total steps = 11, total constraints ≈ 98,000. Well within Nova range (2^20+).


## G3: aggregate_decrypt_raw_result_poly Implementation (2026-05-17)

### Approach
Added `aggregate_decrypt_raw_result_poly` to `FhersBackend` that performs manual Lagrange reconstruction of share polynomials without going through `ShareManager::decrypt_from_shares`. This returns the pre-scaling polynomial (mod Q, not scaled to plaintext domain) needed by the C7 circuit for G3 plaintext binding.

### Poly API for scalar Lagrange reconstruction
- fhe-math's `Poly` supports `Mul<&BigUint>` (element-wise RNS multiplication) and `Neg` (coefficient-wise negation at each modulus level)
- For positive Lagrange coefficients: `&poly * &BigUint::from(λ as u64)`
- For negative Lagrange coefficients: `-(&poly * &BigUint::from((-λ) as u64))`  
- Addition uses standard `&a + &b` syntax
- The share polynomials deserialize in their original representation (PowerBasis); scalar multiplication works regardless of representation since it operates at the RNS residue level
- `Poly::to_bytes()` uses protobuf serialization that auto-converts to PowerBasis

### Test parameters
- `setup_threshold` enforces `t ≤ (n-1)/2` for Shamir security (added in commit 80a0c82)
- Used n=5, t=2 (minimum satisfying constraint: 2 ≤ (5-1)/2 = 2)
- Several pre-existing integration tests violate this constraint (e.g., `aggregate_uses_submitted_shares` with n=5, t=3) — these are pre-existing failures unrelated to this change

### Residual notes
- The raw result poly can be deserialized via `poly_coeffs_from_bytes` (same format as decrypt-share polynomials — protobuf-encoded RNS residues)
- Expected size: 8192 coefficients × 3 moduli = 24576 residues returned by `poly_coeffs_from_bytes`
