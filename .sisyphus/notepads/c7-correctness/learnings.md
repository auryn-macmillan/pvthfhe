# Learnings: C7 Correctness Plan

## 2026-06-04 — Plan creation

### Key findings from codebase analysis

1. **Current circuit gap**: `aggregator_final/src/main.nr:main()` (lines 109-143) proves only Poseidon hash binding of `nova_final_plaintext`. The circuit receives 8 field elements as the "plaintext" and simply hashes them. There is no constraint linking these field elements to the Lagrange recombination of decrypt shares.

2. **Nova IVC folds hashes, not polynomials**: The `LagrangeFoldStepCircuit` in `lagrange_fold_circuit.rs` accumulates `λ_i · share_hash_i` (scalar field multiplication on Poseidon hash values). This is a hash-chain accumulator, not a polynomial arithmetic verifier. The `aggregator_final` circuit receives the final Nova state but must verify the actual polynomial relation separately.

3. **Pre-scaling API exists**: `aggregate_decrypt_raw_result_poly()` in `fhers.rs` (line 1775) returns the raw Lagrange-interpolated polynomial before RNS scaling. This is exactly what the in-circuit relation needs. This API was added as part of Phase B.1 (G3) but hasn't been wired into circuit constraints yet.

4. **Native check is not in-circuit**: `run_c7_verification()` in `full_pipeline.rs` does a native (Rust side) check of `Σ λ_i = 1` and logs `z0`. This is not a cryptographic proof. The circuit must constrain this relation.

5. **Schwartz-Zippel is the right approach**: Verifying 8192 coefficient-wise equalities per share per modulus is infeasible (~96K constraints for t=4). Schwartz-Zippel reduces this to a single polynomial evaluation at a random challenge point, consuming ~7 constraints per share independent of ring dimension.

6. **Ring arithmetic compatibility**: Noir's native field is BN254 Fr (~254 bits). Each RNS modulus q_j is ~58 bits. A single Fr element can hold one q_j residue. Three independent checks (one per modulus) verify the full Q-arithmetic without CRT reconstruction in-circuit.

### Design decisions

1. **Schwartz-Zippel approach**: One evaluation at challenge point `r` (computed via Fiat-Shamir from the transcript), not per-coefficient. This keeps constraint count O(t) not O(N·t).

2. **Circuit location**: Extend `aggregator_final/src/main.nr`, not create a new circuit. The existing circuit already has the correct structure (receiving Nova final state, verifying plaintext commitment). Adding Lagrange recombination constraints to `main()` is the most direct path.

3. **MAX_SHARES = 128**: Matches the existing `NOIR_MAX_PARTICIPANTS` constant in `full_pipeline.rs`. The loop iterates over all MAX_SHARES entries but non-participating entries are zero-padded, so they don't affect the sum.

4. **Lagrange sum constraint**: The circuit MUST assert `Σ λ_i = 1`. This is not optional. Without this check, a malicious prover could double both λ and d_i(r) and still satisfy `Σ λ_i · d_i(r) = pt(r)` while the individual relationship is broken.

### Gotchas to watch

1. **Zero-padding approach**: The `fold_sum` loop iterates over all MAX_SHARES entries. Non-participating entries MUST be zero in the witness. If the witness generator puts garbage in padded entries, the constraint will fail.

2. **Prover.toml array format**: Noir expects arrays as `["val1", "val2", ...]` for toml. For MAX_SHARES=128, the Prover.toml will be large. The build_c7_prover_toml function must handle this correctly.

3. **Existing test updates**: `test_simplified_honest` must be updated to include the new witness fields. The test currently constructs a minimal 8-coefficient plaintext and calls `main()`. It will need new witness parameters.

4. **Constraint count**: The new constraints add ~MAX_SHARES multiplication gates (for `lagrange_coeffs[i] * share_evals[i]`) plus ~MAX_SHARES addition gates. At MAX_SHARES=128, this is ~256 constraints, which is negligible compared to the existing circuit.
