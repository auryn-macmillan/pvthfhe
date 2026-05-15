# Unresolved Issues — Surrogate Replacement Track B (L0+L1)

## Open / Deferred

1. **Full-resolution CCS witness** (L3.3): Current witness uses norm-bounded values (<101).
   Full-resolution values require protocol-level norm management with properly masked
   z_s/z_e extracted from the NIZK sigma proof.

2. **Cryptographic d (public statement)** (L3.3): The public statement for the ring equation
   is derived via SHA-256 expansion (heuristic). The actual d should come from Cyclo
   commitment parameters bound to protocol state.

3. **CCS matrix size optimization**: 2.1 MB per 256×256 matrix is excessive for scaling
   benchmarks. Sparse encoding or R_q-domain CCS could reduce this significantly.

4. **non-ternary secret keys**: The BFV backend generates uniform-random secret keys
   (not ternary). This fundamentally conflicts with the small-norm assumption in the
   Cyclo fold. Need to either (a) use ternary secret keys, or (b) adapt the fold to
   handle large-norm secrets via proper masking.

## Tracked but Not Blocking

5. **red_3 test**: Pre-existing RED test (nizk_verify count mismatch). Not caused by
   these changes. Should be addressed in a separate remediation task.

## Resolved

- ✅ L0.1: RingElementVar::from_coeffs added
- ✅ L0.2: Native ring-equation verification wired (structural check, M1)
- ✅ L1.2: Non-trivial 256×256 CCS matrix replaces 1×1 identity
- ✅ L1.3: Non-trivial witness from real NIZK data (norm-bounded)
- ✅ L1.4: Deterministic RNG documented for research prototype
