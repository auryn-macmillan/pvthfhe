# Decisions: In-Circuit Verification (G2, G3)

## Decision 1: G2 full implementation deferred to M1
The 8192-coefficient Horner evaluation in R1CS is ~1 week of work.
For this session, documented the design clearly and deferred implementation.
Current ext.0 is trusted; off-circuit Merkle proofs provide binding.

## Decision 2: G3 limited to native accumulator check for M1
fhe.rs `decrypt_from_shares` applies RNS scaling, making the returned
polynomial coefficients in [0, t) rather than [0, Q). Full Schwartz-Zippel
check requires the unscaled plaintext from the backend.
M1 check: verify Lagrange sum = 1 and log accumulator.

## Decision 3: CRT reconstruction in BigInt, not in Fr field
Attempting CRT in Fr led to an infinite loop: the intermediate values
(r_j·M_j·inv_j) are ~2^232, which when reduced by repeated subtraction
mod Q (≈ 2^174) would require 2^60 iterations. Used num_bigint::BigInt
with proper modulo operation instead.

## Decision 4: Always use `aggregate_decrypt_with_poly`
Unified the two code paths (with/without `pipeline-extra-checks`) to always call
`aggregate_decrypt_with_poly`. The extra cost is negligible and the plaintext
polynomial bytes are needed for future G3 closure.

## Decision 5: Dynamic CRT invariants
Instead of hardcoding M_j^{-1} mod q_j values (which are error-prone), compute
them dynamically at function entry using the existing `egcd_i128` method.

## Decision 6: G3 approach — Nova finalization step (2026-05-17)

Chose to add one extra Nova IVC step after share folding, dedicated to plaintext binding. This avoids:
- Non-uniform steps (Nova requires identical constraint structure per step)
- State widening (stays at 3 elements)
- External input changes (reuses ExternalInputs5)

The plaintext finalization step passes state through unchanged and enforces `z0 == plaintext(r)`. Plaintext coefficients arrive via the same thread-local mechanism as share coefficients (G2).

## Decision 7: Required FHE backend API extension

The current `aggregate_decrypt_with_poly` returns SCALED plaintext (coefficients in [0, t) post-Scaler). G3 needs PRE-SCALING result polynomial (coefficients in [0, Q)). Must add `aggregate_decrypt_raw_poly` or modify `aggregate_decrypt_with_poly` to also return the pre-scaling `Poly`.

Alternative considered: use the scaled plaintext and account for noise bound. Rejected — noise tolerance is not exact-equality, cannot be expressed as clean R1CS equality constraint.

## Decision 8: r-powers reuse

The r-power constraint chain (P1.7) is already computed in every step. The plaintext step reuses these via the shared `C7_STEP_DATA` thread-local. No need to double-constrain r-powers — they're already verified against external input `ext.4` (r).

