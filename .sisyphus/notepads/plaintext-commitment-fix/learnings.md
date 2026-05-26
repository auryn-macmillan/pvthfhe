## Fix: plaintext_commitment mismatch in C7 Noir aggregator

**Problem**: Pipeline computed plaintext_commitment with its own inline Lagrange formula,
while the Noir circuit computed plaintext from the same shares but could use different
coefficients (in-circuit fallback vs pipeline's native computation).

**Root cause**: Two copies of Lagrange coefficient logic — one in Rust (lines 2834-2851)
and one in Noir (`lagrange_coeff_at`). The Prover.toml `lagrange_coeffs` field was all
zeros, triggering in-circuit O(n^2) fallback.

**Fix**: 
1. Compute Lagrange coefficients once via `compute_lagrange_coeffs_bn254(&party_ids_fr, Fr::from(0u64))`
2. Use those coefficients for plaintext_commitment computation in pipeline
3. Pass the same coefficients to Noir circuit via `lagrange_coeffs` (non-zero triggers fast path)

**Result**: Pipeline and circuit use identical Lagrange coefficients → identical plaintext → identical hash → ACCEPT.

**Files changed**: `crates/pvthfhe-cli/src/full_pipeline.rs` (lines ~2830-2960)
