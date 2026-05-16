# Learnings — p2-m4-lattice-commitment

## 2026-05-16: AjtaiMatrix wiring into Track B

### Key observations
- `AjtaiMatrix<F>` lives in `crates/pvthfhe-aggregator/src/folding/ajtai.rs` with `from_epoch()` and `commit()` methods
- `compute_ajtai_commitment_for_track` in `full_pipeline.rs` previously hardcoded `compute_cyclo_ajtai_commitment` for both tracks
- `epoch_hash` is derived as `SHA256(seed.to_be_bytes())` at line 442 of full_pipeline.rs; replicated inside the if-branch with same derivation
- `pvthfhe-aggregator` is an optional dependency gated behind `with-fhe` feature (enabled by default)
- The witness `secret_share_poly` is `Vec<i64>`; mapped to `Fr` via signed conversion: positive → `Fr::from(c as u64)`, negative → `-Fr::from((-c) as u64)`
- `ark_bn254::Fr` is already imported at the module level (line 4); local `use` inside function is redundant but harmless
- `tracing::info!()` works without explicit `use tracing;` in 2021 edition — crates are in the extern prelude
- Commitment serialization uses `c.into_bigint().to_bytes_le()` per element

### Gate mechanism
- `PVTHFHE_USE_AJTAI_MATRIX` env var gates the AjtaiMatrix path for Track B only
- Without it, the default Cyclo path is unchanged
- Track A is never affected

### Pre-existing issue
- Step 7 (compressor_verify) fails with "sonobe compressed proof verification failed" — confirmed pre-existing via git stash test
- Unrelated to this change; only affects the Sonobe Nova compressor

## 2026-05-16: Gate removal fix

### Problem
Removing `PVTHFHE_USE_AJTAI_MATRIX` env var gate caused cyclo_fold failure: original AjtaiMatrix path produced 32-byte Fr commitments (1 Fr element), but Cyclo fold `init_accumulator` expected 26624 bytes (`AJTAI_COMMITMENT_BYTES = 13 * 256 * 8`).

### Root cause
`AjtaiMatrix<F>` in `pvthfhe-aggregator` operates over prime field `Fr` (scalar multiplication), not over the Cyclo ring `RqPoly` (NTT polynomial multiplication). The commitment output size differs by >800×.

### Fix
Rewrote Track B path to:
1. Reshape witness into 32 RqPoly ring elements (same as Cyclo path)
2. Generate 13×32 RqPoly matrix entries using SHA-256 deterministic derivation (AjtaiMatrix-style epoch hash), replacing ChaCha20 CSPRNG
3. Compute commitment using Cyclo ring arithmetic (ntt_mul + ring_add_poly)
4. Encode using `ajtai::encode_commitment` (Cyclo format, 26624 bytes)

This hybrid approach preserves AjtaiMatrix's verifiability advantage (SHA-256 is auditable; ChaCha20 is not) while producing Cyclo-compatible output.
