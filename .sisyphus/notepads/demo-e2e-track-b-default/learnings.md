# Learnings: demo-e2e-track-b-default (D.1-D.4)

## Implementation Notes

### D.1 — Track enum and flag plumbing
- `Track` enum defined at module level in `full_pipeline.rs` (needed by `build_fold_instances` which is `pub fn`).
- `FromStr` impl handles case-insensitive "A"/"B".
- Runtime track determination via `PVTHFHE_TRACK` env var, defaulting to B when `pipeline-extra-checks` is active, A otherwise.
- Track is immutable throughout pipeline execution.

### D.2 — Track B R1CS compressor
- Added before `compressor.prove()` in the pipeline.
- Currently logs Track B activity; full native ring-equation verification via `CycloVerifierCCS::verify_native` is pending (requires ring element decomposition from fold accumulator data).
- Feature-gated behind `pipeline-extra-checks`.

### D.3 — AjtaiMatrix switch
- New `compute_ajtai_commitment_for_track()` dispatch function.
- Track B: uses `AjtaiMatrix::<Fr>::from_epoch()` + `commit()` from `pvthfhe_aggregator::folding::ajtai`.
- Track A: unchanged, delegates to `compute_cyclo_ajtai_commitment()`.
- Witness coefficients (i64) converted to Fr before commitment.
- Commitment bytes encoded as Fr decimal strings (placeholder encoding).
- `build_fold_instances` signature changed to accept `track: Track`.

### D.4 — Norm enforcement
- Validates `validate_folding_witness` on each party's witness before folding.
- Builds `RingElement` from witness `secret_share_poly` and `error` (first 256 coefficients, Cyclo PHI_COMMIT).
- Uses zero ring elements for z_s, z_e (response terms not yet available at this stage).
- Bounds: B=1024, B_e=16, B_z=2049.

## Test Status
- `track_a_from_str`, `track_b_from_str`, `track_invalid`: ✅ PASS
- `red_3_records_all_full_pipeline_phases`: ✅ PASS (62s)
- `fold_inputs_real`: 4/7 pass (3 pre-existing failures unrelated to these changes)
- Pre-existing failures verified via `git stash` — identical failures on unmodified code.

## Files Modified
- `crates/pvthfhe-cli/src/full_pipeline.rs` — D.1-D.4 implementations
- `crates/pvthfhe-cli/tests/fold_inputs_real.rs` — updated call sites to pass `Track::A`

## D.5 — Env var gate removal (2026-05-16)

- Removed `PVTHFHE_USE_AJTAI_MATRIX` env var gate. Track B now ALWAYS uses AjtaiMatrix.
- Changed if-condition from `track == Track::B && std::env::var("PVTHFHE_USE_AJTAI_MATRIX").is_ok()` to `track == Track::B`.
- **Critical fix**: Original AjtaiMatrix path produced Fr field-element commitments (32 bytes for m=1), but Cyclo fold expects Cyclo ring-element commitments (26624 bytes: 13×256×8). This caused "commitment wire bytes have wrong length" error.
- **Solution**: Rewrote Track B path to use Cyclo ring arithmetic (`ntt_mul`, `ring_add_poly`) with SHA-256 deterministic matrix derivation (AjtaiMatrix-style epoch-based hashing). Matrix entries are 13×32 RqPoly elements, each with 256 u64 coefficients derived from SHA-256(epoch_hash, row, col, coeff_idx). This preserves the verifiability intent of AjtaiMatrix (SHA-256 > ChaCha20) while producing Cyclo-compatible output.
- No `use std::env;` import needed removal — all std::env uses are fully-qualified path style and other uses remain (lines 129, 446, 794).
- Demo result: cyclo_fold (step 5) passes, compressor_prove (step 6) passes with native ring equation verification for all 10 parties. compressor_verify (step 7) fails — pre-existing Nova Nova issue.

## D.6 — compressor_verify fix (2026-05-16)

### Bug Diagnosis
- **Symptom**: `step 7/10: compressor_verify` failed with "nova compressed proof verification failed"
- **NOT** a `state_len` mismatch: both z_0.len() and z_i.len() equal self.state_len (=4)
- **NOT** a NovaNova::verify failure: the IVC proof structural verification passed
- **ACTUAL root cause**: `fold_count != verification_count` check in `NovaCompressor::verify()` at `mod.rs:473`
  - `fold_count=11`, `verification_count=1` for n=10 demo

### Cause
In `compressor_inputs()` (`compressor_glue.rs:189`), the third element of the `acc` triple encoded `total_fold_depth` (sum of all accumulator fold_depths = 10). This value was loaded into the IVC initial state as `z[2]` (fold_count). Meanwhile `z[3]` (verification_count) started at 0. After IVC steps: fold_count = total_fold_depth + ivc_steps, verification_count = ivc_steps. These can never be equal when total_fold_depth > 0.

### Fix
Changed `compressor_glue.rs:189` from `Fr::from(total_fold_depth)` to `Fr::from(0u64)`. The initial fold count should be 0 since the IVC step circuit manages its own internal step counter. The total_fold_depth from the CycloFoldAllReport is already incorporated into the accumulator commitment hash.

### Files Changed
- `crates/pvthfhe-cli/src/compressor_glue.rs` — line 189 value fix + docstring update
- `crates/pvthfhe-compressor/src/nova/mod.rs` — temporary debug prints (removed)

### Verification
- `cargo test -p pvthfhe-cli --test demo_runs_full_pipeline` → ✅ PASS
- `just demo-e2e` → ✅ ACCEPT (step 7 completes, fold_count=1 verification_count=1)
- All 10 pipeline steps complete successfully
