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
