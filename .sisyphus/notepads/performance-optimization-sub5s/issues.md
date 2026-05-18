# Issues

## Pre-existing: pvthfhe-compressor build errors

**Date found**: 2026-05-15
**When running**: `just demo-e2e` (release mode with `sonobe-compressor` feature)

**Errors**:
```
error[E0599]: no function or associated item named `one` found for struct `Fp<P, N>` in the current scope
error[E0599]: no function or associated item named `zero` found for struct `Fp<P, N>` in the current scope
```

**Impact**: `just demo-e2e` fails to build in release mode. Debug build (without `sonobe-compressor` feature) works fine.

**Workaround**: Run `cargo run -p pvthfhe-cli --features "demo-seeded-rng,pipeline-extra-checks" -- demo ...` (without `sonobe-compressor`).

**Note**: This is unrelated to the timing instrumentation changes. The compressor crate has `Zero`/`One` trait import issues that may stem from a dependency version conflict.

## Fixed: Noir aggregator_final TOML mismatch (2026-05-18)

**Symptom**: Demo-e2e silently failed the Noir phase with "Expected argument committee_party_ids" error.
**Root cause**: `build_c7_prover_toml` in `full_pipeline.rs` generated old TOML format with `lagrange_coeffs`, `plaintext_hash`, `plaintext`, `z_q` fields. The circuit was updated (G-LAGRANGE fix) to require `committee_party_ids` instead.
**Fix**: Updated function signature to `committee_party_ids: &[u32]`, removed old fields, added `committee_party_ids` array. Updated both callers and `PipelineReport`.
**Files**: `full_pipeline.rs`, `pvthfhe_e2e.rs`

## Fixed: per_aggregator flat C7 Nova (50s at n=16) (2026-05-18)

**Symptom**: Per-aggregator benchmark showed `c7: 50.0s` at n=16, while demo-e2e showed `c7_decrypt_aggregation: 3617ms`.
**Root cause**: `per_aggregator` used flat Sonobe Nova folding (`prove_steps_c7`), while demo-e2e uses `CompressionTree::build` (MicroNova tree folding) which is 31x faster.
**Fix**: Replaced flat Nova with `CompressionTree::build` using dummy leaf hashes. Kept flat Nova as fallback.
**Files**: `per_aggregator.rs`
