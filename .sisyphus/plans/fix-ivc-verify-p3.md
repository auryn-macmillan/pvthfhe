# Remediation: IVC Verification Failures (P3 Fix)

**Status**: PLAN
**Root Cause**: Nova R1CS preprocessing builds constraint matrices while thread-local data (DKG_AGG_DATA, PK_AGG_DATA) is empty → 288 constraints. During prove, data is populated → 291 constraints. Verify checks against preprocessing R1CS → fail.

## Fix: Pre-seed thread-locals before SonobeCompressor::new()

### C4 — DKG Aggregation

File: `crates/pvthfhe-cli/src/full_pipeline.rs`, before `c4_compressor = SonobeCompressor::new(...)`

Add dummy data to set the correct constraint count:
```rust
// P3: Pre-seed DKG_AGG_DATA to match prove-time constraint count.
// Without this, preprocess builds R1CS with empty data → constraint mismatch.
pvthfhe_compressor::sonobe::set_dkg_agg_data(vec![
    (Fr::from(1u64), Fr::from(1u64), Fr::from(1u64), Fr::from(1u64), Fr::from(1u64), Fr::from(1u64))
]);
// ... create compressor ...
pvthfhe_compressor::sonobe::clear_dkg_agg_data();
```

### C5 — PK Aggregation

Same pattern for PK_AGG_DATA before the C5 compressor.

## Tasks
- [ ] Add pre-seed for DKG_AGG_DATA before C4 compressor
- [ ] Add pre-seed for PK_AGG_DATA before C5 compressor  
- [ ] cargo check ✅
- [ ] Verify demo-e2e c4/c5 PASS
