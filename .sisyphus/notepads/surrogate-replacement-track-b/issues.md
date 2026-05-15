# Issues — Surrogate Replacement Track B (L0+L1)

## 2026-05-15

### Issue 1: Norm enforcement mismatch for real FHE keys
- **Problem**: The cyclo fold path (`fold.rs:159-166`) enforces witness norm ≤ 102
  (`per_step_norm_budget = 1024/10`). Real BFV secret key coefficients have norms ~10^13.
- **Current workaround**: Witness values are norm-bounded (<101) in `build_cyclo_witness`.
- **Resolution needed**: Layer 3 (L3.3) — replace approximated z_s/z_e with actual masked
  values from the NIZK sigma proof, which have controlled norms. The raw secret key coefficients
  should never enter the fold path directly.
- **Tracking**: Surrogate #10 (CCS witness) is partially addressed; full resolution depends on L3.

### Issue 2: CCS matrix is large (2.1 MB)
- **Problem**: The 256×256 CCS matrix (2.1 MB per instance) adds significant memory pressure.
  With 10 parties, that's ~21 MB just for matrix data.
- **Impact**: Acceptable for n=10 demo; may cause issues at n=128+ scaling benchmarks.
- **Resolution needed**: Optimize matrix encoding (sparse format, or use Cyclo's R_q domain
  CCS which uses polynomial-ring arithmetic natively instead of field-element expansion).
- **Tracking**: Performance optimization deferred to Layer 5.

### Issue 3: `red_3_records_all_full_pipeline_phases` test was already failing
- **Problem**: This RED test failed before L0+L1 changes (different failure: nizk_verify count
  mismatch). It continues to fail after changes (norm bound exceeded).
- **Status**: Pre-existing RED test, not a regression. Needs attention in a separate task.
- **Tracking**: The test exercises the full pipeline with seed=0 (which maps to OsRng),
  causing nondeterministic behavior. Fix requires deterministic witness generation
  or relaxed test assertions.

### Issue 4: d (public statement) generation is heuristic
- **Problem**: The public statement `d` for the ring equation is derived from NIZK statement
  via SHA-256 expansion to 256 coefficients (heuristic, not protocol-specified).
- **Impact**: The ring equation check is structurally correct but the values of `d` are not
  cryptographically bound to the protocol state.
- **Resolution needed**: Layer 3 (L3.3) — derive `d` from actual Cyclo commitment parameters.
