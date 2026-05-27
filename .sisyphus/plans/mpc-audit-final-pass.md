# Final MPC Audit Pass — Remediation Plan

**Status**: PLAN
**Date**: 2026-05-27

## Findings

### H1 — compute_sz_gamma: Prover can modify z_s/z_e after seeing gamma
**File**: `crates/pvthfhe-nizk/src/sigma.rs:795-809`
**Issue**: The Schwartz-Zippel challenge derivation hashes `t_rns`, `ch`, `session_id`, `party_id` but NOT `c_rns`, `d_rns`, `z_s`, `z_e`. A prover can modify `z_s`/`z_e` after seeing gamma to make the S-Z evaluation pass.
**Fix**: Add `c_rns`, `d_rns`, `proof.z_s`, `proof.z_e` to the hash input. Use per-point domain separators (`b"gamma0"`, `b"gamma1"`, `b"gamma2"`) instead of slicing bytes from a single digest.
**Effort**: ~15 min

### M1 — Single SHA-256 digest without per-point separation
**File**: `crates/pvthfhe-nizk/src/sigma.rs:805-807`
**Issue**: Bytes 8-16 of the 32-byte SHA-256 digest are SKIPPED. All 3 gammas from one hash call.
**Fix**: Derive each gamma with separate labels: `h.update(b"gamma0"); let g0 = h.finalize(); h.update(b"gamma1"); let g1 = h.finalize();` etc.
**Effort**: ~5 min

### M2 — PipelineReport doesn't cover C1/C4/C5 Nova failures
**File**: `crates/pvthfhe-cli/src/full_pipeline.rs:2124`
**Issue**: `all_verifications_passed: noir_passed` only covers C7 UltraHonk. C1/C4/C5 Nova IVC verification failures are logged but don't affect the final PASS/ACCEPT verdict.
**Fix**: Collect all Nova verification results into a `nova_all_passed` flag and AND it with `noir_passed`.
**Effort**: ~20 min

## Tasks
- [x] H1: Hash c_rns, d_rns, z_s, z_e into compute_sz_gamma
- [x] M1: Derive 3 gammas with per-point domain separators
- [x] M2: Include Nova verification in PipelineReport all_passed
- [x] Verify: `cargo check` + `just demo-e2e` ACCEPT
**Status**: COMPLETE

## Success Criteria
- [ ] `cargo check` = 0 errors
- [ ] `just demo-e2e` runs with ACCEPT
- [ ] No new surrogates or dummy proofs
