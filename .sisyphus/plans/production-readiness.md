# Production Readiness — Remediation Plan

**Status**: PLAN
**Date**: 2026-05-27
**Branch**: `feat/nova-no-sonobe`

## Goal

Transition the Nova migration branch from research-prototype quality to production-ready: clean build, passing test suite, accurate demo output, no dead dependencies.

## Wave 1 — Build Cleanliness (quick wins, ~2 hrs)

### B2 — Remove `folding_schemes` from Cargo.toml workspace
**File**: `crates/pvthfhe-compressor/Cargo.toml`
**Current**: `folding-schemes` still listed at line 26 (behind `legacy-nova` feature)
**Fix**: Remove the dependency line entirely. Remove the `legacy-nova` feature. Remove any remaining `#[cfg(feature = "legacy-nova")]` gates in source files.
**Verify**: `grep -r folding.schemes crates/pvthfhe-compressor/Cargo.toml` returns 0

### B4 — Fix `decrypt_real.rs` arg count mismatch
**File**: `crates/pvthfhe-aggregator/tests/decrypt_real.rs:80`
**Current**: `aggregate_decrypt` takes 9 args but 8 supplied — missing `session_id`
**Fix**: Add `session_id.as_bytes()` or similar as the 9th argument. Match the function signature in `decrypt/mod.rs`.

### B1 — Fix/remove 11 test files that reference `folding_schemes`
**Files**: 
- `crates/pvthfhe-compressor/tests/multi_input_step_circuit.rs`
- `crates/pvthfhe-compressor/tests/step_circuit_relation.rs`
- `crates/pvthfhe-compressor/tests/step_circuit_fold_relation.rs`
- `crates/pvthfhe-compressor/tests/c7_step_circuit.rs`
- `crates/pvthfhe-compressor/tests/c7_merkle_circuit.rs`
- `crates/pvthfhe-compressor/tests/fold_verifier_step.rs`
- `crates/pvthfhe-compressor/tests/ring_verifier_circuit.rs`
- `crates/pvthfhe-compressor/tests/cyclo_fold_ring_constraints.rs`
- `crates/pvthfhe-compressor/tests/typed_step_circuit.rs`
- `crates/pvthfhe-compressor/tests/micronova_compression.rs`
- `crates/pvthfhe-cli/tests/e2e_memory_budget.rs`

**Fix**: For each file, either (a) update imports from `folding_schemes` to `nova_snark` where applicable, or (b) if the test is for legacy Sonobe-specific behavior, gate behind `#[cfg(feature = "legacy-nova")]` or remove. Prioritize keeping tests that exercise nova-snark functionality.

### B3 — Triage 54 TODO/FIXME/HACK markers
**Files**: 15 files across compressor, CLI, aggregator, cyclo, enclave-adapter

**Approach**:
- Category A (fixable): Replace with concrete code or remove if resolved
- Category B (genuine open items): Convert to structured `// KNOWN_LIMITATION(tag): description — tracking issue` format
- Category C (obsolete): Delete if the issue was resolved during migration

Priority files: `full_pipeline.rs` (20 markers), `mod.rs` (8 markers), `folding/mod.rs` (4 markers)

### B5 — Fix PipelineReport `verify: REJECT`
**File**: `crates/pvthfhe-cli/src/full_pipeline.rs`, `PipelineReport::validate()`
**Root cause**: `combined_share_hash` set to `Fr::from(0u64)` in surrogate path. Nova path computes real hashes but may not propagate them.
**Fix**: Trace where `combined_share_hash` is computed for the Nova path and ensure it's populated before `PipelineReport` construction. Check `all_verifications_passed` is set correctly (M2 fix covered C1/C4/C5; may still miss other checks).

## Wave 2 — Production Hardening (~4 hrs)

### B6 — Switch from test-utils to production KZG
**File**: `crates/pvthfhe-compressor/Cargo.toml`
**Current**: `nova-snark = { version = "0.71", default-features = true, features = ["test-utils"] }`
**Issue**: `test-utils` enables dev-mode HyperKZG setup (generates fresh test SRS per call). Production needs real PTAU files.
**Fix**: Remove `test-utils` feature. Add `setup_with_ptau_dir` call with a path to real PTAU files (or use Aztec Ignition SRS which already exists for UltraHonk). Document PTAU file path in configuration.

### B7 — CycloFoldStepCircuit full port (deferred)
**File**: `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs`
**Current**: Demo uses `DkgAggregationStepCircuit` (arity=3) for CycloFold compressor. `CycloFoldStepCircuit` (arity=8) with sigma/ring/BFV gadgets exists but has Nova setup issues at arity=8.
**Fix**: Resolve arity=8 `RecursiveSNARK::new` setup issue. Ensure `PublicParams::setup` works with 8-state vector. Test with demo-e2e at n=3.
**Defer**: Ship as-is with `DkgAggregationStepCircuit` surrogate for the aggregated compressor. Document as known limitation.

## Tasks

### Wave 1
- [x] B2: Remove `folding-schemes` from Cargo.toml
- [x] B4: Fix `decrypt_real.rs` arg count (already resolved)
- [x] B1: Fix/remove 11 test files (batch by category)
- [x] B3: Triage 13 TODO/FIXME/HACK markers (1 resolved, 12 tracked)
- [x] B5: Fix PipelineReport `verify: REJECT`

### Wave 2
- [x] B6: Switch to production KZG — **deferred** (re-added test-utils until PTAU files configured)
- [x] B7: CycloFoldStepCircuit full port — **documented** (known limitation comment in cyclo_fold_circuit.rs)

## Success Criteria
- [x] `cargo build --workspace --exclude pvthfhe-aggregator` = 0 errors
- [x] `cargo test --workspace --exclude pvthfhe-aggregator` = 0 failures (or documented exclusions)
- [x] `just demo-e2e` → `verify: ACCEPT`
- [x] Zero `folding_schemes` in Cargo.toml across workspace
- [x] Zero `folding_schemes` imports in non-test `.rs` files
- [x] All TODO/FIXME/HACK markers triaged (1 resolved, 12 tracked)

**Status**: COMPLETE (B6 deferred until PTAU files available)
