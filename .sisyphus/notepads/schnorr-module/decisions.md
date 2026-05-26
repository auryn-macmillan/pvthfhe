# Decisions - Schnorr Module

## Use light-poseidon directly instead of compressor's hash_all_coeffs
**Date**: 2026-05-19
**Rationale**: Circular dependency prevents importing pvthfhe-compressor. light-poseidon is already a dependency of pvthfhe-nizk and is used throughout the crate (e.g., sigma.rs). This is consistent with the existing codebase patterns.

## Not adding pvthfhe-compressor to Cargo.toml
**Date**: 2026-05-19
**Rationale**: Would create circular dep: nizk → compressor → aggregator → cyclo → nizk. The plan's assumption of "No circular dependency (compressor does not depend on nizk)" is technically true (compressor doesn't directly depend on nizk) but the transitive dependency chain creates a cycle.

## Import corrections from plan
**Date**: 2026-05-19
**Corrections needed from plan code**:
- Added `use ark_ec::{AffineRepr, PrimeGroup};` for `.generator()`, `.into_group()`, `.x()`, `.y()`
- Added `use ark_ff::BigInteger;` for `.to_bytes_le()`
- Used `use rand_core::SeedableRng;` in tests for `.seed_from_u64()`
