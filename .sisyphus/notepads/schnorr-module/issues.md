# Issues - Schnorr Module

## Circular dependency prevents compressor import
**Problem**: Adding `pvthfhe-compressor` as a dependency of `pvthfhe-nizk` creates a circular dependency cycle:
  pvthfhe-nizk → pvthfhe-compressor → pvthfhe-aggregator → pvthfhe-cyclo → pvthfhe-nizk

**Mitigation**: Used `light-poseidon` directly (already a dep of nizk) instead of `pvthfhe_compressor::witness::hash_all_coeffs`. The `Poseidon::new_circom(n).hash()` pattern matches the existing convention in `sigma.rs`.

**Impact**: The canonical sponge-based hashing from compressor (`hash_all_coeffs` with rate=4) differs from the one-shot `new_circom(6).hash()` used here. This should be reconciled when the dependency cycle is resolved (e.g., by extracting hash utilities into a shared crate).

**Todo**: Future work should extract `hash_all_coeffs` into a shared utility crate (e.g., `pvthfhe-poseidon`) to avoid the cycle.
