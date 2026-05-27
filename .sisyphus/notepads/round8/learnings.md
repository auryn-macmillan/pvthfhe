# Round8 Batch C — Learnings

## C.1: bfv_sigma defense-in-depth
- Added `debug_assert!(!binding_data.is_empty(), ...)` in `derive_challenge()` at line ~392.
- Placed after existing comment block, before hashing begins.
- Uses `debug_assert!` (not `assert!`) to keep release-build performance unchanged.

## C.2: dealer_index truncation fix
- Replaced `u32::try_from(stmt.dealer_index).unwrap_or(u32::MAX)` with direct `as u32` cast.
- Added `debug_assert!` to verify the cast is lossless for realistic committee sizes.
- Removed the old TODO(C5) comment since the fix is applied.

## C.3: Wire poly_eval in full_pipeline.rs
- Replaced inline `s.iter().rev().fold(Fr::zero(), |acc, &c| acc * r + c)` with `eval_poly_bn254(s, r)`.
- Key insight: `eval_poly_bn254` treats coeffs[0] as highest-degree (doc says Σ coeffs[i] * r^{N-1-i}), which is identical to what the inline `.rev().fold()` computes.
- Added `use pvthfhe_compressor::poly_eval::eval_poly_bn254;` import within the function scope.

## C.4: Deterministic Nova benchmarks
- Replaced all 3 `let mut rng = OsRng;` with `ChaCha20Rng::from_seed(self.srs_hash)`.
- `srs_hash` is a `[u8; 32]` field on `NovaCompressor`, derived from epoch_hash at construction.
- `ChaCha20Rng` and `SeedableRng` were already imported. Removed now-unused `pvthfhe_rng::OsRng` import.
- `rand_chacha = "0.3"` was already in Cargo.toml — no dependency changes needed.

## C.5: RefCell safety comment
- Added SAFETY comment documenting thread_local! + RefCell invariants.
- Clarifies that `thread_local!` provides per-thread isolation and `RefCell` prevents re-entrant borrowing within a thread.

## C.6: Skipped
- Dual timing tracking consolidation is deferred. No code change.
