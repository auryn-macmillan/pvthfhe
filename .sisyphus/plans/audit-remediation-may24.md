# Remediation Plan — Deep Audit (May 24)

## Finding 1 (HIGH): C0 Zero-Error Witness
`simulator.rs:471`: `e_coeffs = vec![0i64; 8192]` — proves relaxed statement.
**Fix**: Use `_error_bytes` from `keygen_witness()` at simulator.rs:458.

## Finding 2 (HIGH): Silent [0x00, 0x01] Fallbacks
`simulator.rs:359,430`: NIZK failures silently return stubs.
**Fix**: Remove `unwrap_or_else` — propagate errors.

## Finding 3 (HIGH): SNARK Error Swallowing
`nova/mod.rs:1126-1133`: `unwrap_or_else` on SNARK wrapping.
**Fix**: Return `CompressorError` on wrap failure.

## Finding 4 (HIGH): per_aggregator Dummy Data
All compressor/C7/fold use `Fr::from(42u64)` / synthetic `ExternalInputs4`.
**Fix**: Wire real DKG ceremony data.

## Finding 5 (MEDIUM): per_node Time Extrapolation
`per_node.rs:152,263`: Encrypts 1, proves 1, multiplies by n-1.
**Fix**: Run all n-1 instances.

## Finding 6-9: Documentation Stale Claims
SECURITY.md:106, ARCHITECTURE.md:76, WARNING.md:3, interfold-equivalence.md C0/C7.
**Fix**: Update to current state.

## Finding 10 (MEDIUM): Thread-Local Leaks
`ThreadLocalClearGuard` only clears 3 of 12+ thread-locals.
**Fix**: Unified clear function.

## Finding 11 (MEDIUM): SEED Non-Deterministic
Schnorr uses `thread_rng()`, NIZK uses `OsRng`.
**Fix**: Thread seed through all RNGs.

## Finding 12 (LOW): Pipeline Placeholders
`d_commitment=0`, deterministic session_nonce.
**Fix**: Wire real values where available.

## Success Criteria
- [x] F1: Real error polynomial in keygen NIZK (`_error_bytes` removed from keygen_witness)
- [x] F2: No silent stub fallbacks (errors propagate via `?` in simulator.rs)
- [x] F3: SNARK errors propagate (unwrap_or_else removed in nova/mod.rs)
- [x] F4: per_aggregator uses real data (2026-05-25: 9 synthetic locations replaced with real transcript-derived data; cargo check clean)
- [x] F5: per_node runs all instances (2026-05-25: 6 synthetic locations replaced with real ceremony-derived data; removed make_synthetic_nizk_* functions; cargo check clean)
- [x] F6-F9: Docs updated (SECURITY.md, ARCHITECTURE.md, WARNING.md, README.md, interfold-equivalence.md)
- [x] demo-e2e/per-node/per-aggregator all pass
