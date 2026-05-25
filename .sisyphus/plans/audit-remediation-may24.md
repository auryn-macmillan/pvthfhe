# Remediation Plan — Deep Audit (May 24)

## Finding 1 (HIGH): C0 Zero-Error Witness
`simulator.rs:471`: `e_coeffs = vec![0i64; 8192]` — proves relaxed statement.
**Fix**: Use `_error_bytes` from `keygen_witness()` at simulator.rs:458.

## Finding 2 (HIGH): Silent [0x00, 0x01] Fallbacks
`simulator.rs:359,430`: NIZK failures silently return stubs.
**Fix**: Remove `unwrap_or_else` — propagate errors.

## Finding 3 (HIGH): SNARK Error Swallowing
`sonobe/mod.rs:1126-1133`: `unwrap_or_else` on SNARK wrapping.
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
- [ ] F1: Real error polynomial in keygen NIZK
- [ ] F2: No silent stub fallbacks
- [ ] F3: SNARK errors propagate
- [ ] F4: per_aggregator uses real data
- [ ] F5: per_node runs all instances
- [ ] F6-F9: Docs updated
- [ ] demo-e2e/per-node/per-aggregator all pass
