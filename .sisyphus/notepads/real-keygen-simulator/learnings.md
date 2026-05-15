# Learnings: real-keygen-simulator

## 2026-05-15 — Implementation

### R1: Dependencies already satisfied
- `pvthfhe-fhe` and `pvthfhe-nizk` were already non-optional deps of `pvthfhe-aggregator`
- No Cargo.toml changes needed beyond adding `rand_chacha` for deterministic RNG

### R2: Deterministic keygen + encryption helper
- Changed `keygen_share_with_session` from `OsRng` to `ChaCha8Rng::from_seed(session_id || party_id)` 
- This is correct for the simulator (single honest node) but NOT for real deployments
- Added `encrypt_share_for_recipient` that BFV-encrypts a share under a recipient's public key
- Added `prove_keygen_nizk` that generates Cyclo NIZK proofs using `CycloNizkAdapter`
- NIZK witness derived from plaintext (deterministic); matches demo pattern from `demo_nizk.rs`

### R3: Wired into generate_r1_msg
- `run()` now pre-computes all party public keys first (two-pass approach)
- `generate_r1_msg` accepts `all_pks` and uses real encryption per recipient
- NIZK proofs are per-share, serialized into a bundle via `serialize_nizk_bundle`
- Fallback to `vec![0x11, 0x22]` / `vec![0x00, 0x01]` only on encryption failure

### Conventions
- Seeded RNGs annotated with `// allow-seeded-rng: deterministic simulator`
- Domain-separated hashing for all deterministic seeds
- `params.0 = 65_537` (matches demo_nizk.rs); `params.1 = RLWE_N = 8192`

### Test results
- All 10 keygen tests pass (6 honest + 3 malicious + 1 real)
- `demo-e2e` passes: `verify: ACCEPT`, `plaintext_roundtrip: OK`

## R4: Test design patterns (2026-05-16)

### Reconstructing NIZK statements from tests
- The `CycloNizkAdapter` uses deterministic proving with a seeded RNG derived from `SHA256(session_id || dealer_id || recipient_id)`.
- To verify NIZK proofs from integration tests, we need to:
  1. Compute the session_id from public parameters (same as simulator's `session_id()`)
  2. Create a fresh `FhersBackend` with identical parameters
  3. Derive keygen shares using the same seeded RNG
  4. Reconstruct `NizkStatement` and `NizkProof`
  5. Call `adapter.verify()`
- This works because both the simulator and the test backend calls `keygen_share_with_session` with the same inputs, producing identical share bytes.

### NIZK bundle format
- `serialize_nizk_bundle`: `u16 count BE || (u32 len BE || [u8; len])*`
- Deserialization must handle edge cases (truncated bundles, count mismatches).
