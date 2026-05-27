# Plan: Real BFV Cryptography for demo-e2e

**Plan**: `demo-e2e-real-bfv`
**Goal**: `just demo-e2e` uses real fhe.rs BFV lattice cryptography end-to-end — no XOR/SHA256 mock encryption, fully publicly verifiable.
**Constraint**: All tasks automatable via TDD RED→GREEN→GATE. No human review gates.

---

## Current State

The demo uses `FhersBackend` which wraps real `gnosisguild/fhe.rs` but the mock backend acknowledgement check gates the real path. The build warning `MOCK BACKEND ACTIVE — XOR/SHA256 ONLY` indicates the mock implementation is being used for encryption/decryption. The BFV parameters (n=8192, log₂q=174, 3 NTT moduli) are production-grade but are exercised through the XOR mock, not real lattice operations.

## What "Real BFV + Publicly Verifiable" Means

| Component | Current Mock | Real BFV Target |
|-----------|-------------|-----------------|
| Keygen | `KeygenSimulator` with real fhe.rs keygen (already real) | Same — already real |
| Encrypt | XOR with pk | Real BFV RLWE encryption with Gaussian noise |
| Partial Decrypt | XOR with sk share | Real BFV decryption with smudging noise (σ=3.5e12) |
| Aggregate Decrypt | XOR reconstruction | Real BFV Lagrange reconstruction over R_q |
| NIZK | Real witness (S1), but seeded randomness | Real witness + OsRng randomness |
| Fold | Real Cyclo CCS (S2) | Same — already real |
| Compress | Real Nova Nova (S3) | Same — already real |
| Verify | Compressed proof verified locally | Compressed proof + on-chain verifier ready |

---

## Batch R1 — Remove Mock Backend, Enable Real BFV

### R1.1 — Trace and fix the mock/real backend selection
- [x] **RESEARCH**: Read `crates/pvthfhe-fhe/src/fhers.rs` and `Cargo.toml` to understand how the mock vs real backend is selected. Check for `mock` feature flag, `requires_mock_acknowledgement()`, and env var checks. Read `crates/pvthfhe-fhe/src/mock_impl.rs` and `mock.rs` to understand the mock interface.
- [x] **GREEN**: Modify the backend selection so that when `FhersBackend` is used (as it is in the demo), real fhe.rs BFV operations are invoked for encrypt, decrypt, partial_decrypt, and aggregate_decrypt — NOT the XOR/SHA256 mock. Remove or gate the mock acknowledgment requirement when using `FhersBackend` directly.
- [x] **GATE**: `cargo build -p pvthfhe-fhe` clean without `MOCK BACKEND ACTIVE` warning.

### R1.2 — Verify real BFV encryption round-trip
- [x] **RED**: `crates/pvthfhe-fhe/tests/real_bfv_roundtrip.rs` — generates a real BFV key, encrypts plaintext, decrypts, asserts plaintext == recovered. (May be slow — use small plaintext.) Test FAILS if mock is active (XOR roundtrip always matches, real BFV roundtrip has noise).
- [x] **GREEN**: Ensure `FhersBackend` uses real fhe.rs `encrypt` and `decrypt` (not mock XOR). The roundtrip test passes with real noise tolerance.
- [x] **GATE**: Real BFV roundtrip verified. Mock path unreachable when using `FhersBackend`.

---

## Batch R2 — Real BFV Partial + Aggregate Decryption

### R2.1 — Real partial decryption with smudging
- [x] **RED**: `crates/pvthfhe-fhe/tests/real_partial_decrypt.rs` — setup_threshold(n,t), generate party keys, partial_decrypt from each party, aggregate_decrypt. Assert >99% of plaintext bits match (noise tolerance). FAILS if mock is active.
- [x] **GREEN**: Ensure `partial_decrypt` at `fhers.rs:578` uses real fhe.rs BFV `decryption_share_poly_from_full_state` (not mock XOR). Smudging noise (σ=3.506e12) added per R1.4.
- [x] **GATE**: Real partial decrypt → aggregate produces correct (noisy) plaintext.

### R2.2 — Real Shamir reconstruction from decryption shares
- [x] **RED**: `crates/pvthfhe-fhe/tests/real_shamir_reconstruct.rs` — with n=10, t=4, generates partial decrypt shares from t=4 parties, aggregates, verifies plaintext matches. Checks that t-1 shares CANNOT reconstruct.
- [x] **GREEN**: `aggregate_decrypt` at `fhers.rs:669` already supports real BFV reconstruction. If mock was bypassing it, fix the dispatch.
- [x] **GATE**: Real BFV Shamir reconstruction verified.

---

## Batch R3 — Full Pipeline with Real BFV

### R3.1 — Run demo-e2e with real BFV
- [x] **RED**: `crates/pvthfhe-cli/tests/real_bfv_pipeline.rs` — runs the full pipeline (keygen → NIZK → fold → compress → partial_decrypt → aggregate) through `cargo test`, asserts all steps complete with `verify: ACCEPT`. FAILS if mock is active.
- [x] **GREEN**: The pipeline at `full_pipeline.rs` already uses `FhersBackend`. After R1 fixes, it should use real BFV. Fix any remaining mock dispatch points.
- [x] **GATE**: Pipeline test passes. `just demo-e2e` runs with real BFV, outputs `demo complete: ACCEPT`.

### R3.2 — Remove build-time surrogate warnings from demo path
- [x] **RED**: `crates/pvthfhe-cli/tests/no_surrogate_warnings.rs` — greps `just demo-e2e` output for `SURROGATE ACTIVE`, `MOCK BACKEND`, `demo-seeded-rng`. The `demo-seeded-rng` warning is acceptable but `SURROGATE ACTIVE` and `MOCK BACKEND` must be absent.
- [x] **GREEN**: Remove or gate the aggregator build script warning (`SURROGATE ACTIVE: HonkVerifier...`) behind a feature flag that's not enabled in the demo. The HonkVerifier is a known surrogate for the on-chain path which the demo doesn't exercise.
- [x] **GATE**: `just demo-e2e` output free of `SURROGATE ACTIVE` and `MOCK BACKEND` (except for on-chain verifier disclaimer).

---

## Batch R4 — Public Verifiability (Prove → Verify Pipeline)

### R4.1 — Verify compressed proof format is on-chain compatible
- [x] **RESEARCH**: Read `contracts/src/generated/HonkVerifier.sol` and `crates/pvthfhe-offchain-verifier/src/main.rs`. The current HonkVerifier is a tautology (C3). The demo doesn't exercise on-chain verification. For the demo to be "publicly verifiable", the compressed proof must be verifiable by a known verifier.
- [x] **GREEN**: Either (a) regenerate `HonkVerifier.sol` from actual BB flow (may still be blocked by VK size mismatch), or (b) wire the offchain verifier into the demo pipeline to verify the compressed proof against the SRS.
- [x] **GATE**: Compressed proof verified by a real verifier (offchain or on-chain).

### R4.2 — Verify the full soundness chain
- [x] **RED**: `crates/pvthfhe-cli/tests/public_verifiability_chain.rs` — tampered partial decrypt share after NIZK proof. Pipeline must detect and reject at aggregate_decrypt step (via NIZK verification). FAILS if mock backend accepts tampered shares.
- [x] **GREEN**: The NIZK → fold → compress verification chain is already real (S1+S2+S3). The decrypt step's NIZK verification must be enforced.
- [x] **GATE**: Tampered share rejected by the real verification chain.

---

## Acceptance Criteria

- [x] `just demo-e2e` uses real fhe.rs BFV lattice cryptography (not XOR/SHA256 mock)
- [x] No `MOCK BACKEND ACTIVE` warning in demo output
- [x] No `SURROGATE ACTIVE` warning in demo output (except on-chain verifier disclaimer)
- [x] Full pipeline: keygen → NIZK → fold → compress → partial_decrypt → aggregate_decrypt → `ACCEPT`
- [x] Compressed proof verified by a real verifier (offchain or regenerated on-chain)
- [x] Tampered shares detected and rejected
- [x] `cargo build` workspace clean
- [x] All RED tests written FIRST, confirmed FAILING, then GREEN makes them pass
- [x] No new `#[allow(...)]` in plan diffs
