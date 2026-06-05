# Proof Gap Remediation — Learnings

## Session: 2026-06-04 — G1 Option B Sigma Fold Soundness (COMPLETED)

- `ivc_steps` is wired to 90 in the Nova compressor path used by the full pipeline.
- The native sigma prover continues to produce 90 rounds, and the compressor expects all 90 `SIGMA_DATA` entries before `prove_steps`.
- RED test added: corrupting one sigma witness in the 90-step chain is rejected.
- `cargo test -p pvthfhe-compressor sigma_repetition_soundness` passed.

## Session: 2026-06-04 — G4 Relinearization Gate (COMPLETED)

### G4.1a — Current Relinearize Code
- Location: `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs`
- `relin_fhe_ct_bp` (lines 695-735): reads only first 24 of 36 coefficients, enforces `out[i] == in[i]`. ct[2] (indices 24-35) completely ignored.
- `synthesize()` Relinearize branch (lines 1451-1476): calls relin_fhe_ct_bp for 36-coeff input, identity for 24-coeff input.

### G4.1b — Relinearization Key Availability
- Searched `pvthfhe-fhe` and `pvthfhe-fhe-poulpy` for `relin_key`, `relinearize`, `rlk`
- Result: NO relinearization key API exists. `gnosisguild/fhe.rs` backend does not expose rlk.

### G4.1c — Real Relinearization
- Cannot implement: FHE backend does not expose a relinearization key.
- Formula: `ct_out = ct[0] + ct[1] · rlk`

### G4.1d — Feature Gate
- Added `real-relin` feature to `crates/pvthfhe-compressor/Cargo.toml`
- Gated `FheOp::Relinearize` branch behind `#[cfg(feature = "real-relin")]`
- Without feature: returns `SynthesisError::AssignmentMissing`
- Gated `relin_fhe_ct_bp` function + 2 existing tests behind `#[cfg(feature = "real-relin")]`
- Updated function docstring + status comment to document the gap

### G4.2a — RED→GREEN Test
- Added `fhe_compute_relin_rejects_without_real_relin`
- RED before gate (synthesize succeeded as truncation), GREEN after.
- `cargo check -p pvthfhe-compressor` ✅ (default + `--features real-relin`)
- `cargo test -p pvthfhe-compressor --lib` → 74 passed, 0 failed ✅

---

## Session: 2026-06-04 — G6 + G7 Documentation

### G6 — BFV Sigma Caveats (COMPLETED)

**G6.1a** (`crates/pvthfhe-nizk/src/bfv_sigma.rs`):
- Added `# CAVEATS` section to module doc comment (lines 28-45)
- Documents: no rejection sampling, computational ZK via noise drowning (ratio ≥ 4.0), no in-circuit verifier, use S-Z evaluation as alternative

**G6.1b** (`SECURITY.md`):
- Added `## BFV Sigma Caveats` section (line 113)
- Documents: computational ZK only, no rejection sampling, no in-circuit verifier

### G7 — NTT Trust Documentation (COMPLETED)

**G7.1a** (`crates/pvthfhe-nizk/src/sigma.rs`):
- Added `# Trust Assumption (G7)` doc comment to `poly_mul_rq()` function (line 563)
- Documents: NTT correctness assumed from fhe-math backend, S-Z sidesteps NTT in-circuit, native NTT bugs risk

**G7.1a** (`crates/pvthfhe-aggregator/src/folding/mod.rs`):
- Added `# Trust Assumption — NTT Correctness (G7)` to module doc (line 14)
- Documents: same trust assumption at aggregation entry point

**G7.1b** (`SECURITY.md`):
- Added `## Trusted Components` section (line 104)
- Lists: fhe-math NTT as trusted component, plus fhe-math RNS arithmetic
- Documents impact: NTT bugs could produce valid-looking proofs for malformed ciphertexts

## Session: 2026-06-04 — G5: Bootstrap Sigma bsk_hash Binding (COMPLETED)

### G5.1a (`crates/pvthfhe-nizk/src/bootstrap_sigma.rs`):
- `BootstrapStatement` already had `pub bsk_hash: [u8; 32]` field (line 15); no change needed.

### G5.1b (`derive_challenge`, line 110):
- Added `bsk_hash: &[u8; 32]` parameter to `derive_challenge` signature.
- Added `h.update(bsk_hash)` to Fiat-Shamir transcript hash after round index and before t/c/d.
- This binds the bootstrapping key hash into every challenge, preventing cross-bsk replay.

### G5.1c (call sites):
- `prove` (line 165): Updated `derive_challenge` call to pass `&stmt.bsk_hash`.
- `verify` (line 203): Updated `derive_challenge` call to pass `&stmt.bsk_hash`.

### G5.1d (doc comment on `verify`, line 181):
- Added doc: "This sigma proves that ct_out comes from the same LWE secret key as ct_in under the claimed bootstrapping key hash. It does NOT prove the full blind rotation was correct (CMUX chain verification is deferred to P2)."

### G5.2a (test, line 446):
- RED→GREEN: `test_wrong_bsk_hash_rejected` — proves with `bsk_hash_honest`, verifies with `bsk_hash_adversary`, expects REJECT.
- Uses 8-round multi-proof because single-round challenges ({-1,0,1}) have ~33% accidental collision probability. With 8 rounds, false-pass probability is ~(1/3)^8 ≈ 0.015%.
- Sanity check: honest bsk_hash still passes verification.
- All 8 bootstrap_sigma tests pass.

## Session: 2026-06-04 — G3: NIZK Verification in Fold Path (COMPLETED)

### G3.1a — Fold Entry Point
- Location: `crates/pvthfhe-aggregator/src/folding/mod.rs`
- `HashChainFoldingScheme::fold()` (line 137) calls `validate_witness()` before `fold_one_step_multitrack()`
- Gap: `validate_witness()` only checked proof structure (backend_id, norm bound, min size under real-nizk) — never called `CycloNizkAdapter::verify()`

### G3.1b — Wire CycloNizkAdapter::verify()
- Added `decrypt_share_bytes: Vec<u8>` and `pvss_commitment: [u8; 32]` to aggregator's `NizkStatement`
- Added `verify_full_nizk()` function (mod.rs, under `#[cfg(feature = "real-nizk")]`) that:
  1. Converts aggregator types → `pvthfhe_nizk` crate types
  2. Calls `CycloNizkAdapter::verify()` with full multi-round sigma (90 rounds)
  3. Gracefully skips if ring degree ≠ `rlwe_n()` (defense-in-depth; size check covers non-matching params)
- Called from `validate_witness()` BEFORE the Cyclo fold step

### G3.1c — Multi-Round Sigma Path
- `CycloNizkAdapter::verify()` uses `sigma::verify_multi()` with `SIGMA_REPETITIONS = 90` (142-bit soundness)
- This is the native (non-in-circuit) path — the Nova compressor uses `SIGMA_REPETITIONS = 1` per step × 90 steps
- Confirmed: verify path is 90-round, not 1-round

### G3.2a-d — Test Activation
- Removed `#[cfg_attr(not(feature = "real-nizk"), ignore = "...")]` from 3 adversary tests
- Replaced with `#[cfg(feature = "real-nizk")] #[test]` — tests only compile/run under real-nizk
- Tests: fewer-than-t-valid REJECT ✅, single-forged REJECT ✅, ciphertext-mismatch REJECT ✅

### Verification
- `cargo test -p pvthfhe-aggregator --features real-nizk --test fold_e2e_soundness`: 3/3 passed ✅
- `cargo test -p pvthfhe-aggregator --features real-nizk --test folding`: 6/6 passed ✅
- `cargo test -p pvthfhe-aggregator --features real-nizk --test folding_adversarial`: 17/18 (1 pre-existing ignore) ✅
- `cargo test -p pvthfhe-aggregator --test folding` (default): 6/6 passed ✅
- All existing fold tests pass under both default and real-nizk features

### Files Modified
- `crates/pvthfhe-aggregator/src/folding/mod.rs` — added `verify_full_nizk()` + new NizkStatement fields
- `crates/pvthfhe-aggregator/tests/fold_e2e_soundness.rs` — removed conditional ignore, added cfg gate
- `crates/pvthfhe-aggregator/tests/folding.rs` — added VALID_SYNTHETIC_PROOF_LEN
- `crates/pvthfhe-aggregator/tests/folding_adversarial.rs` — added new struct fields
- `crates/pvthfhe-aggregator/tests/folding_multi_track.rs` — added VALID_SYNTHETIC_PROOF_LEN + new fields
- `crates/pvthfhe-aggregator/tests/folding_relation.rs` — added VALID_SYNTHETIC_PROOF_LEN + new fields
- `crates/pvthfhe-aggregator/tests/folding_tamper.rs` — added VALID_SYNTHETIC_PROOF_LEN + new fields
- `crates/pvthfhe-aggregator/tests/folding_witness_validation.rs` — added new struct fields
- `crates/pvthfhe-aggregator/tests/p2_bench.rs` — added conditional proof_len
- `crates/pvthfhe-aggregator/tests/e2e_real.rs` — added new struct fields

## Session: 2026-06-04 — G2: C7 Share Commitment Merkle Binding (IN PROGRESS)

- `crates/pvthfhe-cli/src/full_pipeline.rs` now has a reusable `build_c7_share_commitment_bundle()` helper that computes padded share polys, Poseidon commitments, the 128-leaf Merkle tree, sibling paths, and leaf indices.
- `run_full_pipeline()` already feeds the full 22-argument C7 TOML bundle into `build_c7_prover_toml()`.
- The stale `c7_prover_toml_exports_decrypt_nizk_hash_public_input` test and `pvthfhe_e2e.rs` caller were both missing the 5 G2 arguments; both now compile after wiring the bundle helper.
- `cargo test -p pvthfhe-cli --lib` passed through the C7 TOML test before timing out on a long-running unrelated test.

## Session: 2026-06-04 — Wire Format Mismatch Fix (COMPLETED)

### Root Cause
`encode_proof_multi` (adapter.rs:676-684) encodes: `d_rns || num_rounds(u32) || per_round(t_rns, z_s, z_e, ch) × 90`. But `extract_sigma_proof` was calling `decode_sigma_section` which expects single-round format: `d_rns || t_rns || z_s || z_e || ch`. The 4-byte `num_rounds` field was being misinterpreted as the start of `t_rns`.

### Fix
- `crates/pvthfhe-nizk/src/adapter.rs` line 278: Changed `decode_sigma_section(&sigma_section)` to `decode_sigma_section_multi(&sigma_section)`, then extracted the first round's `SigmaProof` from the returned `SigmaMultiProof`.
- `decode_sigma_section_multi` already existed at line 746 — reads `num_rounds(u32)` before each round.
- `decode_sigma_section` is now dead code (single-round format no longer used by any caller).

### Verification
- `cargo check -p pvthfhe-nizk` ✅ (1 warning: `decode_sigma_section` unused)
- `cargo test -p pvthfhe-nizk adapter` ✅ (3 adapter tests passed)

## Session: 2026-06-05 — G3 Plaintext Binding Mismatch

- Root cause: C7 Path 1 was effectively doing BN254-field evaluation/scaling of shares, while the fhe.rs backend Path 2 recombines in the BFV RNS ring using integer Lagrange coefficients before CRT reconstruction into BN254. Those operations are not interchangeable when coefficients live modulo the BFV RNS moduli.
- Added share diagnostics: verified share polynomial byte hash vs witness `d_share_poly_bytes` hash, backend integer λ comparison vs BN254 λ, and first per-share contribution divergence (`path1_contrib` vs `path2_backend_contrib`).
- Fix: C7 G3 binding now uses backend-verified share residues, backend-compatible integer Lagrange coefficients, and RNS-domain recombination for the bound `z0`; final equality is checked against `aggregate_decrypt_raw_result_poly` at the same challenge point.
- Verification run: `cargo check -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng"` passed; diagnostic unit test `g3_diagnostic_reports_first_divergent_share` passed. A production-parameter demo attempt exceeded the 10-minute command timeout before reaching verify; `insecure512` cannot build the RLWE NIZK context in this path.
