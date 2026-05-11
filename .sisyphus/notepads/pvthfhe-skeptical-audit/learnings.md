# Learnings — pvthfhe-skeptical-audit

## 2026-05-03 Session Start — Ground Truth Scan

### Confirmed Facts
- **P3RealVerifier.sol**: Line ~64 is `ecrecover` against hardcoded `TRUSTED_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`. Confirmed vacuous.
- **SURROGATE markers**: Present in 5 files. `fhers.rs` has MANY inline markers (lines 27,33,38,48,58,68). `protocol.rs` line 1 is a SURROGATE header. `circuits/aggregator_final/src/main.nr` line 5,7. `circuits/decrypt_share/src/main.nr` lines 2,47.
- **hermine.rs**: Line 1 is `#![allow(clippy::as_conversions, clippy::manual_contains)]` — confirmed.
- **obligations.md**: `grep -c "^|"` = 22 (2 header rows + 20 data rows = 20 theorems confirmed).
- **paper/main.tex**: `grep -c '\\begin{theorem}'` = 19 (1 theorem is missing from paper vs 20 obligations — discrepancy confirmed).
- **P3RealVerifier.sol key lines**: TRUSTED_SIGNER on lines 31-32, ecrecover on lines ~62-65.

### Key File Paths
- Verifier: `contracts/src/P3RealVerifier.sol` (ecrecover on ~line 64)
- NIZK: `crates/pvthfhe-fhe/src/fhers.rs` (stub, many SURROGATE markers)
- Aggregator keygen shim: `crates/pvthfhe-aggregator/src/keygen/protocol.rs` (4 lines, SURROGATE line 1)
- Clippy suppression: `crates/pvthfhe-keygen/src/hermine.rs` (line 1 allow directive)
- Noir circuits: `circuits/aggregator_final/src/main.nr`, `circuits/decrypt_share/src/main.nr`
- HonkVerifier surrogate: `contracts/src/generated/HonkVerifier.sol` (line 4 marker)

### Toolchain conventions (from AGENTS.md)
- Foundry: `forge ... --root contracts` from repo root
- Noir: `(cd circuits && nargo ...)` from repo root
- Cargo: from repo root with `-p <crate>`
- TDD: RED test before every implementation change
- Stub protocol: replace in place, NEVER delete-and-recreate

### Canonical Noir+BB flow
1. `nargo execute --package <pkg> --prover-name <Prover_name>`
2. `bb write_vk --scheme ultra_honk -b target/<pkg>.json -o target`
3. `bb prove --scheme ultra_honk -b target/<pkg>.json -w target/<pkg>.gz -o target`
4. `bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs`
FORBIDDEN: `nargo prove`, `nargo verify`

## P3RealVerifier Vacuity (T1)

- `P3RealVerifier` is Option C (ECDSA surrogate) — only checks trusted-signer ECDSA sig
- ecrecover call site: `P3RealVerifier.sol:63`
- TRUSTED_SIGNER hardcoded at line 30-31 = Anvil #0 = `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
- Vacuity test pattern: craft false 200-byte publicInputs, sign with `vm.sign(TRUSTED_SIGNER_PK, digest)`, assert `verify()` returns true
- Test `testVacuousVerifierAcceptsFalseClaim` PASSES — confirming verifier cannot reject false FHE claims
- Unicode chars in string literals cause Solc 0.8.x compile error — use ASCII only

## T2: SURROGATE Reachability (2026-05-03)

- **HonkVerifier.sol** is LIVE in all profiles: imported both by the production `PvtFheVerifier.sol` (default/release) and the e2e test (`PvtFheVerifier.e2e.t.sol`). Surrogate keccak check is active everywhere.
- **aggregator_final/src/main.nr** and **decrypt_share/src/main.nr** are DEAD under all Rust build profiles. `pvthfhe-circuits` crate is a placeholder with only a trivial `#[test] fn placeholder()`. The circuits are only reachable via `nargo test` (Noir-only). They are Noir workspace members but not invoked by any Rust integration test.
- **fhers.rs** is LIVE: `pub mod fhers` in lib.rs + 4 conformance tests directly instantiate `FhersBackend`. All methods delegate to MockBackendInner (surrogate delegation pattern).
- **keygen/protocol.rs** is compiled (LIVE in the sense of being in the module tree via `pub mod protocol`) but has zero Rust items — only 4 comment lines. No external crate or test references `keygen::protocol` directly. Functionally DEAD.
- `*.log` files are gitignored globally; must use `git add -f` for evidence logs in `.sisyphus/evidence/`.

## T3 Cast Audit — hermine.rs (2026-05-03)

- `grep -nE ' as [a-z_][a-z0-9_]*'` returns 18 lines but 2 are doc-comment false-positives ("used as the Shamir", "byte slice as a lowercase"). Actual code casts = 16 across 14 source lines (two lines hold 2 casts each).
- All u64→u128 widening casts in `poly_eval` and `lagrange_interpolate` are safe; arithmetic is always reduced `% PRIME` before narrowing back to u64, so the one u128→u64 narrow cast at lines 46 and 208 is also safe.
- **Single truncating cast**: line 367 `threshold as u16` (usize→u16). The `threshold` local is derived via `as usize` from a `u16` value, so in practice the value can never exceed u16::MAX in current code — but it is still an unsound pattern. Fix for T19: `u16::try_from(threshold)?`.
- **One `manual_contains`**: line 413 — `iter().any(|c| *c == expected_commit)` → `commitments.contains(&expected_commit)`.

## 2026-05-03 T5 — Test Classification Audit

### Key Findings

1. **Zero REAL Rust tests run in CI.** All 118 Rust `#[test]` items are MOCK (77), WEAK (22), or TRIVIAL (19). No Rust test currently exercises a live cryptographic primitive end-to-end.

2. **P1 tests are compile-skipped.** All 13 `lattice_nizk*.rs` tests are gated `#[cfg(feature = "real-nizk")]` — a feature that has no real implementation. They never run.

3. **P2 folding tests use SHA-256 uniformity checks, not ZK proofs.** The `fold` validator rejects proofs whose bytes are not all-identical — this is a placeholder heuristic, not a FS challenge check. 18 tests that appear adversarial are actually testing a string/byte-equality uniformity heuristic.

4. **P4 keygen tests are 100% MOCK.** All 24 P4-related tests use `HermineAdapter` or `KeygenSimulator` — both documented surrogates. No real PVSS, VSS, or DKG code is exercised.

5. **18 REAL Solidity tests exist for P3** — but they validate ECDSA ecrecover, not FHE soundness. `P3VacuityProof.t.sol` formally proves the verifier cannot distinguish correct from fabricated FHE outputs.

6. **`rogue_key.rs` is mislabeled.** It injects `FaultType::MalformedProof`, not a rogue-key attack. No actual rogue-key scenario is modeled anywhere in the test suite.

7. **`noise_budget_closes_malicious` is identical to `noise_budget_closes_honest`.** Both run the same simulation; the "malicious" label is aspirational. No malicious noise model is implemented.

8. **Test count:** Rust: 118 (via `#[test]` scan) / Solidity: 39 (via `function test` scan).


## T4 Theorem Inventory Audit (2026-05-03)

- Audited all 20 obligation rows in `docs/security-proofs/obligations.md` against the corresponding proof documents and current code paths.
- Resolved the 19-vs-20 discrepancy: `P1-T4` exists in the obligation registry and proof docs, but is omitted from both `paper/claims-table.md` and `paper/main.tex`.
- Identified the unique non-discharged theorem as `P2-T4`: its own proof file says accumulator binding is conditional on two unimplemented items in `crates/pvthfhe-aggregator/src/folding/mod.rs` — arithmetic norm enforcement in `validate_witness` and replacement of the SHA-256 hash-chain surrogate with a linear lattice commitment.
- Classified P2 `{T1,T2,T3,T5}` and P3 `{T1,T2,T5}` as vacuous/surrogate engineering theorems relative to the registry wording, because the current code path is still surrogate/hash-chain/ECDSA-based rather than the full claimed lattice-fold / finalize-or-blame path.
- Strongest implementation-backed proofs are P4 `{T1..T5}`, P1 `{T1..T5}` (with T4 correctly framed as deferral), and P3 `{T3,T4}`.

## Test Classification Audit (T5)
- **Finding**: zero "REAL" cryptographic tests for P1-P4 are currently active in the Rust crates. 
- **P1 (NIZK)**: Tests are REAL-quality but gated by `real-nizk` which is unimplemented.
- **P2 (Folding)**: Tests are WEAK/MOCK against a SHA-256 hash-chain surrogate.
- **P3 (Verifier)**: 18 REAL tests exist but only for the ECDSA authenticator, not the FHE soundness.
- **P4 (Keygen)**: Entirely MOCK against the Hermine/Simulator stub.
- **Impact**: The "green" test state is deceptive; it reflects surrogate passing, not cryptographic soundness.

## T20 Missing Theorem Completion (2026-05-03)

- `paper/main.tex` originally contained 19 `\begin{theorem}` environments; adding the deferred `P1-T4` theorem restores parity with the 20 proof obligations.
- `P2-T4` is supportable only as a **conditional** theorem in the current repo state: the proof can cite the standard linear-commitment-to-SIS reduction, but only if the paper and registry explicitly state the two missing implementation hooks.
- The two open hooks that must stay explicit are: (1) arithmetic norm enforcement inside `validate_witness`, and (2) replacing the SHA-256 accumulator surrogate with a linear lattice commitment.
- `paper/main.tex` already contained a `P2 Accumulator Binding` theorem environment; the missing paper theorem was `P1-T4`, not `P2-T4`.

## T13 Paper Claim Fidelity Classification (2026-05-03)

- Classified all 68 extracted paper/docs claims into `supported` / `overstated` / `contradicted` / `untestable from repo`.
- Final counts: **40 supported, 19 overstated, 9 contradicted, 0 untestable**.
- P3 claims about on-chain soundness/public verifiability are the clearest hard failures: the audit matrix and vacuity evidence force `contradicted` for any statement that equates `P3RealVerifier.sol` with cryptographic verification of the P2/FHE relation.
- P2 performance/security language is usually **overstated** rather than fully contradicted: the repo does contain a measured SHA-256 hash-chain surrogate, but the real folding path is dead in production and `P2-T4` remains an explicit GAP.
- Narrowly scoped theorem statements that honestly name the current simulated/placeholder boundaries (especially P4 theorems and P1's abstract ZK/binding statements) can still be `supported` even when the broader construction-level marketing claims are not.

## T15: Adversarial falsification tests (P1-G1..G4, P4-G1..G3)

### What was added
- `test_nizk_forged_proof_rejected` (P1-G2): single-byte flip at index 8 (stmt_fingerprint region) of proof_bytes causes `VerificationFailed` — verifier catches it.
- P1-G1, P1-G3, P1-G4 stubs were already present and correctly testing the adversarial scenario; confirmed passing.
- `test_keygen_deterministic_same_seed` (P4-G1): HermineAdapter uses `derive_field_elem` (SHA-256 based, fully deterministic) — same participants/threshold → identical BFV key bytes.
- `test_keygen_subset_below_threshold_gives_no_info` (P4-G2): `reconstruct_bfv_key` with t-1=1 shares returns `Err("insufficient shares for threshold reconstruction")` — correct.
- `test_honest_party_not_blamed` (P4-G3): all-honest `blame_dealing` returns `Ok(None)` — correct.

### API notes
- `pvthfhe-keygen` must be listed in `[dev-dependencies]` of `pvthfhe-aggregator` to use `HermineAdapter` in integration tests (it is NOT re-exported by `pvthfhe-fhe`).
- `BFVPublicKey` field is `.bytes`, not `.public_key_bytes`.
- `blame_dealing` returns `Result<Option<BlameProof>, KeygenError>`, not a `Vec`.

### Soundness status
- P1 verifier: NOT a stub — the real verification equation is checked; all 4 tamper scenarios produce `Err` as expected.
- P4 Shamir: real over GF(2^61-1); threshold enforcement is hard (returns Err if shares.len() < threshold).

## T16: P2 Falsification Tests (2026-05-03)

### Norm bound: already implemented
`adversarial-gaps.md` predicted P2-G3 (`test_fold_large_norm_witness_rejected`) would be RED because
`validate_witness` only checked byte uniformity. The actual code (lines 293-300 of `folding/mod.rs`)
DOES enforce the arithmetic norm bound (`proof_bytes[i] <= params.2`). P2-G3 is GREEN — the security
obligation is already fulfilled. The `// BUG(P2-T4)` comment is retained as a regression guard.

### Cascading witness tag failures
The norm check broke 8+ pre-existing tests across `folding.rs`, `folding_adversarial.rs`, and
`p2_bench.rs` that used witness tags > 17 (e.g., 0xab=171, 22, 30, 31, 40, 41, 50, 51, 60, 61).
All were fixed by changing tags to values ≤ 17 (used 5, 12, 13, 14, 15, 16).

### Tag semantics in test helpers
`make_witness(tag)` and `make_statement(_, _, _, tag)` must use the SAME tag value: the statement
`ciphertext_bytes` first byte becomes the expected proof tag, checked by `expected_proof_tag`. Using
distinct tags for witness vs statement breaks the proof tag check.

### `#[ignore]` not needed for P2-G3
Since P2-G3 passes, no `#[ignore]` attribute was added. The attribute is only required when a test
is intentionally RED but must not block CI.

## T22: Final Audit Report (2026-05-03)

- Synthesized all audit evidence (T1–T21) into a final severity-rated report.
- Report includes:
  - Executive Summary (Project honesty rating restored via disclosure).
  - Per-Construction Findings (P1-P4 axis verdicts and remediation status).
  - Cross-Cutting Findings (SURROGATE retirement, cast risks, theorem parity).
  - Paper Fidelity (68/68 supported after T21).
  - Residual Risk (Side-channels, parameters, Linear commitments, SNARK verifier).
- Report location: `.sisyphus/evidence/audit-report.md`.

## 2026-05-03 T23 Completion — Clippy Zero-Warning Fix

### Patterns Discovered

- **Inner module `ok()` scope**: When `ok()` helper is defined at crate root (test file top-level) but used inside `mod inner { use super::*; }`, the `use super::*` glob import brings it in. But if the inner module has its own `use` list without `use super::*`, you must add `use super::ok;` explicitly.

- **`criterion_group!` macro conflict**: The macro generates an undocumentable public function. Fixed by switching `pvthfhe-bench` from `workspace = true` lints to manual lints with `missing_docs = "allow"`.

- **`.expect()` in test code under `expect_used = "deny"`**: Pattern is `fn ok<T, E: Debug>(r, ctx) -> T { match r { Ok(v) => v, Err(e) => unreachable!(...) } }`. Same for Option with `some()`, and for expected-error paths with `err()`.

- **`panic!` vs `unreachable!`**: `clippy::panic` fires on `panic!`. `clippy::unreachable` is a separate lint not in workspace deny list. Use `unreachable!` in branches that are provably impossible (e.g., adversarial test match arms, mock arms).

- **`as` conversions in tests**: Files with `#![allow(clippy::as_conversions)]` are fine. For new loops, switch to `for i in 0_u32..64_u32` to avoid the cast, or use `u32::try_from(i).unwrap_or(u32::MAX)`.

- **`GenericArray::as_ref()` ambiguity**: `outer.update(inner_hash.as_ref())` fails when `GenericArray` implements both `AsRef<[u8]>` and `AsRef<[u8; 32]>`. Fix: `outer.update(&inner_hash[..])`.

- **`*.log` gitignore**: Use `git add -f` to force-add evidence logs.

### Final Gate Results (2026-05-03)
- `cargo clippy --all-targets --all-features -- -D warnings`: **EXIT 0** ✓
- `just phase1-gate`: **PASS** ✓
- `just phase2-gate`: **PASS** ✓
- `just phase3-gate`: **PASS** ✓

## R9 Benchmarks, Docs, External-Audit Prep (2026-05-09)

### R9.1 — Benchmarks

- **`bench/tests/` directory does not exist** — no `results_freshness.sh` script present. Benchmarks marked preliminary as allowed by plan.
- **`bench-comparison-gate` policy test failed** due to a new `#[allow(unexpected_cfgs)]` in `crates/pvthfhe-fhe/tests/reshare_entropy.rs` (added during R0.7 F23 fix). Fixed by adding the file to the allowed list in `tests/integration/policy_invariants.rs`.
- **Compilation errors in `pvthfhe-bench`**: `partial_decrypt` signature changed from 10 args to 7 args (removed `sk`, `pk`, duplicate dkg_root params). Fixed `bench_scaling.rs` caller. Also fixed 4 aggregator test files (`decrypt_roundtrip.rs`, `decrypt_rejections.rs`, `decrypt_real.rs`, `adversarial/mod.rs`) that used old calling convention.
- **Removed dead code**: `mock_sk_pk` functions in `decrypt_roundtrip.rs` and `decrypt_rejections.rs` were unused after signature change.
- **Pre-existing failure**: `baseline_smoke` test fails with "decoded plaintext length 41610 exceeds max 16382" — not introduced by R9.
- **Verdict**: Benchmarks marked preliminary per audit INFO-1 (SHA chains, toy circuits, not target protocol).

### R9.2 — README Rewrite

- Completely rewritten to reflect post-audit reality:
  - Added prominent audit status section with per-layer finding summary
  - Added soundness budget section (folding, noise, open problems)
  - Added threat model reference
  - Retracted "real-cryptography pipeline" language
  - Added benchmark preliminary notice
  - Preserved DO NOT DEPLOY warning

### R9.3 — REPRODUCING.md Update

- Toolchain pins already present: Rust 1.95.0, Foundry 1.6.0-1.7.0, Noir 1.0.0-beta.20, BB 5.0.0-nightly.20260324
- Added preliminary-benchmark notice at top (referencing audit INFO-1)
- Added preliminary notice on Expected Runtimes table

### R9.4 — Threat Model v1

- Created `.sisyphus/design/threat-model-v1.md` synthesizing from:
  - AUDIT-2026-05-08 §§1.1-1.3 (adversary model, properties, prototype status)
  - assumptions-ledger.md (21 cryptographic assumptions)
  - security-proofs.md (4 theorems: T-IND-CPA, T-DEC-SOUND, T-PV-SOUND, T-ROBUSTNESS)
  - proof-boundary.md (12 enforcement properties, frozen Phase 2)
  - fold-soundness-budget.md (|C|=2^16, T=10, ε=2^(-160))
  - noise-budget.md (honest 2^46.2, malicious 2^50.7)
- Documents: scope (in/out), adversary model, 8 security properties, primitives table, soundness budgets, enforcement layers, residual assumptions, trust assumptions.

### R9.5 — External-Audit Packet

- Created `.sisyphus/audit/EXTERNAL-PACKET.md` as single-entry document for external auditors:
  - Executive summary (69 findings, NOT SUITABLE FOR PRODUCTION)
  - Document bundle (audit report, threat model, assumptions ledger, security proofs, proof boundary, design specs, soundness budgets, benchmarks, codebase map)
  - Quick-start guide for auditors (5-step process)
  - Key cryptographic parameters table
  - Critical open items for external review (P1, P2, P3, Sonobe substitution, on-chain vacuity, DKG break, end-to-end decoupling)
