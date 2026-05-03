# Audit Matrix: Per-Construction Verdicts (T9–T12)

Evidence inputs: `theorem-inventory.md`, `test-classification.md`, `p1-reachability.md`, `p2-reachability.md`, `surrogate-reachability.md`, `audit-p3-vacuity/`, `paper-claims.md`.

---

## Schema

Each construction is rated on three independent axes:

| Axis | Verdicts |
|------|---------|
| **Impl** | `REAL` / `PARTIAL` / `STUB` / `MOCK` |
| **Proof** | `PROVED` / `PARTIAL` / `GAP` |
| **Test** | `ADVERSARIAL` / `REGRESSION-ONLY` / `INSUFFICIENT` |

Overall **Severity**: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE`  
Overall **Confidence**: `HIGH` / `MEDIUM` / `LOW`

---

### P1 — Lattice NIZK (T9)

- **Impl**: `MOCK`
  - `FhersBackend` (the primary backend, `crates/pvthfhe-fhe/src/fhers.rs`) is annotated `// SURROGATE` and delegates every method to `MockBackend` — confirmed by T5 and T7. The `real_nizk` module (`RealNizkAdapter`) compiles under the default `real-nizk` feature but is invoked only from the benchmark binary `bench_nizk` and aggregator tests — never from any production path. No real lattice NIZK is exercised at runtime.
  - Evidence: `p1-reachability.md`, `test-classification.md` (T5 MOCK findings)

- **Proof**: `PARTIAL`
  - P1-T1 (Completeness): PROVED-WITH-CITATION — SHA-256 hash transcript completeness well-argued.
  - P1-T2 (Soundness): PROVED-WITH-CITATION — straight-line extraction under SHA-256 binding established.
  - P1-T3 (ZK): PROVED-WITH-CITATION — HVZK-to-FS compilation with ROM.
  - P1-T4 (absent from paper): present in `docs/security-proofs/p1/T4.md` but missing from `paper/main.tex` and `claims-table.md` — the 20th theorem discrepancy.
  - P1-T5 (Commitment Binding): PROVED-WITH-CITATION.
  - Open gap admitted in `paper/main.tex:244-245`: "The main open question is the tightness of the P1 soundness reduction." README also admits "Open Problem P1: Lattice NIZK well-formedness soundness is not formally proven."
  - Evidence: `theorem-inventory.md` (P1 rows)

- **Test**: `INSUFFICIENT`
  - 13 tests in `lattice_nizk*.rs` gated `#[cfg(feature = "real-nizk")]` — since `real-nizk` IS the default, these do compile/run, but T5 classifies all as MOCK (they test `RealNizkAdapter` which is the stub implementation, not a real lattice backend). There are no tests that exercise a real cryptographic NIZK that would fail if the algebra were broken.
  - Evidence: `test-classification.md` (P1 MOCK rows)

- **Severity**: `HIGH`
  - Zero real implementation in production paths. Tests pass because they test a mock. Paper admits open problem. Soundness is the core security guarantee.

- **Confidence**: `HIGH`
  - T7 reachability + T5 classification provide independent corroborating evidence.

---

### P2 — Real Folding / LatticeFold+ (T10)

- **Impl**: `STUB`
  - `RealFoldingScheme` in `crates/pvthfhe-aggregator/src/folding/mod.rs` is a surrogate: it uses a SHA-256 hash-chain accumulator instead of a LatticeFold+ algebraic commitment. The `real-folding` feature is **never enabled** from any downstream crate (`pvthfhe-bench`, `pvthfhe-cli` both use default features which do not include `real-folding`). The folding code is completely dead in all production builds.
  - Evidence: `p2-reachability.md` (confirmed by `tests/p2_bench.rs:3` self-annotation: "Surrogate hash-chain implementation of RealFoldingScheme")

- **Proof**: `PARTIAL` (with `GAP`)
  - P2-T1 (Folding Completeness): PROVED-WITH-CITATION — for the hash-chain surrogate.
  - P2-T2 (Knowledge Soundness): PROVED-WITH-CITATION — conditional on SHA-256 binding.
  - P2-T3 (ZK Preservation): PROVED-WITH-CITATION — for the projected SLAP core.
  - **P2-T4 (Accumulator Binding): `GAP`** — Part A proved; Part B explicitly conditional on two unimplemented obligations: (1) arithmetic norm check in `validate_witness` (currently absent), (2) algebraic linear commitment map (currently SHA-256 hash). Proof document itself states "Part B is a conditional theorem and represents an open security obligation."
  - P2-T5 (On-chain Compatibility): PROVED-WITH-CITATION — for bounded gas/proof size.
  - Evidence: `theorem-inventory.md` (P2-T4 GAP row), `docs/security-proofs/p2/T4.md`

- **Test**: `INSUFFICIENT`
  - Folding tests (`folding.rs`, `folding_tamper.rs`, `folding_adversarial.rs`) require `--features real-folding` to compile. The adversarial "rejection" tests check that `proof_bytes` is uniform (all bytes identical) — a harness invariant, not a cryptographic Fiat-Shamir check. No test would fail if the SHA-256 chain were replaced with a no-op hash. The `noise_budget_closes_malicious` test is identical to `noise_budget_closes_honest` (different seed only).
  - Evidence: `test-classification.md` (P2 MOCK/WEAK rows), T5 finding #3

- **Severity**: `CRITICAL`
  - The accumulator binding (P2-T4) has an explicit open security obligation (norm-bound not enforced). The entire folding stack is dead in production. Performance claims (O(polylog n)) are validated only on the SHA-256 surrogate.

- **Confidence**: `HIGH`
  - Multiple independent evidence sources: reachability map, proof doc self-annotation, test source.

---

### P3 — On-Chain Verifier (T11)

- **Impl**: `MOCK` (functionally: trusted-signer authenticator)
  - `contracts/src/P3RealVerifier.sol` calls `ecrecover(digest, v, r, s) == TRUSTED_SIGNER` where `TRUSTED_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` (Anvil account #0). No P2 accumulator is checked. No FHE ciphertext relation is verified. The verifier authenticates that a trusted party signed the public inputs — it does not verify any cryptographic computation.
  - Evidence: `audit-p3-vacuity/forge-output.log`, `contracts/test/P3VacuityProof.t.sol` (Forge test proves attacker-chosen false claim is accepted by the verifier when signed by the trusted key)

- **Proof**: `PARTIAL` (mostly mislabeled)
  - P3-T1 proof file (`docs/security-proofs/p3/T1.md`) is titled **"Completeness of the ECDSA On-Chain Verifier"** and proves ECDSA sign→verify completeness, NOT the claimed soundness ("any on-chain acceptance implies P2 accumulator acceptance"). The claims-table.md labels P3-T1 as "On-chain Soundness" but the proof content proves only that an honest signer's signature verifies — a completely different statement.
  - P3-T3 (Trusted-Setup Explicitness): the proof correctly states "N/A otherwise" for non-setup-based paths — this is honest.
  - P3-T4 (Gas Bound): PROVED-WITH-CITATION — gas measurement-based.
  - Evidence: `docs/security-proofs/p3/T1.md`, `paper/claims-table.md`

- **Test**: `REGRESSION-ONLY`
  - 18 Solidity tests in `RealVerifier.t.sol` and `RealVerifierAdversarial.t.sol` are classified REAL for ECDSA authentication (they correctly test that a wrong-signer signature is rejected). However, none test FHE correctness. `P3VacuityProof.t.sol` (T1 evidence) demonstrates the verifier accepts arbitrary false claims — these adversarial tests do not catch that.
  - Evidence: `test-classification.md` (P3 rows), `audit-p3-vacuity/SUMMARY.md`

- **Severity**: `CRITICAL`
  - P3's headline claim ("O(1) gas on-chain verifier for FHE") is a trusted-signer signature check. The proof of "on-chain soundness" (P3-T1) actually proves only ECDSA completeness. Any attacker who controls the trusted signer key (or colludes with them) can attest to arbitrary false decryptions on-chain.

- **Confidence**: `HIGH`
  - T1 Forge test provides machine-executable proof of vacuity. P3-T1.md proof text is unambiguous.

---

### P4 — Aggregator / PVSS Keygen (T12)

- **Impl**: `PARTIAL`
  - `crates/pvthfhe-aggregator/src/keygen/protocol.rs` (4 lines) is a re-export shim: `pub use crate::keygen::mod::*;`. The actual implementation is in `crates/pvthfhe-keygen/src/hermine.rs` via `HermineAdapter`. The keygen logic is real Shamir secret sharing over `GF(2^61-1)` — not a surrogate. However, the FHE key itself is a serialized placeholder (`BFVPublicKey` — stub), and Ring-LWE secrecy is deferred (P4-T2 explicitly acknowledges this caveat).
  - Evidence: `surrogate-reachability.md`, `crates/pvthfhe-aggregator/src/keygen/protocol.rs`

- **Proof**: `PROVED` (with deferred caveat)
  - P4-T1 through P4-T5 are all PROVED-WITH-CITATION (see `theorem-inventory.md` P4 rows). All proofs cite concrete code paths in `hermine.rs`. P4-T2 explicitly defers Ring-LWE secrecy — the proof is honest about its scope.
  - Evidence: `theorem-inventory.md` (P4 rows), `docs/security-proofs/p4/`

- **Test**: `INSUFFICIENT`
  - All P4 tests use `HermineAdapter` or `KeygenSimulator` — both documented surrogates (T5 finding #4: "P4 keygen tests are 100% MOCK"). No test exercises a real PVSS/DKG protocol. The `protocol.rs` shim is never directly tested (it's a re-export).
  - Evidence: `test-classification.md` (P4 MOCK rows)

- **Severity**: `HIGH`
  - FHE public key is a placeholder stub. Ring-LWE secrecy is deferred. Tests test only the surrogate adapter, not a real keygen. The Shamir implementation in `hermine.rs` has clippy-suppressed casts (T3) that are unaudited for sign/truncation risk.

- **Confidence**: `MEDIUM`
  - Implementation axis confident. Test/proof axis confident. Severity rating is uncertain because Ring-LWE deferral could be a design phase marker rather than a fundamental gap.

---

## Summary Matrix

| Construction | Impl | Proof | Test | Severity | Confidence |
|---|---|---|---|---|---|
| **P1** Lattice NIZK | MOCK | PARTIAL | INSUFFICIENT | HIGH | HIGH |
| **P2** Real Folding | STUB | PARTIAL (GAP: T4) | INSUFFICIENT | CRITICAL | HIGH |
| **P3** On-Chain Verifier | MOCK | PARTIAL (T1 mislabeled) | REGRESSION-ONLY | CRITICAL | HIGH |
| **P4** Aggregator/PVSS | PARTIAL | PROVED (deferred) | INSUFFICIENT | HIGH | MEDIUM |

## Cross-cutting findings

1. **Zero production-path real crypto**: P1 FhersBackend delegates to mock; P2 folding disabled in production; P3 is an ECDSA check; P4 FHE key is a stub.
2. **P2-T4 security obligation unmet**: arithmetic norm check and algebraic commitment both missing. This is a hard blocker for the accumulator binding claim.
3. **P3-T1 proof is mislabeled**: claims-table says "On-chain Soundness" but the proof document proves "ECDSA Completeness" — a fundamentally different property.
4. **P1-T4 absent from paper**: 20th theorem not reflected in `paper/main.tex` or `claims-table.md`.
