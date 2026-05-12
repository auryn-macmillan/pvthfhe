# Deep Audit Remediation Plan

**Created**: 2026-05-12
**Trigger**: 5-dimensional deep audit (soundness, security, bugs, E2E verifiability, Interfold comparability)
**Findings**: 3 CRITICAL, 4 HIGH, 6 MEDIUM, 3 LOW across 24 source files

## Cross-cutting constraint: Theory–Docs–Code alignment

Every task in this plan MUST update three layers in lockstep:

| Layer | Scope | Files |
|-------|-------|-------|
| **Theory** | Security proofs, threat model, soundness budget | `docs/security-proofs/`, `.sisyphus/design/threat-model-v1.md` |
| **Docs** | Implementation docs, README, SECURITY, design docs | `README.md`, `SECURITY.md`, `.sisyphus/design/*.md` |
| **Code** | Source, tests, CI | `crates/*/src/*.rs`, `crates/*/tests/*.rs` |

Do NOT fix code without updating the theory and docs that reference it. Do NOT update theory without reflecting it in code. Every batch below includes explicit sub-items for all three layers.

---

## 🔴 CRITICAL — Batch A (fix immediately)

### A.1 — Replace fixed masking seeds with fresh randomness
- [ ] **Code**: `crates/pvthfhe-pvss/src/nizk_share.rs` lines 412, 667 — replace `[0xA5; 32]` and `[0xB4; 32]` with `OsRng` or transcript-derived seed
- [ ] **Theory**: `docs/security-proofs/interfold-equivalent-pvss.md` — add § on sigma protocol ZK property, noting masking randomness is now fresh per proof
- [ ] **Docs**: `SECURITY.md` §P1 — add item: "Sigma masking seeds: fresh per proof (OsRng, non-deterministic)."
- [ ] **Gate**: All 15 focused PVSS tests still pass. Demo-e2e still passes. `grep -c "from_seed(\[" crates/pvthfhe-pvss/src/nizk_share.rs` returns 0 for literal-array seeds at the proof generation call sites (lines 412, 667).

### A.2 — Fix double-subtract threshold bug
- [ ] **Code**: `crates/pvthfhe-cli/src/full_pipeline.rs` lines 194, 318 — remove `saturating_sub(1)` from both `setup_threshold` and `aggregate_decrypt` calls; pass `backend_threshold` directly (line 92 already stores `cfg.t` correctly)
- [ ] **Theory**: `.sisyphus/design/threat-model-v1.md` — add § on threshold convention: "FHE threshold = PVSS threshold = number of shares required for reconstruction"
- [ ] **Docs**: `README.md` — update threshold parameter documentation; remove any stale reference to `t-1` convention
- [ ] **Gate**: Demo-e2e passes (unchanged behavior). Test t=1 works normally. FHE threshold equals PVSS threshold.

### A.3 — Fix DKG vs FHE aggregate key mismatch
- [ ] **Code**: `crates/pvthfhe-cli/src/full_pipeline.rs` lines 198, 209-212 — remove underscore, add `assert_eq!` key comparison
- [ ] **Theory**: `.sisyphus/design/spec-real-p2p3.md` — add § on aggregate key consistency: DKG transcript key MUST equal FHE backend aggregate key
- [ ] **Docs**: `WARNING.md` — add note about aggregate key verification being enforced
- [ ] **Gate**: Demo-e2e passes. No runtime assertion failure.

---

## 🟠 HIGH — Batch B

### B.1 — Remove plaintext slot logging from aggregate_decrypt
- [ ] **Code**: `crates/pvthfhe-fhe/src/fhers.rs` lines 1116-1120 — remove or gate behind `#[cfg(feature = "trace-decrypt")]`
- [ ] **Theory**: `.sisyphus/design/threat-model-v1.md` — add § on logging hygiene: "No plaintext material shall be emitted to stdout/stderr on the happy path"
- [ ] **Docs**: `SECURITY.md` — add "Logging: no plaintext in default output (trace-decrypt feature gate available)"
- [ ] **Gate**: Demo-e2e output no longer contains `[FHE-DECRYPT] aggregate_decrypt:` line.

### B.2 — Also remove encode/decode slot logging
- [ ] **Code**: `crates/pvthfhe-fhe/src/fhers.rs` lines 436-441, 454-458 — same treatment as B.1
- [ ] **Theory**: (covered by B.1 threat model update)
- [ ] **Docs**: (covered by B.1 SECURITY.md update)
- [ ] **Gate**: Demo-e2e output no longer contains `[FHE-ENCODE]` or `[FHE-DECODE]` lines.

### B.3 — Add threshold enforcement to `shamir::recover`
- [ ] **Code**: `crates/pvthfhe-pvss/src/shamir.rs` lines 123-126 — add `threshold` parameter, return `InsufficientShares` when `shares.len() < threshold`
- [ ] **Theory**: `.sisyphus/design/nizk-construction.md` — add § on shamir module API contract: recover requires threshold validation
- [ ] **Docs**: (Code is self-documenting via error type)
- [ ] **Gate**: Existing PVSS tests pass. New RED test verifies `recover()` with fewer than `t` shares returns error.

### B.4 — Change `shamir::split` asserts to returned errors
- [ ] **Code**: `crates/pvthfhe-pvss/src/shamir.rs` line 83-84 — replace `assert!` with `Err(ShamirError::InvalidParameters(...))`
- [ ] **Theory**: (covered by B.3 docs update)
- [ ] **Docs**: (Code is self-documenting via error type)
- [ ] **Gate**: Existing tests pass. Program doesn't panic on invalid inputs.

---

## 🟡 MEDIUM — Batch C

### C.1 — Wrap `DecryptNizkWitness` secret fields in Zeroize
- [ ] **Code**: `crates/pvthfhe-pvss/src/nizk_decrypt.rs` lines 82-83 — wrap `secret_key_bytes` and `decryption_noise` in `pvthfhe_types::Secret<Vec<u8>>` (already imported; same pattern as `ShareSecret`, `EncRandomness`)
- [ ] **Theory**: `.sisyphus/design/smudging.md` — add § on memory hygiene: all secret witness fields must use `Secret<T>` + `ZeroizeOnDrop`
- [ ] **Docs**: `SECURITY.md` — add "Memory hygiene: all secret witness fields use Secret<T> wrapper"
- [ ] **Gate**: Build passes. No plain `Vec<u8>` secret fields remain.

### C.2 — Add input validation to `scale_plaintext_to_rns`
- [ ] **Code**: `crates/pvthfhe-nizk/src/bfv_sigma.rs` lines 164-181 — add `|c| ≤ B_M` check at function entry
- [ ] **Theory**: `.sisyphus/design/nizk-construction.md` — add § on BFV sigma API contract: `scale_plaintext_to_rns` requires `|coeff| ≤ B_M`; out-of-bounds inputs return error
- [ ] **Gate**: Build passes. No panic on out-of-bounds input.

### C.3 — Fix `bytes_to_i64_poly` trailing bytes issue
- [ ] **Code**: `crates/pvthfhe-cli/src/demo_nizk.rs` lines 125-132 — assert `input.len() % 8 == 0` before `chunks_exact(8)`, or use `chunks(8)` with explicit partial-chunk error
- [ ] **Theory**: (documented in code via assertion message — no separate theory doc needed for demo utility)
- [ ] **Gate**: Existing tests pass. No silent data loss.

### C.4 — Rename `B_E` constant to avoid namespace collision
- [ ] **Code**: `crates/pvthfhe-nizk/src/sigma.rs:39` → `SIGMA_B_E`, `bfv_sigma.rs:50` → `BFV_SIGMA_B_E`
- [ ] **Gate**: Build passes. No ambiguous imports.

### C.5 — Add `n > 0` guard to `compute_party_sk_sums`
- [ ] **Code**: `crates/pvthfhe-fhe/src/fhers.rs` lines 267-275 — add `if n == 0 { return Err(FheError::Backend { reason: "n must be > 0".into() }) }` at function top
- [ ] **Theory**: (documented in code via error type and message — no separate theory doc needed for guard clause)
- [ ] **Gate**: Build passes. Function returns error for n=0.

### C.6 — Fix `derive_demo_error_poly` naming/doc
- [ ] **Code**: `crates/pvthfhe-cli/src/demo_nizk.rs` lines 115-119 — add doc comment: "Generates small-norm demo polynomial for NIZK testing, not actual BFV encryption error"
- [ ] **Docs**: `README.md` — update NIZK error witness description
- [ ] **Gate**: No functional change; doc-only.

---

## 🔵 LOW — Batch D

### D.1 — Remove `WitnessLeakingProofBytesV0` quarantine type
- [ ] **Code**: `crates/pvthfhe-types/src/lib.rs` lines 369-405 — remove type or add `#[deprecated]`
- [ ] **Docs**: `SECURITY.md` — remove any reference to `WitnessLeakingProofBytesV0`
- [ ] **Gate**: Build passes.

### D.2 — Rename `noise_tolerant_plaintext_compare` to `plaintext_compare_exact`
- [ ] **Code**: `crates/pvthfhe-fhe/src/lib.rs` line 241 — rename function; update call sites at `full_pipeline.rs:326`
- [ ] **Docs**: (Code is self-documenting via function name)
- [ ] **Gate**: Build passes. No behavioral change.

### D.3 — Gate test vector debug prints behind feature flag
- [ ] **Code**: `crates/pvthfhe-core/tests/vectors.rs` lines 121-188 — gate behind `#[cfg(feature = "trace-test-vectors")]`
- [ ] **Docs**: (No docs impact)
- [ ] **Gate**: Tests pass; no secret output on standard runs.

---

## Interfold Gap Closure — Batch E

### E.1 — Wire committed smudge mode into primary path (C6 closure)
- [ ] **Code**: `crates/pvthfhe-pvss/src/encrypt.rs` — add `committed_esm_noise_bytes: Option<Vec<u8>>` parameter to `prove_decrypted_share()` (line 79 signature). When `Some`, construct `DecryptNizkMode::CommittedSmudge { ... }` instead of `LegacyLocalSmudge` on line 104, and call `backend.partial_decrypt_committed_smudge()` instead of `backend.partial_decrypt()` at the call site in `recover()` (line 271). Update the `RecoverContext` or pass-through to carry the esm bytes.
- [ ] **Theory**: `.sisyphus/design/smudging.md` §8.3 — update to reflect committed mode is now wired into primary path; document the two-track DKG `e_sm` dependency
- [ ] **Docs**: `README.md` — update C6 status from "PARTIAL" to "IMPLEMENTED" in Interfold comparison table
- [ ] **Gate**: `cargo test -p pvthfhe-pvss --test nizk_decrypt_committed_smudge` passes (new RED→GREEN test). Legacy path verified by existing decrypt tests.

### E.2 — Document C7 gap and plan
- [ ] **Theory**: `.sisyphus/design/interfold-equivalence.md` §C7 — add section: current state (stub), what's needed (Noir circuit for Lagrange+CRT+decode), dependency on Batch G
- [ ] **Docs**: `README.md` — ensure C7 status reflects "MISSING / deferred to Batch G"
- [ ] **Gate**: Documentation update only.

### E.3 — Document C3 structural proof gap
- [ ] **Theory**: `.sisyphus/design/interfold-equivalence.md` §C3 — document algebraic sigma proves `d = c * H(share)` (hash-preimage), not Shamir structure
- [ ] **Theory**: `docs/security-proofs/interfold-equivalent-pvss.md` — add § on C3 gap: share well-formedness proof is hash-preimage, share structure is not proven
- [ ] **Docs**: `README.md` — ensure C3 status matches theory document
- [ ] **Gate**: Documentation update only.

### E.4 — Document C5 gap
- [ ] **Theory**: `.sisyphus/design/interfold-equivalence.md` §C5 — document aggregate decryption uses internal ShareManager, produces no verifiable proof
- [ ] **Docs**: `SECURITY.md` — add note: "Aggregate decryption correctness is trusted (no verifiable proof). Verifier must redo Lagrange+CRT+decode from scratch."
- [ ] **Gate**: Documentation update only.

### E.5 — Update C2 status from "partial" to "implemented" across all docs
- [ ] **Theory**: `.sisyphus/design/interfold-equivalence.md` §C3 — change status from `missing/partial` to `implemented (v4 BFV sigma proof)`
- [ ] **Docs**: `README.md`, `SECURITY.md` — update all references to C2/BFV encryption from "partial" to "implemented"
- [ ] **Gate**: All docs consistent with code reality (v4 proofs include BFV sigma, verified through `verify_shares` → `bfv_sigma::verify()`)

---

## Compressor Verifiability — Batch F

### F.1 — Add external verifier option for compressor proof
- [ ] **Code**: `crates/pvthfhe-cli/src/full_pipeline.rs` — after `compressor.verify()`, optionally serialize proof and call off-chain verifier as independent check
- [ ] **Theory**: `.sisyphus/design/spec-real-p2p3.md` §5 — add note: "Compressor proof is verified in-process during demo. External verification via off-chain verifier CLI is available as a separate step."
- [ ] **Docs**: `README.md` — add compressor verification section noting the two-tier verification (in-process + optional external)
- [ ] **Gate**: `cargo run --release -p pvthfhe-cli --features "sonobe-compressor" -- verify-proof --proof-path /tmp/compressed.proof` succeeds (new `verify-proof` subcommand or equivalent external invocation). Until the CLI subcommand is built, gate is: `compressor.verify()` is called AND a second independent `SonobeNova::verify()` is executed from a separate code path (simulating external verification).

### F.2 — Document CycloFoldStepCircuit gap in theory
- [ ] **Theory**: `.sisyphus/design/spec-real-p2p3.md` §P3 — document that `CycloFoldStepCircuit` proves field arithmetic on 3 Fr scalars (hash of commitments), NOT full Ajtai commitment folding. The real fold verification is deterministic recomputation in `verify_fold()`.
- [ ] **Theory**: `docs/security-proofs/interfold-equivalent-pvss.md` — add §P3: "Sonobe Nova step circuit does not prove lattice Ajtai fold. The IVC proves hash-accumulate correctness, not ring-element folding. See open problem P2/P3."
- [ ] **Docs**: `README.md` — update P2/P3 status to reflect this gap is documented but not closed
- [ ] **Gate**: Documentation update only.

---

## Theory Consolidation — Batch G

### G.1 — Update threat model with all new findings
- [ ] **Theory**: `.sisyphus/design/threat-model-v1.md` — add/update sections:
  - § on threshold convention: FHE threshold = PVSS threshold = number of shares required
  - § on aggregate key consistency: DKG transcript key MUST equal FHE backend aggregate key (enforced by assertion)
  - § on logging hygiene: no plaintext/witness material in stdout/stderr on happy path
  - § on memory hygiene: all secret witness fields use `Secret<T>` + `ZeroizeOnDrop`
  - § on sigma ZK: masking seeds are fresh per proof (OsRng), not hardcoded
- [ ] **Theory**: Update P1/P2/P3 status in threat model to reflect audit findings
- [ ] **Gate**: Threat model is consistent with all code changes in Batches A-D

### G.2 — Create soundness budget reconciliation table
- [ ] **Theory**: `docs/security-proofs/soundness-budget.md` (new) — create table reconciling:
  - Aspirational bounds from README vs actual conditional status
  - ε_fold claimed (2^-160) vs actual (conditional on Lemma 9 heuristic)
  - Composed soundness claimed (2^-128) vs actual (aspirational, P1/P2/P3 unresolved)
- [ ] **Docs**: `README.md` — update soundness budget section to reference this reconciliation table
- [ ] **Gate**: No aspirational bounds presented as achieved in any public doc

### G.3 — Cross-verify code–theory–docs alignment
- [ ] **Verify**: For every `[x]` item in Batches A-F, confirm that:
  - The code change was applied correctly
  - The corresponding theory document (if named) was updated and saved
  - The corresponding docs file (if named) was updated and saved
  - The three layers are consistent (no drift)
- [ ] **Fix**: Any drift found → re-delegate that specific item
- [ ] **Gate**: Script: `for batch in A B C D E F; do echo "=== Batch $batch ==="; git diff --name-only | grep -E "(theory\|docs\|code)" | sort -u; done` — each batch with code+theory+docs sub-items must show at least one file touched in each layer. A batch with explicit "no theory/doc needed" (e.g., C.3, C.5) is exempt from that layer.

---

## Execution order

| Batch | Priority | Depends on | Effort | Notes |
|-------|----------|------------|--------|-------|
| **A** (CRITICAL) | P0 | None | ~2h | A.2 then A.3 sequentially (adjacent lines in `full_pipeline.rs`:194,198). A.1 can run in parallel |
| **B** (HIGH) | P1 | None | ~1h | Independent |
| **C** (MEDIUM) | P2 | None | ~1h | Independent; C.5 and B.1/B.2 both touch `fhers.rs` but in different regions |
| **D** (LOW) | P3 | None | ~30min | Independent; D.2 touches `full_pipeline.rs` (line 326) — non-overlapping with A.2/A.3 |
| **E** (Interfold gaps) | P2 | A.2 (threshold fix) | ~2h | |
| **F** (Compressor) | P2 | None | ~1h | |
| **G** (Theory consolidation) | P1 | A-F complete | ~1h | Runs last |
| **H** (Demo + benchmark) | P1 | A-C complete | ~1h | Runs after code fixes; before G |

---

## Demo + Benchmark Integration — Batch H

Before closing the remediation, verify that every fixed code path is exercised by the demo and that the comparative benchmark reflects the post-fix state.

### H.1 — Verify demo exercises all fixed success paths
- [ ] **Verify**: `just demo-e2e 10` runs to completion. Success paths for A.2, A.3, B.1/B.2 are exercised by the demo. Error paths for B.3, B.4, C.2, C.3, C.5 are validated by per-item unit/RED tests (not the demo). Check demo output for:
  - No `[FHE-ENCODE]` or `[FHE-DECODE]` plaintext slot leaks (B.1/B.2 fix)
  - `verify: ACCEPT` (all verification passes)
  - `plaintext_roundtrip: OK` (no threshold/key mismatch)
  - `aggregate_pk_hash` and ciphertext hash are consistent across runs (no key mismatch A.3)
- [ ] **Fix**: If any verification step fails, trace to the specific batch and re-delegate.
- [ ] **Gate**: `just demo-e2e 10` passes with clean output.

### H.2 — Verify force-large-n still works
- [ ] **Verify**: `cargo run --release -p pvthfhe-cli --features "sonobe-compressor,demo-seeded-rng" -- demo --n 231 --threshold 4 --seed 1 --force-large-n` succeeds
- [ ] **Gate**: Same as H.1 but for n=231.

### H.3 — Run comparative benchmark before and after
- [ ] **Before**: Run `python3 bench/i1_one_vs_two_track.py` and save to `bench/results/deep-audit-before.json`
- [ ] **After**: After all code batches (A-D) are applied, run again and save to `bench/results/deep-audit-after.json`
- [ ] **Compare**: Produce `bench/results/deep-audit-before-after.md` with side-by-side table of:
  - keygen_ms, encrypt_ms, decrypt_ms, proof_size, verifier_time
  - Any metric differences >10% flagged as regressions
- [ ] **Gate**: No regression >10% in any measured metric. If present, documented and justified.

### H.4 — Verify benchmark script still exercises all paths
- [ ] **Verify**: `python3 -m py_compile bench/i1_one_vs_two_track.py` passes
- [ ] **Verify**: `python3 -m json.tool bench/results/i1-one-vs-two-track.json` passes
- [ ] **Gate**: Benchmark infrastructure intact.

### H.5 — Document any benchmark regression
- [ ] **Verify**: If H.3 comparison shows >10% regression in any metric, add a section to `bench/results/deep-audit-before-after.md` explaining the cause and justifying the trade-off.
- [ ] **Gate**: No unexplained regression >10%.

---

## Acceptance criteria

### CRITICAL gates (blocking)
- [ ] A.1: Fixed masking seeds replaced with fresh randomness; ZK property restored
- [ ] A.2: FHE threshold equals PVSS threshold (no double-subtract); t=1 works
- [ ] A.3: DKG aggregate key matches FHE aggregate key (assertion passes)

### HIGH gates (blocking)
- [ ] B.1-B.2: No plaintext, share, or witness material in stdout/stderr on happy path
- [ ] B.3: `shamir::recover` enforces threshold; RED test passes
- [ ] B.4: `shamir::split` returns errors instead of panicking

### MEDIUM gates
- [ ] C.1: `Secret<T>` wrapping on all secret witness fields
- [ ] C.2-C.5: All guarded functions have explicit validation
- [ ] C.6: Demo error poly has clarifying docs

### Interfold gates
- [ ] E.1: C6 committed smudge wired into primary path (with legacy fallback)
- [ ] E.2-E.5: Interfold equivalence doc updated with C2/C3/C5/C6/C7 status

### Compressor gates
- [ ] F.1: Compressor proof verifiable externally (off-chain verifier wired)
- [ ] F.2: P2/P3 gap documented in theory and docs

### Theory–Docs–Code alignment gates
- [ ] G.1: Threat model updated with all new findings
- [ ] G.2: Soundness budget reconciliation table created; no aspirational bounds as facts
- [ ] G.3: Cross-verification confirms no drift between code, theory, and docs for any batch

### Demo integration gate
- [ ] H.1: `just demo-e2e 10` exercises all fixed code paths and passes (`plaintext_roundtrip: OK`, `verify: ACCEPT`)
- [ ] H.2: `just demo-e2e 10` with `--force-large-n` flag still works for n > 230

### Benchmark comparison gate
- [ ] H.3: Run `python3 bench/i1_one_vs_two_track.py` before and after remediation; publish comparative results in `bench/results/deep-audit-before-after.md`
- [ ] H.4: Comparative benchmark shows no regression (>10% slowdown) in any measured metric (keygen_ms, encrypt_ms, decrypt_ms, proof_size, verifier_time)
- [ ] H.5: If regression detected, document cause and justify in the benchmark report

### Regression gates
- [ ] All 15 focused PVSS tests pass
- [ ] Demo-e2e passes (`plaintext_roundtrip: OK`, `verify: ACCEPT`)
- [ ] `cargo clippy --workspace -- -D warnings` passes (pre-existing fhers.rs excluded)
- [ ] `cargo build` passes for all crates
- [ ] `forge test --root contracts` passes
