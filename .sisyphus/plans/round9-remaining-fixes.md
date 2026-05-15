# Plan: Round 9 — Remaining R7/R8 Audit Remediation

**Plan**: `round9-remaining-fixes`
**Status**: DRAFT
**Created**: 2026-05-15
**Source**: R7+R8 follow-up audit — 4 unfixed medium+ items, 1 CRITICAL

---

## Findings

### Critical (1)

| ID | Finding |
|----|---------|
| **F1** | MicroNova `verify_tree` computes per-step circuit hashes but never checks them — the values are only logged via `tracing::debug!` and discarded. Verifier accepts any step with the single `vk`. |

### Medium (4)

| ID | Finding |
|----|---------|
| **F2** | `NizkWitness` in both `pvthfhe-fhe` and `pvthfhe-nizk` lacks `Zeroize` — 8192-coefficient secret key material persists in freed memory |
| **F3** | NIZK verify loop is sequential `for` — `rayon` never wired (Batch D unfixed) |
| **F4** | C7 Merkle circuit never tested with real decryption share data — all test data is synthetic (all-1 leaves, sequential share_evals) |
| **F5** | Batch sigma NIZK verification not started (Batch F — research) |

### Low (2)

| ID | Finding |
|----|---------|
| **F6** | `dealer_index as u32` has no runtime bound check |
| **F7** | `num_circuits()` fix correct but untested at depth=0,1 |

---

## Batch A: Critical — MicroNova Verifier Enforcement (F1)

| Task | Files | Effort |
|------|-------|--------|
| A.1 | Document architecture limitation: `SonobeNova` uses single verifier key — per-variant enforcement requires heterogeneous verifier keys, which Nova doesn't support. Add comment to `verify_tree` explaining this is a known Sonobe surrogate limitation. | `compressor.rs:108-127` | 0.5 day |
| A.2 | Add RED test confirming limitation: verify_tree with wrong circuit variant still passes (documents gap, prevents regression) | `micronova_heterogeneous` tests | 0.5 day |
| A.3 | Update `docs/security-proofs/p3/heterogeneous-ivc.md` line 96-99: replace "planned" with "KNOWN LIMITATION — requires architectural changes to Sonobe Nova" | `heterogeneous-ivc.md:96-99` | 0.5 day |
| A.4 | Update SECURITY.md P3 section to document the limitation | `SECURITY.md` | 0.5 day |

## Batch B: NizkWitness Zeroize (F2)

| Task | Files | Effort |
|------|-------|--------|
| B.1 | Add `#[derive(Zeroize, ZeroizeOnDrop)]` to `NizkWitness` in `pvthfhe-fhe` | `real_nizk.rs:30` | 0.5 day |
| B.2 | Add `#[derive(Zeroize, ZeroizeOnDrop)]` to `NizkWitness` in `pvthfhe-nizk` | `nizk/lib.rs:58` | 0.5 day |
| B.3 | Verify both crates have `zeroize` in Cargo.toml dependencies (check workspace or add) | `Cargo.toml` files | 0.5 day |

## Batch C: Parallel NIZK Verify (F3)

| Task | Files | Effort |
|------|-------|--------|
| C.1 | Add `rayon = "1"` to `pvthfhe-cli/Cargo.toml` | `Cargo.toml` | 0.5 day |
| C.2 | Replace sequential verify loop with `rayon::par_iter()` — collect results, then call observer sequentially | `full_pipeline.rs:208-232` | 1 day |
| C.3 | Benchmark: n=32 time before/after, verify speedup ≥ 4× on 8-core | Manual run | 0.5 day |

## Batch D: C7 Merkle Real Data (F4)

| Task | Files | Effort |
|------|-------|--------|
| D.1 | Add integration test: extract real decryption share coefficients from pipeline, build Merkle tree, verify with C7 Merkle circuit | Integration test | 1 day |
| D.2 | Fix leaf_index limitation (currently only supports position 0) — document as deferred | `c7_merkle_circuit.rs` | 0.5 day |

## Batch E: Low Fixes (F6-F7)

| Task | Files | Effort |
|------|-------|--------|
| E.1 | Add `debug_assert!(dealer_index <= u32::MAX as usize)` before `as u32` cast | `nizk_share.rs:1547` | 0.5 day |
| E.2 | Add depth=0 and depth=1 tests for `num_circuits()` | `latticefold_circuit_family` tests | 0.5 day |

## Acceptance Criteria

- [ ] F1 documented as known Sonobe architecture limitation
- [ ] F2: Both NizkWitness structs zeroized on drop
- [ ] F3: NIZK verify speedup ≥ 4× on 8-core for n=32
- [ ] F4: Integration test passes with real data
- [ ] F6-F7: Edge case tests added
- [ ] Demo ACCEPT — both tracks
- [ ] All existing tests pass

## Execution Order

Batch B (Zeroize) → Batch C (rayon) → Batch D (C7 data) → Batch A (docs) → Batch E (edge cases)

Batches B, D, E can run in parallel (different files).
