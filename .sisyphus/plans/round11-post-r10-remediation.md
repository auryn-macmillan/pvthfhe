# Plan: Round 11 — Post-R10 Comprehensive Remediation

**Plan**: `round11-post-r10-remediation`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-15
**Audits**: Final surrogate sweep (31 surrogates), bugs + efficiency (10 findings), compromised node exploits (11 findings)

---

## Critical (5 — MUST FIX)

| ID | Finding | Source |
|----|---------|--------|
| **F1** | C7 batch algebra: `(Σλ)×(Σd)` ≠ `Σ(λ×d)` — soundness violation | Bugs |
| **F2** | Default build missing `pipeline-extra-checks` — all extra verifications skipped | Exploits N1 |
| **F3** | `verify_all_dealer_share_computations` and `verify_all_recipient_dkg_aggregations` use hardcoded synthetic data — never check real transcript | Exploits N2 |
| **F4** | Keygen NIZK stub: `nizk: vec![0x00,0x01]`, `encrypted_shares: vec![0x11,0x22]` | Surrogate C1 |
| **F5** | SURROGATE banners in aggregator + fhe build.rs — all 3 components still surrogate | Surrogate C3-C4 |

## High (5)

| ID | Finding | Source |
|----|---------|--------|
| **F6** | Noir `build_c7_prover_toml` hardcodes ALL fields to `0u64` — Noir verification is no-op | Bugs + Exploits N4 |
| **F7** | No plaintext binding in Nova C7 `ExternalInputs3` — aggregator can claim wrong plaintext | Exploits N4 |
| **F8** | `epoch_hash = [0u8; 32]` still in 6 files (binaries, examples, tests) | Surrogate H1 |
| **F9** | Seeded RNG in prove_step with no OsRng nonce mixing | Surrogate H2 |
| **F10** | Micronova tree XOR toy + zero root proof | Surrogate H4-H5 |

## Medium (5)

| ID | Finding | Source |
|----|---------|--------|
| **F11** | Sequential share evaluation — `.iter()` should be `.par_iter()` | Bugs |
| **F12** | LegacyLocalSmudge still active fallback in pipeline | Bugs |
| **F13** | Aggregator lacks RS consistency check | Exploits N3 |
| **F14** | 4 dead `fn placeholder() {}` | Surrogate M11 |
| **F15** | CLI subcommands marked "(stub)" | Surrogate C5 |

---

## Batch A: Critical — C7 Soundness + Default Build (F1-F3)

| Task | Files | Effort |
|------|-------|--------|
| A.1 | Fix C7 batch algebra: replace `(Σλ)×(Σd)` with `Σ(λ×d)` per batch, restructure Nova step semantics | `full_pipeline.rs:1379-1404` | 1 day |
| A.2 | Add `pipeline-extra-checks` to default features | `Cargo.toml:53` | 0.5 day |
| A.3 | Replace hardcoded synthetic data in `verify_all_dealer_share_computations` with transcript-derived values | `full_pipeline.rs:1246-1302` | 2 days |
| A.4 | Replace hardcoded synthetic data in `verify_all_recipient_dkg_aggregations` with actual DKG shares | `full_pipeline.rs:1133-1226` | 1 day |
| A.5 | RED tests: C7 batch algebra correct, default verifications run, stubs replaced | Tests | 2 days |

## Batch B: Keygen + Noir + Plaintext (F4-F7)

| Task | Files | Effort |
|------|-------|--------|
| B.1 | Replace keygen NIZK stub with real CycloNizkAdapter per dealer | `simulator.rs:332-354` | 3 days |
| B.2 | Wire real pipeline data into `build_c7_prover_toml` — replace 0u64 with actual Fr values in hex | `full_pipeline.rs:1419-1482` | 1 day |
| B.3 | Add plaintext binding to Nova C7 ExternalInputs3 or add post-prove check | `full_pipeline.rs:1403`, `c7_circuit.rs:53-70` | 1 day |
| B.4 | Remove SURROGATE banners from build.rs files | `aggregator/build.rs`, `fhe/build.rs` | 0.5 day |

## Batch C: Remaining (F8-F15)

| Task | Files | Effort |
|------|-------|--------|
| C.1 | Replace `epoch_hash = [0u8; 32]` in 6 files with session-derived SHA-256 | 6 files | 1 day |
| C.2 | Add OsRng nonce mixing to seeded ChaCha20Rng in prove_step | `sonobe/mod.rs:376-378,552-554,686-688` | 0.5 day |
| C.3 | Replace micronova XOR with real Cyclo fold | `micronova/tree.rs:29-30` | 1 day |
| C.4 | Fix sequential `.iter()` → `.par_iter()` for share evaluation | `full_pipeline.rs:1371` | 0.5 day |
| C.5 | Make LegacyLocalSmudge fallback emit `tracing::warn!` or hard-error | `full_pipeline.rs:697-715` | 0.5 day |
| C.6 | Remove 4 dead `fn placeholder() {}` | 4 files | 0.5 day |
| C.7 | Document CLI stub status in main.rs | `main.rs:43,52,61,70,82` | 0.5 day |

---

## Acceptance Criteria

- [ ] C7 batch algebra correct (A.1)
- [ ] Default build runs extra verifications (A.2)
- [ ] Keygen NIZK real, not stub (B.1)
- [ ] Noir Prover.toml uses real data (B.2)
- [ ] Plaintext binding enforced (B.3)
- [ ] Demo ACCEPT
- [ ] All RED tests pass

## Estimated Effort

~2-3 weeks. Batch A: 1 week. Batch B: 1 week. Batch C: 0.5 week.
