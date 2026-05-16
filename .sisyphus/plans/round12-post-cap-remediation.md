# Plan: Round 12 — Post-Cap-Removal Remediation

**Plan**: `round12-post-cap-remediation`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-16
**Audits**: Surrogate/gap sweep (12 findings), bug/soundness (9 bugs), rogue node exploits (8 vectors)

---

## Critical (2)

| ID | Finding | Audit |
|----|---------|-------|
| **F1** | u16 `unwrap_or(0)` silently corrupts `recipient_id` for n≥65536 in 5 files | Bug |
| **F2** | Static `Prover.toml` read directly in `pvthfhe_e2e.rs:359` — Noir verifies hardcoded data, not real pipeline values | Surrogate |

## High (5)

| ID | Finding | Audit |
|----|---------|-------|
| **F3** | `compute_party_sk_sums` O(n²) allocation up to ~844 TB at n=65535 — no memory budget | Bug |
| **F4** | Cyclo CCS `participant_id: u16` type-level cap on P2/P3 folding pipeline | Bug |
| **F5** | `setup_threshold` backend API lacks `max_t = (n-1)/2` enforcement | Rogue |
| **F6** | Enclave SGX DCAP `verify_proof` always returns `false` — deferred | Surrogate |
| **F7** | `party_secret_key_bytes()` etc. unconditionally `pub` — exfiltrate-able | Rogue |

## Medium (4)

| ID | Finding | Audit |
|----|---------|-------|
| **F8** | `as u16` truncation in `full_pipeline.rs:1147,1252,1266` for share verification at n>65535 | Bug |
| **F9** | 5 surrogate/mock features (`surrogate-decrypt-share`, `surrogate-compressor`, `mock`, `legacy-fold`, `stub`) can be accidentally enabled | Surrogate |
| **F10** | `#![allow(dead_code)]` blanket on production crate `aggregator/src/lib.rs` | Surrogate |
| **F11** | `build.rs` still prints "SURROGATE" warning (folding is real) | Surrogate |

---

## Remediation Batches

### Batch A: Critical — u16 Overflow + Noir Fix (F1-F2)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| A.1 | Replace `unwrap_or(0)` / `unwrap_or(u16::MAX)` with `?` error propagation in 5 files | `full_pipeline.rs:638,642`, `decrypt/mod.rs:184`, `folding/mod.rs:349`, `simulator.rs:510` | 1 day |
| A.2 | Replace `as u16` casts at L1147,1252,1266 with `u16::try_from().context()` | `full_pipeline.rs` | 0.5 day |
| A.3 | Fix `pvthfhe_e2e.rs:359` to call `build_c7_prover_toml()` instead of reading static `Prover.toml` | `pvthfhe_e2e.rs` | 0.5 day |
| A.4 | RED tests: n=65536 → proper errors, n=200 → Noir data is real | Tests | 1 day |

### Batch B: High — Memory Budget + API Fixes (F3-F7)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| B.1 | Add practical n-cap (1024) in `compute_party_sk_sums` before O(n²) allocation | `fhers.rs:337-341` | 0.5 day |
| B.2 | Add `max_t = (n-1)/2` check in `setup_threshold` backend API | `fhers.rs:641` | 0.5 day |
| B.3 | Document Cyclo CCS `participant_id: u16` limitation in SECURITY.md — requires wire format v2 bump | `SECURITY.md` | 0.5 day |
| B.4 | Feature-gate `party_secret_key_bytes`, `esm_noise_poly_for`, `store_esm_noise_poly_bytes` behind `benchmark-internals` | `fhers.rs` | 1 day |
| B.5 | Document SGX DCAP deferral in enclave-adapter README | `enclave-adapter/README.md` | 0.5 day |

### Batch C: Medium (F8-F11)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| C.1 | Target `#[allow(dead_code)]` to specific items instead of crate-level blanket | `aggregator/src/lib.rs:2` | 0.5 day |
| C.2 | Remove "SURROGATE" warning from `build.rs` (folding is real) | `aggregator/build.rs`, `fhe/build.rs` | 0.5 day |
| C.3 | Document surrogate/mock features in SECURITY.md with build-time guard recommendations | `SECURITY.md` | 0.5 day |

---

## Acceptance Criteria

- [ ] n=65536 produces clear `anyhow::Error` at CLI entry, not silent data corruption
- [ ] Noir C7 generates real `Prover.toml` in both `full_pipeline.rs` AND `pvthfhe_e2e.rs` paths
- [ ] `setup_threshold` rejects `t > (n-1)/2` at backend API level
- [ ] `compute_party_sk_sums` rejects `n > 1024` with clear error
- [ ] Internal key material APIs gated behind `benchmark-internals` feature
- [ ] Demo ACCEPT at n≤255, errors clearly at n>cap
- [ ] All existing tests pass

## Estimated Effort

~1 week. Batch A: 3 days. Batch B: 2.5 days. Batch C: 1.5 days. Batches A and B can run in parallel (different files).
