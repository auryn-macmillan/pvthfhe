# Plan: Round 6 — Adversarial Audit Remediation

**Plan**: `round6-adversarial-remediation`
**Status**: DRAFT
**Created**: 2026-05-14
**Audits**: NIZK soundness, threshold/robustness, replay/splicing/timing, DKG+compressor+fold

---

## Findings Summary

### Critical (3)

| ID | Finding | Source |
|----|---------|--------|
| **F1** | SmudgeSlotRegistry enforcement gated behind `pipeline-extra-checks` — no freshness enforcement in default build | Replay |
| **F2** | `aggregate_decrypt` does not verify `session_id` against external expectation — cross-session replay possible if session_id ≠ dkg_root | Replay |
| **F3** | Keygen NIZK is a stub `[0x00, 0x01]` with whitespace validation (only `[0xBA, 0xAD]` rejected) | DKG |

### High (6)

| ID | Finding | Source |
|----|---------|--------|
| **F4** | `e_i = 0` in algebraic proof — weaker relation than proper RLWE | NIZK |
| **F5** | Circular pvss_commitment in algebraic proof (`SHA256(d_rns)` instead of real P4 commitment) | NIZK |
| **F6** | BFV sigma `derive_challenge` has no internal session binding — relies entirely on caller | NIZK |
| **F7** | Real backend `aggregate_keygen()` misses duplicate party_id check (mock has it) | Threshold |
| **F8** | FHE backend `aggregate_decrypt()` has no session_id parameter — caller can decrypt cross-session | Threshold |
| **F9** | `share_proof_dkg_root` silently falls back to `session_id` when `dkg_root` is empty | Replay |

### Medium (5)

| ID | Finding | Source |
|----|---------|--------|
| **F10** | D2 hash binding does not include `dkg_root` | Replay |
| **F11** | Compressor hash-accumulates, does not perform lattice-native Ajtai folding (P3) | DKG |
| **F12** | 64-bit epoch entropy (seed → only 8 bytes used for epoch_hash) | DKG |
| **F13** | No CCS satisfiability check at `init_accumulator` — deferred to `verify_fold` | DKG |
| **F14** | Ajtai witness bound enforced only at commit time, never verified | NIZK |

---

## Remediation Batches

### Batch A: Critical Security (F1-F3)

| ID | Task | Files |
|----|------|-------|
| A.1 | Remove `#[cfg(feature = "pipeline-extra-checks")]` gate on SmudgeSlotRegistry; make enforcement unconditional | `full_pipeline.rs:571-576` |
| A.2 | Add `session_id` equality check in `aggregate_decrypt` pre-checks | `decrypt/mod.rs:309-313` |
| A.3 | Add `session_id` parameter to `FhersBackend::aggregate_decrypt()` or deprecate session-less variant | `fhers.rs:1125` |
| A.4 | Wire `CycloNizkAdapter` per dealer for real keygen NIZK (or document as simulator-limitation) | `simulator.rs:208,334` |

### Batch B: NIZK Hardening (F4-F6, F14)

| ID | Task | Files |
|----|------|-------|
| B.1 | Fix e_i=0 in algebraic proof — propagate actual error from witness or document binding trade-off | `nizk_share.rs:555` |
| B.2 | Replace `test_digest_sigma_d(&d_rns)` with real `stmt.pvss_commitment` in algebraic proof Fiat-Shamir | `nizk_share.rs:571,1130` |
| B.3 | Add internal session/participant binding to `bfv_sigma::derive_challenge` (defense-in-depth) | `bfv_sigma.rs:389` |
| B.4 | Document Ajtai witness bound verification gap (only at commit, not verify) | `SECURITY.md` |

### Batch C: Aggregation + Threshold Defense (F7-F8, F10)

| ID | Task | Files |
|----|------|-------|
| C.1 | Add duplicate party_id check to `FhersBackend::aggregate_keygen()` (match mock) | `fhers.rs:624-686` |
| C.2 | Add `dkg_root` binding to D2 hash in share NIZK | `nizk_share.rs:1233-1247` |

### Batch D: Infrastructure Hardening (F9, F12-F13)

| ID | Task | Files |
|----|------|-------|
| D.1 | Add assert/error when `dkg_root` is empty and `share_proof_dkg_root` falls back to `session_id` | `encrypt.rs:405-411` |
| D.2 | Expand epoch_hash to full 32 bytes (Keccak256 of seed) | `full_pipeline.rs:433-434` |
| D.3 | Add `check_satisfiability()` at `init_accumulator_inner` for defense-in-depth | `fold.rs:82-113` |

### Batch E: Documentation + Tests

| ID | Task | Files |
|----|------|-------|
| E.1 | Update SECURITY.md with adversarial audit findings | `SECURITY.md` |
| E.2 | Write RED tests: cross-session replay, duplicate keygen share, empty NIZK, large witness Ajtai | Tests |
| E.3 | Verify demo + benchmark still ACCEPT | Run |

---

## Verification

```bash
cargo build --workspace
just demo-e2e              # Track B → ACCEPT
just demo-e2e 32 14        # Large n → ACCEPT
```

## Execution Order

A (critical) → B+C (parallel, different files) → D → E
