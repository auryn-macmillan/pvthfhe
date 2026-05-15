# Plan: Round 10 — Pre-Adversarial Remediation

**Plan**: `round10-adversarial-remediation`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-15
**Audits**: Rogue dealer (6 vectors), rogue participant (6 vectors), aggregator compromise (6 vectors)

---

## Findings Summary (18 findings, 3 audits)

### Critical (5)

| ID | Finding | Source |
|----|---------|--------|
| **F1** | `verify_shares()` checks each NIZK individually — NO cross-share polynomial consistency check. Dealer can create shares from different polynomials that all pass individually. | Dealer |
| **F2** | Share poisoning: individually-valid shares reconstruct garbage. `share_computation::verify_batched_share_computation` catches it but is opt-in (`pipeline-extra-checks`). | Dealer |
| **F3** | DKG simulator has NO adversarial resistance — stubbed NIZK (`[0x00,0x01]`), hardcoded encrypted shares (`[0x11,0x22]`), mock transcript hash. | Dealer |
| **F4** | Aggregator uses `payload.share` for aggregation but NEVER checks `payload.share.bytes == opened.statement.decrypted_share_bytes`. Party can submit Y while NIZK proves X. | Participant |
| **F5** | LegacyLocalSmudge NIZK binding: `expected_sk_agg_share = derive_party_binding(party_pk)` depends only on public key. Any key produces valid proof. RED test confirms. | Participant |

### High (5)

| ID | Finding | Source |
|----|---------|--------|
| **F6** | C3 gap: NIZK proves ciphertext well-formedness but NOT that the plaintext matches `share_commitment`. Dealer can encrypt share_A while committing to share_B. | Dealer |
| **F7** | `transcript_hash` is a literal mock (`"mock_cbor_hash_of_everything"`). Any transcript field can be modified without detection. | Aggregator |
| **F8** | No cryptographic proof of correct DKG key generation. `dkg_root` only hashes party_ids and PKs — no round2/round3 or aggregate PK binding. | Aggregator |
| **F9** | C7 Nova circuit has NO `aggregate_pk_hash` or plaintext binding. Noir circuit has it but is not wired into C7 flow. | Aggregator |
| **F10** | `epoch = [0u8; 32]` hardcoded in C7 verifier. Enables SRS reuse and deterministic proofs across sessions. Noir circuit's `epoch > 0` check bypassed. | Aggregator |

### Medium (5)

| ID | Finding | Source |
|----|---------|--------|
| **F11** | Threshold inflation possible (shares from degree > t-1 polynomial). Reed-Solomon check exists but is opt-in. | Dealer |
| **F12** | SmudgeSlotRegistry `slot_id` hardcoded to 1. One smudge slot per party per session. DoS risk if proof fails (slot consumed, can't retry). | Participant |
| **F13** | Two separate SmudgeSlotRegistry implementations (pvss vs keygen-spec). Only pvss version wired. Potential divergence. | Participant |
| **F14** | Aggregate PK not bound in C7 circuit. Noir circuit partially binds via `r` derivation but `d_commitment` excludes it. | Aggregator |
| **F15** | C7 verification gated behind `pipeline-extra-checks` + `sonobe-compressor` — in base config, no C7 verification runs. | Aggregator |

### Low (3)

| ID | Finding | Source |
|----|---------|--------|
| **F16** | Multiple share submission blocked by HashSet deduplication + DKG proof binding. | Participant |
| **F17** | `verify_tree()` defined but never called in production. | Aggregator |
| **F18** | Wire decoder lacks max-size limit on poly bytes (DoS risk, not crypto exploit). | Participant |

---

## Remediation Batches

### Batch A: Critical — Cross-Share Verification + Decrypt Share Binding (F1-F5)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| A.1 | Call `verify_batched_share_computation` UNCONDITIONALLY from `verify_shares`, not gated behind `pipeline-extra-checks` | `encrypt.rs:271-305`, `share_computation.rs:155` | 1 day |
| A.2 | Add cross-validation: `if payload.share.bytes.0 != opened.statement.decrypted_share_bytes { reject }` in `aggregate_decrypt` | `decrypt/mod.rs:334` | 0.5 day |
| A.3 | Document DKG simulator stubs in pipeline — note that keygen NIZK + encrypted shares are simulated | `full_pipeline.rs`, `SECURITY.md` | 0.5 day |
| A.4 | Deprecate LegacyLocalSmudge for production — enforce CommittedSmudge in default path | `decrypt/mod.rs:188` | 1 day |
| A.5 | RED tests: inconsistent shares rejected at verify_shares, decrypt byte mismatch rejected | Tests | 1 day |

### Batch B: High — C3 Gap + Transcript Integrity (F6-F10)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| B.1 | Wire Noir `aggregator_final` circuit into C7 flow: `nargo execute → bb prove → bb verify` as optional C7 phase | `full_pipeline.rs:1262-1338`, `pvthfhe_e2e.rs` | 3 days |
| B.2 | Replace mock `transcript_hash` with real SHA-256 over serialized transcript fields | `simulator.rs:287-290` | 0.5 day |
| B.3 | Replace `epoch = [0u8; 32]` with session-derived epoch (SHA-256 of session_id + seed) | `full_pipeline.rs:1316` | 0.5 day |
| B.4 | Add `aggregate_pk_hash` binding to C7 circuit external inputs | `c7_circuit.rs:53-70`, `c7_merkle_circuit.rs` | 1 day |
| B.5 | Document C3 gap status in SECURITY.md (improved but not fully closed) | `SECURITY.md:57` | 0.5 day |

### Batch C: Medium + Low (F11-F18)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| C.1 | Remove `pipeline-extra-checks` gate on C7 verification — make it unconditional | `full_pipeline.rs` | 0.5 day |
| C.2 | Add `slot_id` parameter to SmudgeSlotRegistry (not hardcoded to 1) — bound to ciphertext | `full_pipeline.rs:688` | 0.5 day |
| C.3 | Consolidate SmudgeSlotRegistry into single implementation | `slot_registry.rs`, `keygen-spec/src/lib.rs` | 1 day |
| C.4 | Add max byte limit on decrypt share poly deserialization | `wire.rs:120-137` | 0.5 day |

---

## Acceptance Criteria

- [ ] `verify_shares` performs Reed-Solomon parity check unconditionally (A.1)
- [ ] Decrypt share byte mismatch rejected (A.2)
- [ ] CommittedSmudge enforced in production path (A.4)
- [ ] Noir aggregator_final circuit optionally wired into C7 (B.1)
- [ ] Transcript hash is real (B.2)
- [ ] Epoch is session-derived, not zero (B.3)
- [ ] C7 verification is unconditional (C.1)
- [ ] Demo ACCEPT — all adversarial RED tests pass
- [ ] Existing tests pass (no regression)

## Execution Order

A (critical) → B (high, can overlap with C) → C (medium/low)

## Estimated Effort

~2 weeks. Batch A: 0.5 week. Batch B: 1 week. Batch C: 0.5 week.
