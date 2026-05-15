# Plan: P1-T3 — Verify and Document Zero-Knowledge of Serialized NIZK Proofs

**Plan**: `p1-t3-zk-verify-document`
**Status**: COMPLETE (superseded by p1-t3-zk-full.md RESOLVED)
**Created**: 2026-05-14
**Updated**: 2026-05-14 — findings from code inspection
**Goal**: Verify that the serialized share NIZK proof achieves computational zero-knowledge, document the proof, and add a RED regression test for the serialized byte format.

---

## Context

### Current state (verified)

The `ShareNizkOpenedProof` struct does **not** contain witness openings. A REGRESSION TEST `nizk_share_no_witness_leak.rs` actively prevents witness fields from being added. The test passes.

The serialized proof contains only:
- Statement fields (public)
- Commitment hash bindings (public, non-revealing)
- The sigma transcript `(t_bytes, z_s, z_e)` — computational ZK because:
  - `t_bytes` commits to fresh random masks `y_s, y_e`
  - `z_s = y_s + c·s` (masked by random y_s)
  - `z_e = y_e + c·e` (masked by random y_e)
- The BFV encryption sigma proof — also ZK (sigma protocol)

### What changed from the initial plan

The initial plan assumed witness openings (`secret_share_open`, `error_open`) existed in the serialized proof. They don't. The plan has been simplified from "remove openings + create ZK variant" to "verify ZK status + document + add regression test."

### Security analysis

The sigma protocol transcript IS computational ZK under:
1. Fresh random masks per proof (`OsRng`, non-deterministic)
2. HVZK property of the sigma protocol
3. Fiat-Shamir ROM compilation

A verifier learns:
- That the prover knows some witness `(s, e)` satisfying the statement
- Nothing about `s` or `e` beyond what the public statement already reveals

The statement itself (`ShareNizkStatement`) contains public data only — participant keys, ciphertext references, DKG roots.

---

## Implementation

### ZK.1 — Add RED regression test for byte-level ZK

**File**: `crates/pvthfhe-pvss/tests/nizk_zk_regression.rs` (new)

Test that serialized proof bytes contain no witness information:
1. `zk_proof_bytes_contain_no_share_values` — parse a real proof, extract all integer-looking byte sequences, verify none match the actual secret share / error values
2. `zk_proof_bytes_are_identical_for_same_witness` — deterministic prover produces identical bytes for same inputs (no randomness leak beyond commitment)
3. `zk_proof_bytes_differ_for_different_masks` — different random masks produce different `t_bytes` and `z_s`/`z_e` (confirming masking)

### ZK.2 — Update P1-T3 proof document

**File**: `docs/security-proofs/p1/T3.md`

Update the theorem scope from "projected SLAP core transcript" to "serialized ShareNizkProof." Remove the caveat about "the current prototype appends explicit witness openings" — that doesn't apply. Add note about the regression test enforcing ZK at the serialization level.

### ZK.3 — Update P1-T3 plan

**File**: `.sisyphus/plans/p1-t3-zk-full.md`

Mark as RESOLVED. Note that the serialized proof is ZK, confirmed by code inspection and regression test. The M1 design question (audit-field exposure) is answered: no audit fields exist in the serialized proof.

### ZK.4 — Update SECURITY.md

**File**: `SECURITY.md`

Update P1 section: note that serialized share NIZK proofs achieve computational ZK (masked sigma transcript, fresh randomness per proof). Remove or update the audit-field exposure note.

---

## Acceptance Criteria

- [ ] RED regression test passes — serialized proof bytes contain no witness values
- [ ] `nizk_share_no_witness_leak` test still passes (struct-level check)
- [ ] P1-T3 proof document updated (scope expanded to serialized form)
- [ ] P1-T3 plan marked RESOLVED
- [ ] SECURITY.md updated
- [ ] Demo ACCEPT
- [ ] No proof format changes needed

## Non-Goals

- Changing the proof serialization format (it's already ZK)
- Adding new proof variants (not needed)
- Rewriting P1-T2 extractor (blocked on Lemma 9 anyway)

## Estimated Effort

~2 hours. No code changes to the proof system — documentation + tests only.

