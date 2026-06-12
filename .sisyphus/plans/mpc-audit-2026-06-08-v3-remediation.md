# MPC Audit Remediation Plan — v3 (2026-06-08)

**Source**: MPC-AUDIT-2026-06-08-v3 (this audit)
**Status**: ✅ IMPLEMENTED (2026-06-08)
**Model**: Actively malicious adversary, only verifier trusted

---

## P0: FN1 — Fix `derive_challenge` Return Type u64 → u128 (MEDIUM)

### Problem
`crates/pvthfhe-cyclo/src/fold.rs:62` extracts 64 bits (8 bytes) from the 256-bit SHA-256 challenge hash via `u64::from_le_bytes(h[..8].try_into().unwrap())`. This is an improvement from the earlier 16-bit extraction (F0), but the recommended 128-bit field extraction provides conservative soundness margin. At 64 bits with T=10 rounds, the exponential soundness bound (|C|^-T ≈ 2^-640) dominates, but cryptographic conservatism favors using the full 128 bits to ensure the linear bound (T/|C|) stays firmly below 2^-128.

### Fix
1. Change `derive_challenge` return type from `u64` to `u128`.
2. Extract 128 bits (16 bytes) instead of 64 bits (8 bytes).
3. Update `scalar_mul` in `ring.rs` to accept `u128` (parameter flows from `derive_challenge` output). Internally already uses `u128` for intermediate product, so change is mechanical.
4. Update `public_io_v1` in `fiat_shamir.rs` to accept `r_value: u128` (flows from fold.rs:212).
5. Update test at `tests/challenge_entropy.rs` for `u128` type compatibility.
6. `params_digest` already passed (N1 fixed); `challenge_v2` already returns `[u8; 32]` (no change needed there).

### Files changed
- `crates/pvthfhe-cyclo/src/fold.rs` — `derive_challenge`, callers (`fold_one_deterministic_inner`, caller at line 205 `scalar_mul`, line 218 `public_io_v1`)
- `crates/pvthfhe-cyclo/src/ring.rs` — `scalar_mul` signature: `s: u64` → `s: u128`
- `crates/pvthfhe-cyclo/src/fiat_shamir.rs` — `public_io_v1` signature: `r_value: u64` → `r_value: u128`
- `crates/pvthfhe-cyclo/tests/challenge_entropy.rs` — test challenge helper type

### Tests needed
- `test_derive_challenge_has_128_bit_entropy` — verify u128 value uses all 16 bytes
- Update existing fold tests to compile with `u128` return type

### Verification
```bash
cargo test -p pvthfhe-cyclo -- fold
cargo test -p pvthfhe-cyclo -- challenge_entropy
```

---

## P1: FF10 — Inject LaZer Session/Party Binding Into C Library (MEDIUM)

### Problem
`crates/pvthfhe-nizk/src/lazer_bridge.rs:283-310` computes `lazer_session_binding(session_id, participant_id)` (domain-tagged SHA-256 via `Tag::LazerSessionBinding`) but stores it only as `let _binding = ...`. The binding is NOT passed to the LaZer C library (`lazer::lin_prove()` on line 297). The verifier path (line 341) identically discards the binding.

While the NIZK adapter layer cross-checks session_id and participant_id independently (`adapter.rs:185-190`), the LaZer proof itself carries no cryptographic binding to these identities, creating a defense-in-depth gap.

### Fix
Two approaches, ordered by preference:

**Option A (preferred):** Inject the binding into the LaZer relation context.
1. Compute `binding = lazer_session_binding(session_id, participant_id)`.
2. If the LaZer C API supports witness/statement injection per-proof, pass `binding` as additional witness material.
3. If the LaZer C API does NOT support this, XOR the binding bytes into the statement data hash before passing to `lazer::lin_prove`.

**Option B (fallback):** Strengthen adapter-layer defense.
1. Document that LaZer proof binding is enforced at the adapter layer (already done — comment at lines 292-295).
2. Add an integration test that verifies: a LaZer proof produced for (session_A, party_1) is REJECTED when verified against (session_B, party_1) by the adapter layer.
3. Add an integration test that verifies: a LaZer proof produced for (session_A, party_1) is REJECTED when verified against (session_A, party_2).

### Files changed
- `crates/pvthfhe-nizk/src/lazer_bridge.rs` — `prove`, `verify`, `lazer_session_binding`
- `crates/pvthfhe-nizk/tests/` — new integration tests

### Tests needed (for Option B)
- `test_lazer_proof_session_binding_rejection` — different session ID
- `test_lazer_proof_participant_binding_rejection` — different participant ID

### Verification
```bash
cargo test -p pvthfhe-nizk -- lazer --features enable-lazer
```

---

## P2: FN2 — Replace Sigma Challenge Fallback With Error Return (LOW)

### Problem
`crates/pvthfhe-nizk/src/sigma.rs:694-697` silently returns challenge `0` when Poseidon hash fails:
```rust
let ch_fr = match poseidon_hash(&[lo, hi]) {
    Ok(fr) => fr,
    Err(_) => return 0,  // silent fallback
};
```

When the challenge is 0, the sigma response `z_s = y_s + 0·s_i = y_s` (mask only), which provides zero soundness for that round. Since 90 rounds are used, one wasted round is negligible, but the silent nature means no diagnostic or defense escalation occurs.

### Fix
Return an error instead of silent `0`:
```rust
let ch_fr = poseidon_hash(&[lo, hi])?;
```
This propagates `NizkError::VerificationFailed("Poseidon hash failed")` up the call chain. Requires changing `derive_challenge_from_commitment` return type from `i64` to `Result<i64, NizkError>` (the `?` operator requires this). All call sites are already in `Result`-returning functions so `?` works cleanly.

### Files changed
- `crates/pvthfhe-nizk/src/sigma.rs` — `derive_challenge_from_commitment` return type: `i64` → `Result<i64, NizkError>`; line 694-697: `return 0` → `poseidon_hash(...)?`
- `crates/pvthfhe-nizk/src/sigma.rs` — call sites at lines 315, 452: add `?` to `derive_challenge_from_commitment(...)` calls; test call sites at ~lines 1199, 1206: add `.unwrap()` or similar
- `crates/pvthfhe-nizk/src/lib.rs` — re-export signature update

### Tests needed
- Existing sigma tests need mechanical update (`.unwrap()` at call sites for `derive_challenge_from_commitment`).

### Verification
```bash
cargo test -p pvthfhe-nizk -- sigma
```

---

## Non-Code Items: Documentation Sync

### SECURITY.md Updates
- Update "Latest audit" section to reference v3 audit.
- Update F0 status: 16-bit → 64-bit partial fix noted; 128-bit planned in FN1.

### docs/OPEN-PROBLEM-BLOCKERS.md Updates
- No new open problems introduced. P1, P2, P4, G-N8 statuses unchanged.

---

## Summary

| Priority | Finding | Fix | Effort | Files |
|----------|---------|-----|--------|-------|
| P0 | FN1 (u64 → u128) | Change return type + extraction | 2 lines + caller updates | `fold.rs` |
| P1 | FF10 (LaZer binding) | Inject binding or strengthen tests | Small | `lazer_bridge.rs` + tests |
| P2 | FN2 (silent fallback) | `return 0` → `?` | 1 line | `sigma.rs` |

**Total estimated effort**: ~30 minutes for all code fixes + test verification.
