# MPC Audit Remediation Plan — 2026-06-07

**Source**: [MPC-AUDIT-2026-06-07.md](MPC-AUDIT-2026-06-07.md)
**Scope**: P1 + P2 findings (implementable; P0/G-N8/P4 deferred to research track)
**Methodology**: TDD — write RED tests first, then implement, verify GREEN
**Target**: 9 findings across 6 crates in 4 parallel workstreams
**Review**: Momus (ACCEPT-WITH-MODIFICATIONS, 2026-06-07) — M4 added, FF7 removed (already fixed), RED tests spec'd for FF6+H9

---

## Workstream 1: WITNESS INTEGRITY (FF1, FF2) · pvthfhe-nizk, pvthfhe-aggregator

### FF1: Wire Real NIZK Witness into Cyclo Fold Instance

**Files**:
- `crates/pvthfhe-aggregator/src/folding/mod.rs` (lines 414-456)
- `crates/pvthfhe-nizk/src/adapter.rs` (proof encoding)

**Steps**:
1. **TDD**: Add test `cyclo_instance_uses_real_witness` in `crates/pvthfhe-aggregator/tests/` that verifies `ccs_witness_bytes != demo_zero_witness_bytes()` after `fold_stmt_witness_to_cyclo_instance`
2. **Extract**: Add `extract_ccs_witness_from_proof(proof_bytes: &[u8]) -> Vec<u8>` to `adapter.rs` that parses the sigma witness segment from proof bytes (the `z_s` and `z_e` fields from each round)
3. **Wire**: In `fold_stmt_witness_to_cyclo_instance`, replace `demo_zero_witness_bytes()` with `extract_ccs_witness_from_proof(&witness.nizk_proof.proof_bytes)`
4. **Verify**: Run `cargo test -p pvthfhe-aggregator --features real-folding`

### FF2: Require Exact Witness Length

**Files**:
- `crates/pvthfhe-nizk/src/adapter.rs` (lines 374-381, 507-512)

**Steps**:
1. **TDD**: Add test `validate_witness_rejects_short` and `validate_witness_rejects_long` in `crates/pvthfhe-nizk/tests/`
2. **Fix**: Modify `validate_witness` to check `secret_share_poly.len() == rlwe_n()` and `error.len() == rlwe_n()`
3. **Remove**: Delete `pad_or_truncate_to_rlwe_n` usage from the prove path (line 95-96); keep function for backward compat or add `#[deprecated]`
4. **Update**: Ensure `NizkWitness` construction in `nizk_decrypt.rs` and test harnesses provides exactly `rlwe_n()` coefficients
5. **Verify**: `cargo test -p pvthfhe-nizk` (sigma adversarial tests must still pass)

---

## Workstream 2: KEY INTEGRITY (FF5) · pvthfhe-nizk, pvthfhe-keygen

### FF5: Add Schnorr Proof-of-Possession

**Files**:
- `crates/pvthfhe-nizk/src/schnorr.rs`

**Steps**:
1. **TDD**: Add tests `schnorr_pop_honest_verifies`, `schnorr_pop_wrong_key_rejected`, `schnorr_pop_replay_rejected`
2. **Implement**: Add `prove_pop(sk: &Fr, pk: &G1Affine, rng: &mut dyn RngCore) -> SchnorrPop` and `verify_pop(pk: &G1Affine, pop: &SchnorrPop) -> bool`
3. **Domain tag**: Use `pvthfhe_domain_tags::Tag::SchnorrPop` (add if missing)
4. **Integrate**: In DKG Round 1 (`pvthfhe-keygen`), verify PoP before accepting any party's public key
5. **Verify**: `cargo test -p pvthfhe-nizk -- schnorr`

---

## Workstream 3: SESSION BINDING (FF10) · pvthfhe-nizk, pvthfhe-lazer

### FF10: Bind Session/Party to LaZer Proofs

**Files**:
- `crates/pvthfhe-nizk/src/lazer_bridge.rs` (lines 270-340)

**Steps**:
1. **TDD**: Add test `lazer_session_binding_changes_proof` — verify that changing `session_id` produces different proof bytes
2. **Investigate**: Check lazer C API (`pvthfhe-lazer`) for session/participant binding hooks
3. **Fix Option A** (if C API supports it): Pass `session_id` and `participant_id` as relation parameters
4. **Fix Option B** (fallback): In Rust, pre-hash `session_id || participant_id` into the witness commitment or statement before calling LaZer:
   ```rust
   let binding = Sha256::new()
       .chain_update(pvthfhe_domain_tags::Tag::LazerSessionBinding.as_bytes())
       .chain_update(session_id.as_bytes())
       .chain_update(participant_id.to_be_bytes())
       .finalize();
   // Mix binding into witness or statement used by LaZer
   ```
5. **Remove**: `let _ = _session_id` and `let _ = _participant_id` discards
6. **Verify**: `cargo test -p pvthfhe-nizk -- lazer`

---

## Workstream 4: DEFENSE-IN-DEPTH (FF6, FF7, H9, M9) · pvthfhe-nizk, pvthfhe-domain-tags

### FF6: Add Label Binding to FS Challenge Expansion

**File**: `crates/pvthfhe-nizk/src/fiat_shamir.rs` (line 102-105)

**Steps**:
1. **TDD**: Add RED tests in `crates/pvthfhe-nizk/tests/fs_domain.rs`:
   - `label_binding_changes_challenge_output`: Two identical transcripts with different labels produce different challenge bytes
   - `label_binding_same_label_same_output`: Two identical transcripts with same label produce identical challenge bytes (determinism check)
2. **Fix**: Add label to each counter-mode block:
```rust
let mut h = Sha256::new();
h.update(label);
h.update(counter.to_be_bytes());
h.update(state);
```
3. **Verify**: `cargo test -p pvthfhe-nizk -- fs_domain`

### FF7: Return Error Instead of Panicking in Poseidon — ✅ ALREADY FIXED

**File**: `crates/pvthfhe-nizk/src/sigma.rs` (line 725)

**Status**: Code already uses `map_err(|_| NizkError::VerificationFailed(...))?`. No action needed. Confirmed via Momus review.

### H9/M2: Consolidate Inline Domain Strings

**Files**: `sigma.rs`, `schnorr.rs`, `greyhound_pcs.rs`, `hash_bridge.rs`

**Steps**:
1. **TDD**: Add lint test `all_domain_tags_are_declared` that greps for inline `b"..."` in hash operations outside `domain_tags/src/lib.rs` (excluding tests)
2. Audit: List all inline `b"..."` strings in hash operations:
   - `b"pvthfhe-d2-hash-bridge/v1"` → Need `Tag::HashBridgeCommit` (not in lib.rs)
   - `b"pvthfhe-schnorr-pop-v1"` → Need `Tag::SchnorrPop` (not in lib.rs)
   - `b"greyhound-A"`, `b"greyhound-B"`, `b"greyhound-D"` → Need `Tag::GreyhoundA/B/D` variants (not in lib.rs)
   - `b"t2-commit"` and `b"t2-commit-ch"` → Already covered by `Tag::SigmaScalarChallenge`
3. Add missing tags to `pvthfhe-domain-tags/src/lib.rs`
4. Replace raw strings with `Tag::*.as_bytes()` references
5. **Verify**: `cargo test -p pvthfhe-domain-tags`, `cargo test -p pvthfhe-nizk`, `cargo test -p pvthfhe-compressor`

### M4: Populate contextId Instead of Hardcoded bytes32(0)

**File**: `contracts/src/PvtFheVerifier.sol` (line 581)

**Steps**:
1. **TDD**: Add RED test in `PvtFheVerifier.t.sol`: `testContextIdIsNotEmpty()` — verifies `contextId != bytes32(0)` in the verification statement during an honest test run
2. **Fix**: Derive `contextId` as `keccak256(abi.encode(sessionId, epoch, contextLabel))` where `contextLabel` is a protocol identifier (e.g., `"pvthfhe/v1"`)
3. **Verify**: `forge test --root contracts --match-test testContextId`

### M9: Remove fiat_shamir.rs Counter-Mode Defense Gap

**Already covered by FF6.** No additional work needed.

---

## Documentation Sync

### Files to Update

| File | Current Issue | Fix |
|------|--------------|-----|
| `README.md` | Status table: "Compute: Verifiable FHE ops ✅" | Change to "⚠️ Add only (Mul unproven, N=4 demo)" |
| `SECURITY.md` | §Implementation Status: "Verifiable FHE ops: FHE Add only; Mul at N=4 demo scale" — accurate but hidden | Promote to visible caveat in "Known Limitations" |
| `WARNING.md` | "C7/A1/C5 status outdated (still shows OPEN for RESOLVED items)" | Update to reflect C7 ✅ RESOLVED, A1 ✅ RESOLVED, C5 ✅ RESOLVED |
| `ARCHITECTURE.md` | "Compute: Verifiable FHE ops ✅" | Change to "⚠️ Add only" |
| `spec-real-p2p3.md` §3.4 | Missing `sigma_proof_bytes` SPEC EXTENSION | Add documentation of sigma proof byte layout |
| `paper/main.tex` | May reference old surrogate status | Verify and update claims table |
| `STATUS.md` | Check if exists and needs update | Audit and update |

---

## Verification Gates

After all fixes are applied:

```bash
# Rust tests
cargo test -p pvthfhe-nizk
cargo test -p pvthfhe-aggregator --features real-folding
cargo test -p pvthfhe-cyclo
cargo test -p pvthfhe-domain-tags
cargo test -p pvthfhe-pvss
cargo test -p pvthfhe-keygen
cargo test -p pvthfhe-compressor

# Noir circuits
(cd circuits && nargo test --package aggregator_final)
(cd circuits && nargo test --package decrypt_share)

# Solidity
forge test --root contracts

# Full build
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build
just demo-e2e

# LSP diagnostics on changed files
# All must be clean (0 errors)
```

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| FF1 real witness extraction breaks Cyclo fold compatibility | Roll back to demo witness; document gap explicitly |
| FF2 exact-length check breaks existing test vectors | Update test fixtures to use full N=8192 witnesses |
| FF5 Schnorr PoP breaks DKG wire format | Version bump proof format; backward-compat decode |
| FF10 LaZer C API doesn't support session binding | Fall back to Option B (Rust-side pre-hashing) |

---

## Estimated Effort

| Workstream | Estimate | Can Parallelize? |
|-----------|---------|-----------------|
| WS1: Witness Integrity (FF1+FF2) | 2 hours | ✅ with WS2, WS3, WS4 |
| WS2: Key Integrity (FF5) | 1.5 hours | ✅ with WS1, WS3, WS4 |
| WS3: Session Binding (FF10) | 1.5 hours | ✅ with WS1, WS2, WS4 |
| WS4: Defense-in-Depth (FF6+FF7+H9) | 1 hour | ✅ with WS1, WS2, WS3 |
| Doc sync | 30 min | After code changes |
| Verification (all gates) | 30 min | After all changes |

**Total**: ~4 hours (parallel) + 1 hour (sequential verification + doc)
