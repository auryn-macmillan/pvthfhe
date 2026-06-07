# MPC Audit 2026-06-06 (Fresh) — Remediation Plan

**Plan**: `mpc-audit-2026-06-06-fresh-remediation`
**Audits**: 
- `.sisyphus/audit/MPC-AUDIT-2026-06-06-FRESH.md` — 15 fresh findings (1C, 5H, 5M, 4L)
- `.sisyphus/audit/MPC-AUDIT-2026-06-06.md` — 12 prior findings (3C, 4H, 3M, 2L), all still unfixed
- `.sisyphus/audit/MPC-AUDIT-2026-06-05.md` — 5 remaining open (H6-P1-3a, M2, M4, M8, L3)
**Total findings to address**: 33 (5 CRITICAL, 10 HIGH, 10 MEDIUM, 8 LOW)
**Baseline**: Git HEAD
**Constraint**: TDD RED→GREEN→GATE. Stub protocol: replace in place, never delete-and-recreate.

---

## Task Dependency Graph

```
P0-1 (G-N8) ───┐
                ├─► P0-2 (S1) ──► Documentation
P0-3 (S2) ─────┘

P1-1 (F1-DomainSep) ── independent
P1-2 (F2/H7-WitnessLen) ── independent
P1-3 (F3/M10-CycloBind) ── independent
P1-4 (F4-RealWitness) ── independent
P1-5 (H8-SchnorrPoP) ── independent
P1-6 (H9+Tags) ── P1-6a (register) → P1-6b (replace)
P1-7 (H6-TFHE) ── independent

P2-1 (F5-BatchSession) ── independent
P2-2 (F6-DealerIndex) ── independent
P2-3 (F7-PvssCommitment) ── independent
P2-4 (M9-FSChallenge) ── independent
P2-5 (M2-DomainTags) ── covered by P1-6
P2-6 (M4-ContextId) ── independent
P2-7 (M8-NoirBFV) ── independent

P3-1 (F8-F11, L6, L7, L3) ── independent cleanup

P4 (Documentation) ── depends on P0, P1
```

---

## Parallel Workstreams

| Stream | Findings | Key Files | Effort |
|--------|----------|-----------|--------|
| **S0: Circuit + Transcript** | G-N8, S1, S2 | `circuits/`, `pvthfhe-compressor/`, `adapter.rs` | HIGH |
| **S1: NIZK Binding** | F1, F2/H7, F3/M10, F4 | `pvthfhe-nizk/adapter.rs`, `pvthfhe-cyclo/fiat_shamir.rs`, `aggregator/folding/mod.rs` | MEDIUM |
| **S2: Key Integrity** | H8, H6-P1-3a, F6 | `pvthfhe-nizk/schnorr.rs`, `tfhe_ops.rs`, `pvss/lib.rs` | MEDIUM |
| **S3: Domain Tags** | H9, M2, F5 | `domain-tags/`, 7 source files | LOW |
| **S4: Crypto Hygiene** | M9, F7, M4, L6, L7, F9, F10, F11 | Multiple scattered | LOW |
| **S5: Documentation** | README/ SECURITY/ WARNING/ spec | 4 files | LOW |
| **S6: Contracts** | L3, F8 (verify) | `PvtFheVerifier.sol` | LOW |

---

## Wave P0 — CRITICAL (5 findings)

### P0-0: F0 — Fix 16-bit Fold Challenge to Full-Field Challenge

**Description**: `derive_challenge()` in `fold.rs:60` extracts only 16 bits (2 bytes) from a 256-bit hash, giving 2^-16 soundness. Replace with full field element reduction from the entire 32-byte hash.

**Files**:
- `crates/pvthfhe-cyclo/src/fold.rs:46-61` — replace `u64::from(u16::from_le_bytes([h[0], h[1]]))` with `Fr::from_le_bytes_mod_order(&h)`
- All call sites in `fold.rs` — update challenge type from `u64` to `Fr`

**RED test**: Challenge statistics show only 16-bit entropy distribution
**GREEN tests**: `test_fold_challenge_is_full_field`, `test_fold_challenge_variants`

**Effort**: ~1 hour. **ABSOLUTE HIGHEST PRIORITY** — this breaks Cyclo folding soundness.

---

### P0-1: G-N8 — N=8 Circuit vs N=8192 Production

**Description**: Circuit operates on N=8, production uses N=8192. Fix: implement native multi-point Schwartz-Zippel verifier that checks consistency between N=8 circuit projections and N=8192 plaintext.

**Files**:
- `crates/pvthfhe-cli/src/full_pipeline.rs` — add `verify_multi_point_sz_projection()`
- `crates/pvthfhe-nizk/src/adapter.rs` — wire into verify path
- `circuits/aggregator_final/src/main.nr` — update N=8 limitation comment
- `docs/OPEN-PROBLEM-BLOCKERS.md` — update G-N8 status

**RED test**: Multi-point S-Z rejects inconsistent N=8→N=8192 projection
**GREEN tests**: `test_g8_multi_point_consistent`, `test_g8_multi_point_rejects_inconsistent`

📝 **DEFERRED**: Full N=8192 circuit scaling postponed to T42 (pre-audit milestone). This task implements defense-in-depth only.

---

### P0-2: S1 — Unify Native/Circuit Transcripts

**Description**: Bind C7 circuit's Schwartz-Zippel challenge `r` into sigma protocol native transcript (bidirectional binding).

**Files**:
- `crates/pvthfhe-nizk/src/adapter.rs` — add `r` to sigma binding
- `crates/pvthfhe-nizk/src/sigma.rs` — pass `r` through prove/verify
- `circuits/aggregator_final/src/main.nr` — expose `sigma_binding_hash` as public input
- `crates/pvthfhe-cli/src/full_pipeline.rs` — wire unified transcript

**RED test**: Divergent transcripts accepted (should fail)
**GREEN tests**: `test_s1_unified_accepts`, `test_s1_different_r_rejects`

---

### P0-3: S2 — Wire FHE Mul Proof into Step Circuit

**Description**: `FheComputeStepCircuit` already contains `mul_fhe_ct_bp()` gadget (~496-688). Wire this into `synthesize()` for `FheOp::Mul`.

**Files**:
- `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs` — wire Mul branch
- `crates/pvthfhe-cli/src/full_pipeline.rs` — add Mul witness generation
- `crates/pvthfhe-compressor/tests/fhe_compute_mul.rs` — new test file

📝 **Scope**: N=4 demo scale. Production N=8192 Mul deferred alongside G-N8.

---

## Wave P1 — HIGH (10 findings)

### P1-1: F1 — Domain-Separate `ajtai_sigma_session_binding`

**File**: `crates/pvthfhe-nizk/src/adapter.rs:604-617`

Replace raw concatenation `SHA256(sid || ajtai || ct || share)` with domain-separated, length-prefixed encoding using `Tag::SigmaSessionBinding`.

**RED test**: Cross-domain injection test
**GREEN tests**: `test_binding_is_domain_separated`, `test_binding_changes_on_sid`

---

### P1-2: F2/H7 — Reject Truncated/Short Witness Polynomials

**Files**: `crates/pvthfhe-nizk/src/adapter.rs:374-381, 507-512`

Add exact length check to `validate_witness()` and remove `pad_or_truncate_to_rlwe_n()`.

```rust
fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
    if witness.secret_share_poly.is_empty() {
        return Err(NizkError::InvalidInput("secret_share_poly must be non-empty"));
    }
    if witness.secret_share_poly.len() != rlwe_n() {
        return Err(NizkError::InvalidInput("secret_share_poly must have exactly N coefficients"));
    }
    if witness.error.len() != rlwe_n() {
        return Err(NizkError::InvalidInput("error must have exactly N coefficients"));
    }
    Ok(())
}
```

**RED test**: `test_short_witness_rejected`
**GREEN tests**: `test_exact_length_accepted`, `test_short_rejected`, `test_long_rejected`

---

### P1-3: F3/M10 — Bind `participant_id` + `params_digest` to Cyclo Challenge

**Files**: `crates/pvthfhe-cyclo/src/fiat_shamir.rs:7-23` + all call sites

Add `participant_id: u16` and `params_digest: &[u8; 32]` parameters to `challenge_v1()`.

**RED test**: Cross-prover challenge replay test
**GREEN tests**: `test_challenge_differs_by_participant`, `test_challenge_differs_by_params`

---

### P1-4: F4 — Wire Real NIZK Witness into Cyclo Fold Instances

**File**: `crates/pvthfhe-aggregator/src/folding/mod.rs:414-455`

Replace `demo_zero_witness_bytes()` and `demo_one_by_one_matrix_bytes()` with actual witness bytes extracted from verified NIZK proofs.

**RED test**: Real witness not consumed (should fail structural bind)
**GREEN tests**: `test_real_witness_consumed`, `test_demo_witness_rejected`

---

### P1-5: H8 — Add Schnorr Proof-of-Possession

**Files**: `crates/pvthfhe-nizk/src/schnorr.rs` + `crates/pvthfhe-keygen/src/`

Add `schnorr_pop_prove()` and `schnorr_pop_verify()` — each party proves knowledge of `sk` corresponding to declared `pk`.

**RED test**: Key accepted without PoP (should fail)
**GREEN tests**: `test_pop_valid`, `test_pop_unknown_key`, `test_pop_forged`

---

### P1-6a: H9 — Register Remaining Domain Tags

**File**: `crates/pvthfhe-domain-tags/src/lib.rs`

Add `Tag` variants: `SigmaT2Commit`, `SigmaT2CommitCh`, `CycloAjtaiD2V1`, `GreyhoundA`, `GreyhoundB`, `GreyhoundD`, `SigmaSessionBinding`, `CycloFoldChallengeV2`, `PvssDecryptBindingV1`.

---

### P1-6b: H9 — Replace Inline Domain Literals

**Files**: `sigma.rs:649,683`, `adapter.rs:479`, `greyhound_pcs.rs:429,431,433`, `cyclo/fiat_shamir.rs:15`

Replace raw `b"..."` domain strings with `Tag::*.as_bytes()`.

**Validation**: CI lint `grep -r 'b"' crates/ | grep -v domain_tags | grep -v test` must be empty.

---

### P1-7: H6-P1-3a — Replace Hardcoded TFHE Bootstrap Seeds

**File**: `crates/pvthfhe-fhe-poulpy/src/poulpy_backend_impl/tfhe_ops.rs:248-256`

Replace `[0xABu8; 32]` and `[0xCDu8; 32]` with `OsRng`-filled seeds.

**RED test**: Two bootstrap calls with same input produce identical outputs
**GREEN tests**: `test_tfhe_bootstrap_non_deterministic`

---

## Wave P2 — MEDIUM (10 findings)

### P2-1: F5 — Domain-Separate Batch Session ID

**File**: `crates/pvthfhe-aggregator/src/folding/mod.rs:677`

Replace `format!("{session_id}-batch-{batch_index}")` with `format!("{session_id}/batch/{batch_index}")`.

---

### P2-2: F6 — Rejection Sampling for Dealer Index

**File**: `crates/pvthfhe-pvss/src/lib.rs:46-56`

Add rejection sampling to `derive_dealer_index()` or document bias with bounds.

---

### P2-3: F7 — Verify `secret_key_bytes` Against Committed Hash

**File**: `crates/pvthfhe-pvss/src/nizk_decrypt.rs`

Ensure `hash_bridge::verify(pvss_commitment)` is always called and its error propagated in all NIZK verify paths.

---

### P2-4: M9 — Label Binding in FS Challenge Expansion

**File**: `crates/pvthfhe-nizk/src/fiat_shamir.rs:102-106`

Add `h.update(label)` before counter in `challenge_bytes` expansion loop.

---

### P2-5: M2 — Consolidate Remaining Inline Domain Tags

Covered by P1-6. Verify completeness.

---

### P2-6: M4 — Populate `contextId`

**File**: `contracts/src/PvtFheVerifier.sol:581`

Populate from protocol label + parent session when Phase 2 seam closes. For now: document as deferred.

---

### P2-7: M8 — Document BFV Sigma In-Circuit Verifier Limitation

**File**: `crates/pvthfhe-nizk/src/bfv_sigma.rs`

Add module-level doc explaining that no Noir in-circuit verifier exists for BFV sigma proofs. Acceptable for research prototype.

---

## Wave P3 — LOW (8 findings)

### P3-1: F8 — Document CRS Seed Derivation Correctness

**File**: `crates/pvthfhe-nizk/src/adapter.rs:641`

Add comment confirming `derive_epoch_crs_seed` is correct: bound to `(epoch, session_id)`.

---

### P3-2: F9 — Return Error on `u32::try_from` Overflow

**File**: `crates/pvthfhe-nizk/src/adapter.rs:654-668`

Replace `unwrap_or(u32::MAX)` with proper error propagation in `encode_u64s_le` and `encode_i64s_le`.

---

### P3-3: F10 — Replace Poseidon Panic with NizkError

**File**: `crates/pvthfhe-nizk/src/sigma.rs:725,728`

Replace `.unwrap_or_else(|| panic!(...))` with `?` using `NizkError`.

---

### P3-4: F11 — Implement `Send + Sync` for `CycloParams`

**File**: `crates/pvthfhe-cyclo/src/lib.rs`

Add `unsafe impl Send for CycloParams {}` and `unsafe impl Sync for CycloParams {}`.

---

### P3-5: L6 — Validate Poseidon Rate/Capacity at Construction

**File**: `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs`

Extract rate/capacity from Poseidon parameter struct; validate at construction.

---

### P3-6: L7 — Replace Floating-Point JL Projection

**File**: `crates/pvthfhe-nizk/src/sigma.rs:85-118`

Replace `f64` with integer fixed-point arithmetic or document as WIP-only.

---

### P3-7: L3 — Document ecrecover EIP-712 Migration Plan

**File**: `contracts/src/PvtFheVerifier.sol:660-680`

Add explicit EIP-712 migration milestone to code comment. No code change now (deferred to Phase 3 gate).

---

## Wave P4 — DOCUMENTATION

### P4-1: Fix Documentation Accuracy

| File | Change |
|------|--------|
| `README.md` | "Compute: Verifiable FHE ops ✅" → "⚠️ Add only, Mul at N=4 demo scale" |
| `SECURITY.md` | "Verifiable FHE ops" → "Add-only verifiable. Mul unproven." |
| `WARNING.md` | Update C7/A1/C5 status: C7=RESOLVED, A1=RESOLVED, C5=RESOLVED |
| `.sisyphus/design/spec-real-p2p3.md` §3.4 | Document `sigma_proof_bytes` SPEC EXTENSION |
| `docs/OPEN-PROBLEM-BLOCKERS.md` | Update G-N8 status with description of P0-1 fix |

### P4-2: Paper-Code Alignment

**File**: `paper/` — verify all claims match current implementation status.

---

## Verification Gates

| Gate | Command | Expected |
|------|---------|----------|
| **RUN-TESTS** | `cargo test --workspace --exclude pvthfhe-bench` | All pass |
| **NOIR** | `(cd circuits && nargo test --workspace)` | ≥18 tests pass |
| **FORGE** | `forge test --root contracts` | No regression |
| **BUILD** | `cargo build --workspace` | Clean |
| **LINT-DOMAIN** | `grep -r 'b"' crates/pvthfhe-nizk/src \| grep -v domain_tags \| grep -v test \| grep -v '//'` | Empty |
| **LINT-PANIC** | `grep -r '\.unwrap()\|\.expect(\|panic!' crates/ \| grep -v test \| grep -v '//'` | Checked |

---

## Commit Strategy

1. `fix(mpc-audit): P1 NIZK binding fixes — domain separator, witness length, cyclo challenge`
2. `fix(mpc-audit): P1 Schnorr PoP + TFHE randomness`
3. `fix(mpc-audit): P1 domain tags consolidation`
4. `fix(mpc-audit): P2 crypto hygiene — batch session, dealer index, FS expansion`
5. `fix(mpc-audit): P3 code quality — panic removal, overflow safety`
6. `docs(mpc-audit): update README, SECURITY, WARNING, spec for accuracy`

## Estimated Effort: ~16-20 hours total (parallelizable waves)

| Wave | Effort | Can Parallelize |
|------|--------|----------------|
| P0 (3C) | 8-10h | No (sequential deps) |
| P1 (10H) | 4-6h | Yes (7 parallel tasks) |
| P2 (10M) | 2-3h | Yes |
| P3 (8L) | 1-2h | Yes |
| P4 (Docs) | 1-2h | After P0+P1 |

---

*Plan version*: 1.0
*Target review*: Momus (plan critic)
*Next step*: Momus review → implement
