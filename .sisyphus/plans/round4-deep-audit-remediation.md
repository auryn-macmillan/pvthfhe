# Round 4 Deep Audit Remediation Plan

**Status**: IN PROGRESS
**Created**: 2026-05-13
**Audits**: NIZK proof soundness + PVSS security guarantees + E2E verifiability + Bug/edge case surface
**Pre-audit baseline**: `2d2540d` (Momus remediation complete)
**Demo baseline**: `just demo-e2e` → ACCEPT (n=10, t=4)
**Benchmark baseline**: `just bench-comparison 10 4 1` → fails (arg syntax + missing feature)
**Gate**: All changes must pass `just demo-e2e` and `just bench-comparison 10 4 1`

---

## Findings Summary (4 parallel deep audits)

Cross-referencing NIZK-soundness (bg_65e16803), PVSS-guarantees (bg_cc84f44b), E2E-verifiability (bg_0dbd9c6a), and Bug-surface (bg_7708438a).

### Critical

**F1 — Missing sigma equation check in share-encryption algebraic proof**
- Source: NIZK-GAP-1, PVSS-C3
- File: `crates/pvthfhe-pvss/src/nizk_share.rs:922-997` (`verify_algebraic_relation`)
- Gap: The function checks challenge re-derivation (line 940-979), z_s norm (line 985-989), z_e norm (line 990-994), but **never checks** `c*z_s + z_e == t + ch*d_i (mod Q)` — the core sigma verification equation.
- The canonical equation check exists at `sigma.rs:220-233` but is not called.
- Impact: A malicious prover can forge arbitrary z_s, z_e, t_rns within norm bounds, derive a matching challenge, and the proof is accepted. **The algebraic sigma proof is completely unsound**.
- Fix: Replicate the equation check from `sigma.rs:220-233` before the `Ok(())` at line 996.

### High

**F2 — bfv_sigma::verify missing plaintext domain check for z_m**
- Source: NIZK-GAP-2
- File: `crates/pvthfhe-nizk/src/bfv_sigma.rs:273-374`
- Gap: The verifier checks `z_m < B_Z_M` (masking bound) but never checks `|z_m_i| < t/2` (32768 for t=65536). The plaintext domain constraint is never enforced.
- RED test at line 572 (`red_verifier_rejects_plaintext_domain_violation`) documents this.
- Impact: Proofs with plaintext coefficients outside `[-32768, 32767]` are accepted.
- Fix: Add `|z_m_i| < t_plain/2` check for all coefficients in verify(). Note: earlier remediation correctly reverted a check on `m_resp` (which is masked), but the check should be on `z_m` open response in the sigma protocol.

**F3 — Decrypt NIZK vacuous witness binding**
- Source: NIZK-GAP-3
- File: `crates/pvthfhe-pvss/src/nizk_decrypt.rs:366-380`, `tests/nizk_decrypt_soundness.rs`
- Gap: The `secret_share` scalar in `proof_secret_share()` derives from `derive_party_binding(&stmt.party_pk)` — public key hash, NOT the secret key. The verifier cannot distinguish a proof made by the legitimate key-holder from one made with arbitrary bytes.
- RED tests (both `#[ignore]`): `adversary_without_ski_cannot_produce_valid_proof`, `two_different_witnesses_both_verify`.
- Impact: Decrypt share proofs can be generated without knowing the secret key share.
- Fix: Bind the sigma proof's committed secret share to the DKG-anchored secret key share (`sk_agg_share`) rather than the public key hash. The verifier must check that the committed value matches the party's DKG-verified key share.

**F4 — Dealer index hardcoded to 0; no cryptographic dealer identity binding**
- Source: PVSS-GAP-3, PVSS-GAP-8
- File: `crates/pvthfhe-pvss/src/encrypt.rs:237` (`dealer_index: 0`)
- Gap: `dealer_index` is a literal constant 0 — never derived from any identity key, public key, or signature. No `dealer_pk` or `dealer_keypair` exists anywhere in the PVSS crate.
- Impact: A malicious dealer can substitute shares across sessions; no cryptographic deterrent against cross-session share replay by the same or different dealer.
- Fix: Add dealer identity key to `PvssContext`, derive `dealer_index` from it (e.g., hash of `dealer_pk`), and bind it into all NIZK statements and share commitments.

**F5 — No public verifier role/binary; "verify: ACCEPT" is unconditional**
- Source: E2E-overall
- File: `crates/pvthfhe-cli/src/main.rs:355`
- Gap: `println!("verify: ACCEPT");` prints unconditionally regardless of verification results. There is no `verify_with_public_data()` function. The demo pipeline is the prover — all verification happens inside the same process that generated the data.
- Impact: A third-party verifier with only public data cannot confirm the computation was correct.
- Fix: Add a `VerifierReport` struct and conditional ACCEPT/REJECT based on actual verification results, or create a separate verifier binary.

**F6 — KeygenSimulator::new accepts invalid thresholds silently**
- Source: Bugs-H1
- File: `crates/pvthfhe-aggregator/src/keygen/simulator.rs:45-52`
- Gap: Zero threshold validation in constructor. Accepts `t=0`, `t>n`, `n=0` without error.
- Fix: Add threshold bounds check matching `full_pipeline.rs:85`: `1 <= t <= n` and `t <= (n-1)/2`.

### Medium

**F7 — unwrap_or(0) on share commitments silently produces invalid proofs**
- Source: Bugs-H2
- File: `crates/pvthfhe-pvss/src/encrypt.rs:120,128`
- Gap: `effective_sk_share.unwrap_or(0)` and `effective_esm_share.unwrap_or(0)` — when DKG aggregate values are missing, commitment is to zero instead of error.
- Fix: Replace with `ok_or(PvssError::MissingShare)` and propagate error.

**F8 — t_plain hardcoded to 65536, conflicts with CLI params (131072)**
- Source: Bugs-M3
- File: `crates/pvthfhe-pvss/src/nizk_share.rs:807`
- Gap: `let t_plain: i64 = 65536;` is hardcoded in `encode_fhers_plaintext_slots`, but CLI uses `t_plain = 131072`.
- Fix: Extract `t_plain` from BFV parameters context rather than hardcoding.

**F9 — share_computation and dkg_aggregation verifiers never called in pipeline**
- Source: E2E-GAP
- Files: `crates/pvthfhe-pvss/src/share_computation.rs:155`, `crates/pvthfhe-pvss/src/dkg_aggregation.rs:216`
- Gap: These thorough public-input-only verifiers exist and work but are never wired into `run_full_pipeline()`.
- Fix: Add optional (feature-gated) calls to both verifiers in the pipeline.

**F10 — Demo-derived NIZK witnesses, not real BFV encryption error**
- Source: E2E-GAP
- File: `crates/pvthfhe-cli/src/demo_nizk.rs:102` (`derive_demo_error_poly`)
- Gap: NIZK witnesses use demo-derived error polynomials (modulo-3 mapping), not the actual BFV encryption error from `encrypt_with_witness()`.
- Fix: Plumb real BFV encryption witnesses from the backend into the NIZK keygen path.

**F11 — assert_eq! crash path in aggregate key check**
- Source: E2E-GAP
- File: `crates/pvthfhe-cli/src/full_pipeline.rs:246`
- Gap: `assert_eq!(aggregate_pk.bytes, aggregate_key.bytes)` panics instead of returning a clean error in release mode.
- Fix: Convert to `anyhow::bail!` or `ensure!`.

### Low

**F12 — Challenge comparison not constant-time in verify_algebraic_relation**
- Source: NIZK-GAP-5
- File: `crates/pvthfhe-pvss/src/nizk_share.rs:979`
- Gap: `if expected_ch != sigma_proof.ch` uses plain `!=` instead of `subtle::ConstantTimeEq`.
- Fix: Use `subtle::ConstantTimeEq` matching `sigma.rs:203-207`.

**F13 — Modular arithmetic helpers lack defensive modulus>0 check**
- Source: Bugs-C1
- File: `crates/pvthfhe-aggregator/src/decrypt/mod.rs:567-601`
- Gap: `add_mod`, `sub_mod`, `neg_mod`, `mul_mod`, `mod_inverse` all do `% modulus` without checking `modulus != 0`. Currently guarded by upstream `validate_final_aggregation_statement`, but no defensive check inside.
- Fix: Add `debug_assert!(modulus > 0)` to each function.

**F14 — bench-comparison recipe uses wrong arg syntax for pvthfhe-e2e**
- Source: Bug surface (observed during baseline)
- File: `Justfile:45`
- Gap: Named args `n=10` parsed as literal `"n=10"` by just. Positional args work: `just bench-comparison 10 4 1`.
- Fix: Document positional invocation, or fix justfile to use positional parameters.

**F15 — bench-comparison recipe missing demo-seeded-rng feature**
- Source: Bug surface (observed during baseline)
- File: `Justfile:45`
- Gap: `pvthfhe-e2e` binary requires `--features demo-seeded-rng` for seed!=0, but recipe only passes `--features sonobe-compressor`.
- Fix: Add `demo-seeded-rng` to the feature list.

**F16 — unwrap_or(u32::MAX) patterns in 7+ locations**
- Source: Bugs-M1
- Files: Multiple (see bug audit)
- Gap: `try_from().unwrap_or(u32::MAX)` silently substitutes MAX for invalid values, which are then included in hashes and transcripts.
- Fix: Audit all sites; prefer `?` or `ok_or()`.

---

## Batches

### Batch A: Critical Fix — Sigma Equation in Algebraic Proof

| ID | Task | Files | Expected Outcome |
|----|------|-------|-----------------|
| A.1 | Add equation check `c*z_s + z_e == t + ch*d_i (mod Q)` in `verify_algebraic_relation` | `nizk_share.rs:996` | Function verifies the equation before returning Ok(()) |
| A.2 | Use constant-time challenge comparison (F12 bundled here) | `nizk_share.rs:979` | Uses `subtle::ConstantTimeEq` |
| A.3 | Write RED test: forged algebraic proof with wrong witness | `nizk_share` tests | Test asserts verifier rejects forged proof |
| A.4 | Verify share-encryption roundtrip still works | Existing tests | Existing tests pass unmodified |

**Implementation notes**: Replicate `sigma.rs:220-233` logic:
- Convert `z_s`, `z_e`, `ch` to RNS
- Compute `lhs = c*z_s + z_e`  
- Compute `rhs = t + ch*d_i`
- Compare element-wise (constant-time)

### Batch B: High Protocol — BFV Domain + Decrypt Binding + Dealer Identity

| ID | Task | Files | Expected Outcome |
|----|------|-------|-----------------|
| B.1 | Add `|z_m_i| < t_plain/2` check in `bfv_sigma::verify` | `bfv_sigma.rs:~338` | RED test at line 572 passes |
| B.2 | Extract t_plain from BFV context (F8 bundled) | `nizk_share.rs:807` | t_plain not hardcoded |
| B.3 | Fix decrypt NIZK witness binding to use DKG-anchored `sk_agg_share` | `nizk_decrypt.rs:366-380` | Verifier checks committed value matches DKG key share |
| B.4 | Wire `sk_agg_share` into DecryptNizkVerifier statement for committed-smudge mode | `nizk_decrypt.rs:288-299` | Verifier has access to expected sk_agg_share |
| B.5 | Add dealer identity key to PvssContext, derive dealer_index | `encrypt.rs:237`, `lib.rs` (PvssContext) | dealer_index is cryptographically bound |
| B.6 | Bind dealer_pk into all NIZK statements and share commitments | `nizk_share.rs`, `nizk_decrypt.rs` | Session + dealer identity non-malleability |
| B.7 | Write RED tests: cross-dealer share replay, key substitution | PVSS tests | Tests assert rejections |
| B.8 | Update docs: dealer identity binding in security model | `SECURITY.md`, `threat-model-v1.md` | Documentation reflects binding |

### Batch C: High Code Quality — Validation, Error Propagation, Hardcoding

| ID | Task | Files | Expected Outcome |
|----|------|-------|-----------------|
| C.1 | Add threshold validation in `KeygenSimulator::new` (F6) | `simulator.rs:45` | Rejects t=0, t>n, t>(n-1)/2 |
| C.2 | Replace `unwrap_or(0)` with error propagation (F7) | `encrypt.rs:120,128` | Returns Err on missing share |
| C.3 | Add `debug_assert!(modulus > 0)` to modular helpers (F13) | `decrypt/mod.rs:567-601` | Defensive check in 5 functions |
| C.4 | Replace `assert_eq!` with `anyhow::bail!` (F11) | `full_pipeline.rs:246` | Clean error on key mismatch |
| C.5 | Audit `unwrap_or(u32::MAX)` sites; convert to errors where possible (F16) | Multiple files | Reduced silent fallback surface |
| C.6 | Write tests for threshold edge cases | `simulator` tests | t=0, t=0/n=0, t>n, t>(n-1)/2 all rejected |

### Batch D: E2E Verifiability — Public Verifier Role + Pipeline Wiring

| ID | Task | Files | Expected Outcome |
|----|------|-------|-----------------|
| D.1 | Conditionalize "verify: ACCEPT" on actual verification results (F5) | `main.rs:355` | Prints ACCEPT only when all checks pass |
| D.2 | Optionally wire share_computation and dkg_aggregation verifiers into pipeline (F9) | `full_pipeline.rs` | Feature-gated calls to public verifiers |
| D.3 | Plumb real BFV encryption witnesses from backend into NIZK keygen path (F10) | `full_pipeline.rs`, `demo_nizk.rs` | NIZK proves over real encryption witness, not demo-derived |
| D.4 | Add `--verify-only` mode to CLI: reads public artifacts, runs all verifications, prints ACCEPT/REJECT | `main.rs` or new binary | Third party can verify with only public data |
| D.5 | Update paper/claims-table with verifiability status | `paper/main.tex`, `paper/claims-table.md` | Claims reflect actual verifier capabilities |

### Batch E: Polish — Benchmark Fix + Documentation

| ID | Task | Files | Expected Outcome |
|----|------|-------|-----------------|
| E.1 | Fix bench-comparison justfile: add demo-seeded-rng feature (F15) | `Justfile:45` | `just bench-comparison 10 4 1` works |
| E.2 | Document positional arg invocation for bench-comparison (F14) | `Justfile`, `REPRODUCING.md` | Clear usage docs |
| E.3 | Update ARCHITECTURE.md / SECURITY.md to reflect F1-F4 fixes | `ARCHITECTURE.md`, `SECURITY.md` | Documentation matches implementation |
| E.4 | Update interfold-equivalence.md C3/D.1 status | `interfold-equivalence.md` | Gap status reflects fixes |
| E.5 | Run full gate: `just phase3-gate` | — | Gate passes |

---

## Verification

### Pre-commit checks for each batch:

```bash
# Per-batch:
cargo build --workspace
cargo clippy --workspace 2>&1 | grep -v "warning:"
cargo test -p pvthfhe-pvss -p pvthfhe-nizk -p pvthfhe-aggregator
```

### End-of-plan checks:

```bash
# Must pass:
just demo-e2e                          # ACCEPT
just bench-comparison 10 4 1           # Clean run, no errors
just phase3-gate                       # All gates pass
```

### Cross-reference consistency:
- [ ] `paper/main.tex` theorem statuses match code reality
- [ ] `paper/claims-table.md` updated
- [ ] `SECURITY.md` reflects all fixes
- [ ] `WARNING.md` updated for any unsound path disclosures
- [ ] `ARCHITECTURE.md` verifiability chain documented
- [ ] `docs/security-proofs/interfold-equivalent-pvss.md` updated

---

## Open / Deferred

| Item | Reason | Tracking |
|------|--------|----------|
| C7 (Final aggregation proof) | Noir toy circuit not production-ready | Batch G of interfold-equivalent-pvss plan |
| P1/P2/P3 (open problems) | Research-blocked | Existing deferred plans |
| Smudge-slot freshness enforcement | Planned, not in scope for R4 | Batch C/F of interfold-equivalent-pvss plan |
| Batched share verification (D.2) | Planned as follow-on | Existing plan |

---

## Execution Order

1. **Batch A** — Critical; must be done first (unblocks all share-encryption verification)
2. **Batch C** — Independent code quality; can run in parallel with Batch B
3. **Batch B** — Protocol changes; depends on A for equation context
4. **Batch D** — Verifiability plumbing; depends on A+B+C for sound foundation
5. **Batch E** — Polish and gates; depends on D for verifier to exercise

**Delegation strategy**: Each batch → delegate to `deep` or `unspecified-high` agent with full file paths and constraints. Batches A and C can run in parallel. Batch B after A completes. Batch D after B completes.
