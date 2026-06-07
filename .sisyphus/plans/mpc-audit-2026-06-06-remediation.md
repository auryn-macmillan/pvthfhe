# MPC Audit 2026-06-06 — Remediation Plan

**Plan**: `mpc-audit-2026-06-06-remediation`
**Audit**: `.sisyphus/audit/MPC-AUDIT-2026-06-06.md` (12 findings: 3 CRITICAL, 4 HIGH, 3 MEDIUM, 2 LOW)
**Baseline**: Git HEAD post 2026-06-05 remediation (P0+P1 completed, P2 partially)
**Constraint**: TDD RED→GREEN→GATE. Stub protocol: replace in place, never delete-and-recreate.

## Prior Remediation Status

14 of 19 findings from the prior audit are confirmed fixed. This plan addresses ONLY fresh findings from 2026-06-06.

## Execution Order: P0 CRITICAL → P1 HIGH → P2 MEDIUM → P3 LOW → P4 DOCUMENTATION

## Task Dependencies

| Task | Depends On | Reason |
|------|-----------|--------|
| P0-1 (G-N8) | None | Standalone |
| P0-2 (S1) | P0-1 | Needs N-domain definition |
| P0-3 (S2) | P0-1 | Constraint count tied to N |
| P1-1 (H7) | None | Single function change |
| P1-2 (H8) | None | Independent module |
| P1-3a (H9 tags) | None | Add tags to domain-tags |
| P1-3b (H9 replace) | P1-3a | Tags must exist first |
| P2-1 (M9) | None | Local fix |
| P2-2 (M10) | None | Signature change |
| P3-1 (L6) | None | Local fix |
| P3-2 (L7) | None | Local fix |
| P4-1 (docs) | P0-1, P0-3, P1-1, P1-3 | Reflects resolution status |

## Parallel Workstreams

| Stream | Findings | Key Files |
|--------|----------|-----------|
| S0: Circuit + transcript | G-N8, S1, S2 | `circuits/`, `pvthfhe-nizk/adapter.rs`, `pvthfhe-compressor/` |
| S1: Input validation | H7 | `pvthfhe-nizk/adapter.rs` |
| S2: Key integrity | H8 | `pvthfhe-nizk/schnorr.rs` |
| S3: Domain tags | H9, M10 | `pvthfhe-domain-tags/`, 6 source files |
| S4: Defense-in-depth | M9, L6, L7 | `fiat_shamir.rs`, `poseidon_gadget.rs`, `sigma.rs` |
| S5: Documentation | Doc gaps | `README.md`, `SECURITY.md`, `WARNING.md`, `spec-real-p2p3.md` |

---

## Wave P0 — CRITICAL (3 findings)

### P0-1: G-N8 — Formalize N=8→N=8192 Reduction with Multi-Point S-Z

**Description**: Circuits prove correctness for N=8, production RLWE uses N=8192. The native `aggregate_decrypt_raw_result_poly()` projection is unverified. Fix: implement multi-point Schwartz-Zippel verification in the native verifier that checks consistency between N=8 projections and N=8192 plaintext. If a malicious aggregator produces inconsistent projections, the verifier rejects.

**Files**:
- `crates/pvthfhe-cli/src/full_pipeline.rs` — add `verify_multi_point_sz_projection()`
- `crates/pvthfhe-nizk/src/adapter.rs` — wire into verify path
- `circuits/aggregator_final/src/main.nr` — update N=8 limitation comment
- `docs/OPEN-PROBLEM-BLOCKERS.md` — update G-N8 status

**RED test**: `cargo test -p pvthfhe-cli -- g8_n8_projection_mismatch` — accepts inconsistent projection (should fail)
**GREEN tests**: `test_g8_multi_point_accepts_consistent`, `test_g8_multi_point_rejects_inconsistent`
**Fallback**: If formal reduction infeasible, document limitation with failure probability analysis

### P0-2: S1 — Unify Native/Circuit Transcripts

**Description**: Bind the C7 circuit's Schwartz-Zippel challenge `r` into the sigma protocol's native transcript, and bind the sigma commitment hash into the C7 circuit's public inputs. This creates a bidirectional binding so both verification paths commit to the same underlying proof.

**Files**:
- `crates/pvthfhe-nizk/src/adapter.rs` — add `r` binding to sigma transcript
- `crates/pvthfhe-nizk/src/sigma.rs` — pass `r` through prove/verify
- `circuits/aggregator_final/src/main.nr` — expose `sigma_binding_hash` as public input
- `crates/pvthfhe-cli/src/full_pipeline.rs` — wire unified transcript

**RED test**: `cargo test -p pvthfhe-nizk --test transcript_mismatch` — divergent transcripts accepted
**GREEN tests**: `test_s1_unified_accepts`, `test_s1_different_r_rejects`

### P0-3: S2 — Wire FHE Mul Proof Into Step Circuit

**Description**: The `FheComputeStepCircuit` already contains `mul_fhe_ct_bp()` (negacyclic convolution gadget, ~lines 496-688). Wire this into the `synthesize()` method for `FheOp::Mul` so FHE multiplication becomes verifiable.

**Files**:
- `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs` — wire Mul branch in `synthesize()`
- `crates/pvthfhe-cli/src/full_pipeline.rs` — add Mul witness generation
- `crates/pvthfhe-cli/src/main.rs` — update `just compute` to support Mul
- `crates/pvthfhe-compressor/tests/fhe_compute_mul.rs` — new test file

**RED test**: `cargo test -p pvthfhe-compressor --test fhe_compute_mul` — Mul synthesis fails
**GREEN tests**: `test_fhe_mul_prover_accepts`, `test_fhe_mul_tampered_output_rejects`

**Scope note**: N=4 demo scale. Production N=8192 Mul deferred alongside G-N8 resolution.

---

## Wave P1 — HIGH (4 findings)

### P1-1: H7 — Reject Short/Long Witness Polynomials

**Description**: `pad_or_truncate_to_rlwe_n()` silently zero-pads short witnesses and truncates long ones. Reject any witness whose length does not exactly match N.

**Files**: `crates/pvthfhe-nizk/src/adapter.rs:507-512`
**RED test**: `cargo test -p pvthfhe-nizk --test witness_length` — short witness accepted
**GREEN tests**: `test_exact_length_accepts`, `test_short_witness_rejects`, `test_long_witness_rejects`

### P1-2: H8 — Add Schnorr Proof-of-Possession

**Description**: Add `schnorr_pop_prove()` and `schnorr_pop_verify()` to the Schnorr module. Each party must prove knowledge of their secret key before their public key is accepted into the DKG aggregate.

**Files**:
- `crates/pvthfhe-nizk/src/schnorr.rs` — add PoP struct and functions
- `crates/pvthfhe-keygen/src/` — wire PoP into DKG Round 1/2

**RED test**: `cargo test -p pvthfhe-nizk --test schnorr_pop` — key accepted without PoP
**GREEN tests**: `test_pop_valid_key_accepts`, `test_pop_unknown_key_rejects`, `test_pop_forged_rejects`

### P1-3a: H9 — Register Remaining Domain Tags

**Description**: Add new `Tag` variants for all inline domain strings not yet in the `domain-tags` crate. Add CI lint test that verifies no raw `b"..."` domain strings remain outside the crate.

**Files**: `crates/pvthfhe-domain-tags/src/lib.rs` — add: `SigmaT2Commit`, `SigmaT2CommitCh`, `CycloAjtaiD2V1`, `GreyhoundA`, `GreyhoundB`, `GreyhoundD`

### P1-3b: H9 — Replace Inline Domain Literals

**Description**: Replace raw `b"..."` domain strings with `Tag::*.as_bytes()` in 7 locations across 4 files.

**Files**: `sigma.rs:649,683`, `adapter.rs:479`, `greyhound_pcs.rs:429,431,433`, `ajtai_crs_binding.rs:69`
**GREEN**: lint test passes, existing tests pass

---

## Wave P2 — MEDIUM (3 findings)

### P2-1: M9 — Label Binding in Challenge Expansion

**Description**: Add `h.update(label)` before counter in the `challenge_bytes` expansion loop for defense-in-depth.

**Files**: `crates/pvthfhe-nizk/src/fiat_shamir.rs:102-106`

### P2-2: M10 — Bind Participant ID + Params Digest to Cyclo Challenge

**Description**: Add `participant_id` and `params_digest` to `challenge_v1()` hash inputs. Update all callers.

**Files**: `crates/pvthfhe-cyclo/src/fiat_shamir.rs:7-23` + all call sites

### Confirmed Already Fixed (from prior audit)

M2 (domain tag consolidation) → Covered by H9-P1-3. M3 (Noir Lagrange weights), M5 (Greyhound session binding), M6 (Cyclo challenge bytes), M7 (sigma zero witness) → all confirmed fixed.

---

## Wave P3 — LOW (2 findings)

### P3-1: L6 — Validate Poseidon Rate/Capacity at Construction

**Files**: `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs`

### P3-2: L7 — Replace Floating-Point JL Projection with Integer Fixed-Point

**Files**: `crates/pvthfhe-nizk/src/sigma.rs:85-118`

---

## Wave P4 — DOCUMENTATION

### P4-1: Fix Documentation Accuracy

| File | Change |
|------|--------|
| `README.md` | "Compute: Verifiable FHE ops ✅" → "⚠️ Add only, Mul deferred to T42" |
| `SECURITY.md` | "Verifiable FHE ops" → "Add-only verifiable. Mul unproven." |
| `WARNING.md` | Update C7/A1/C5 status from OPEN to RESOLVED |
| `.sisyphus/design/spec-real-p2p3.md` §3.4 | Document sigma_proof_bytes extension |

---

## Verification Gates

| Gate | Command | Expected |
|------|---------|----------|
| RED | All RED tests | Each test file fails with expected error |
| GREEN-cargo | `cargo test --workspace --exclude pvthfhe-bench` | All pass |
| GREEN-noir | `(cd circuits && nargo test --workspace)` | 18/18 pass + new |
| GREEN-forge | `forge test --root contracts` | No regression |
| BUILD | `cargo build --workspace` | Clean |
| LINT | `grep -r 'b"' crates/ \| grep -v domain_tags \| grep -v test` | Empty |

## Commit Strategy

1. `fix(mpc-audit): P0-P3 structural fixes, domain tags, documentation accuracy`
2. `docs(mpc-audit): update spec §3.4 and warning status`

## Estimated Effort: ~8-10 hours
