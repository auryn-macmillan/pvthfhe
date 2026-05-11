# PVTHFHE Gate Resolution Plan

**Status**: R0–R10 implementation complete (144/178, 80.9%). 34 gate-level items remain.
**Prepared**: 2026-05-09 · Atlas Orchestrator
**Depends on**: External human cryptographic review (cannot be automated)

---

## Sequencing

```
Phase Ω1: Immediate fixes (hours)
  └─> Ω1.1 Fix F1 caveats
  └─> Ω1.2 Re-run F4 (full test matrix)

Phase Ω2: Cryptographic sign-off (days–weeks)
  └─> Ω2.1 External construction review
  └─> Ω2.2 Parameter freeze ceremony

Phase Ω3: Adversarial dress rehearsal (≥2 weeks)
  └─> Ω3.1 Written attacker scope
  └─> Ω3.2 Red-team exercise
  └─> Ω3.3 Findings triage

Phase Ω4: Oracle GATE reviews (days, after Ω2)
  └─> Ω4.1 R1 GATEs (DKG)
  └─> Ω4.2 R2 GATEs (Cyclo/Folding)
  └─> Ω4.3 R3 GATEs (Lattice NIZK)
  └─> Ω4.4 R4 GATEs (Aggregator)
  └─> Ω4.5 R5 GATEs (Compressor)
  └─> Ω4.6 R8 GATEs (E2E Pipeline)

Phase Ω5: Final Wave re-run (after Ω4)
  └─> Ω5.1 Re-run F2 (code quality, now with real NIZK)
  └─> Ω5.2 Re-run F3 (security soundness)
  └─> Ω5.3 Re-run F5 (context mining)
  └─> Ω5.4 Confirm all 5: APPROVE

Phase Ω6: Infrastructure completion (weeks–months)
  └─> Ω6.1 R7 Noir+BB fixtures → R6.7
  └─> Ω6.2 TEE hardware → R10 integration test
```

---

## Phase Ω1 — Immediate Fixes (< 1 day)

### Ω1.1 — F1 Caveat Resolution
- [ ] **env-var-name**: Rename `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK` in README vs code if mismatched. Grep for both names, unify.
- [ ] **CI --workspace**: Document in `AGENTS.md` that `--workspace` in CI is pre-existing and excluded from the "never --workspace" rule per audit scope.
- [ ] **TDD ordering**: Add `r0.X-red.log` / `r0.X-green.log` timestamps to git (already in `.sisyphus/evidence/`) — verify git-blame ordering.
- [ ] **GATE/sub-task inconsistency**: Walk plan lines 45–49 vs actual checkboxes; reconcile. Either close checkboxes or convert GATE lines to descriptive.
- [ ] **F1 Re-run**: After fixes, re-run F1 oracle reviewer. Target: clean APPROVE with zero caveats.

### Ω1.2 — F4 Re-run (Full Test Matrix)
- [ ] **cargo test** matrix: `-p pvthfhe-cyclo --lib`, `-p pvthfhe-pvss`, `-p pvthfhe-fhe`, `-p pvthfhe-keygen`, `-p pvthfhe-nizk --lib`, `-p pvthfhe-aggregator --lib`, `-p pvthfhe-compressor`, `-p pvthfhe-cli`
- [ ] **forge test**: `forge test --root contracts` — must show 104+/105 pass
- [ ] **nargo test**: `(cd circuits && nargo test)` — must pass for retained circuits
- [ ] **cargo build**: workspace clean
- [ ] **Capture output** to `.sisyphus/evidence/f4-hands-on-qa.log`
- [ ] **Verdict**: F4 APPROVE if all pass. Any failure → document and triage.

---

## Phase Ω2 — Cryptographic Sign-off (days–weeks)

### Ω2.1 — External Construction Review

**Documents needing sign-off:**

| Document | Lines | Reviewer | Action |
|----------|-------|----------|--------|
| `dkg-construction.md` | 641 | External cryptographer (not on build team) | Read, file written comments with file:line citations. Verify Pedersen-DKG over BFV/RLWE soundness ≥ 2⁻¹²⁸. |
| `fold-construction.md` | 390 | Same reviewer | Verify Sonobe Nova substitution is sound for current parameter regime. |
| `nizk-construction.md` | 493 | Same reviewer | Verify Greco NIZK is the correct construction; MPCitH fallback trigger criteria are sound. |
| `nizk-witness-language.md` | 288 | Same reviewer | Verify schema bridges R3↔R4↔R5 without semantic gaps. |
| `pre-reveal-binding.md` | 273 | Same reviewer | Verify full tuple binding prevents plaintext extraction without proof. |

- [ ] **All 5 docs reviewed** with at least one substantive comment each
- [ ] **Sign-off letter** committed to `.sisyphus/design/construction-review/` with reviewer name, affiliation, date, and per-document verdict
- [ ] **Issues raised** triaged: CRITICAL → fix before gate pass; HIGH → track in plan; MED/LOW → document

### Ω2.2 — Parameter Freeze Ceremony

**Document**: `.sisyphus/design/param-freeze-v1.md` (currently MISSING)

- [ ] **Draft** the document. Must freeze:
  1. **BFV parameters**: n=8192, log₂q=174, t_plain=65536, 3 NTT moduli (288230376173076481, 288230376167047169, 288230376161280001). Source: `.sisyphus/design/parameters.md` + `parameters.toml`.
  2. **SRS epoch**: On-chain epoch number used to seed transparent SRS. Production epoch TBD but freeze the derivation function `H(epoch ‖ "pvthfhe-srs-v1")`.
  3. **DKG (n,t) policy bounds**: Supported (n,t) combinations, max n, threshold floor.
  4. **Ajtai matrix dimensions**: m (rows), n (cols), modulus q for CRS.
  5. **Domain-tag table**: All variants in `DomainTag` enum with protocol phase mapping.
- [ ] **Joint signature**: Cryptography lead + zk lead sign with PGP or git-signed commit.
- [ ] **Commit** as `.sisyphus/design/param-freeze-v1.md`.
- [ ] **CI lint** added: `forbid-param-drift.sh` — asserts frozen parameters match code.

---

## Phase Ω3 — Adversarial Dress Rehearsal (≥ 2 weeks)

### Ω3.1 — Written Attacker Scope

- [ ] **Document**: `.sisyphus/design/dress-rehearsal-scope.md`
- [ ] **5 required scenarios** (per plan):
  1. DKG ceremony manipulation: corrupting t-1 parties, biasing key derivation
  2. NIZK forgery: producing valid proof without knowing secret
  3. Fold-instance substitution: replacing fold inputs post-NIZK, pre-compression
  4. Plaintext extraction without proof: bypassing proof verification in aggregate_decrypt
  5. On-chain replay: replaying a valid proof against consumed epoch
- [ ] **For each scenario**: define success criteria, attacker capabilities, detection mechanisms

### Ω3.2 — Red-team Exercise

- [ ] **Duration**: ≥ 2 weeks
- [ ] **Team**: 2+ engineers not on the build team
- [ ] **Environment**: Staging network (not mainnet), full pipeline deployed
- [ ] **Deliverables**: Attack log per scenario, successes observed, false positives

### Ω3.3 — Findings Triage

- [ ] **All CRITICAL/HIGH findings** triaged and closed before production promotion
- [ ] **Findings document**: `.sisyphus/design/dress-rehearsal-findings.md`
- [ ] **Remediation**: Code fixes for any discovered vulnerabilities
- [ ] **GATE**: Rehearsal complete, zero unclosed CRITICAL findings

---

## Phase Ω4 — Oracle GATE Reviews (after Ω2)

All oracle reviews use `subagent_type="oracle"` in fresh sessions. Each reads the specified test file, verifies the adversary model, and issues APPROVE/REJECT.

### Ω4.1 — R1 GATEs (DKG)

- [ ] **R1.1 GATE**: Oracle reviews `reshare_entropy.rs`. Verdict on non-determinism property. → APPROVE/REJECT
- [ ] **R1.5 GATE**: Oracle reviews `dkg_secrecy.rs` adversary model (distinguisher game, t-1 shares, ε < 2⁻¹²⁸). → APPROVE/REJECT

### Ω4.2 — R2 GATEs (Cyclo/Folding)

- [ ] **R2.0 GATE**: Oracle re-reviews `fold-construction.md`. Sonobe-only decision holds? → APPROVE/REJECT
- [ ] **R2.1 GATE**: Oracle verifies every fold callsite uses `range_check::infinity_norm`. CI lint `forbid::bytes_iter_max_in_norm` exits 0. → APPROVE/REJECT
- [ ] **R2.2 GATE**: Oracle verifies soundness budget `const SOUNDNESS_BITS: u32 = 128` asserted in code. → APPROVE/REJECT
- [ ] **R2.3 GATE**: Oracle verifies CCS positive + negative test green. Benchmark overhead documented. → APPROVE/REJECT
- [ ] **R2.4 GATE**: Oracle reviews `forgery_resistance.rs` adversary model (100K forge attempts, 0 successes). → APPROVE/REJECT

### Ω4.3 — R3 GATEs (Lattice NIZK)

- [ ] **R3.0a GATE**: Oracle reviews `nizk-witness-language.md` schema. Cross-phase coherence test. → APPROVE/REJECT
- [ ] **R3.1 GATE**: Oracle reviews `nizk_share_zk.rs` + `nizk_share_soundness.rs`. Must NOT use MockBackend. ZK + soundness with real lattice relation. → APPROVE/REJECT
- [ ] **R3.2 GATE**: Oracle reviews `nizk_decrypt_soundness.rs` + `decrypt_aggregation_real_nizk.rs`. Real NIZK verifier, no `nizk[0] == 1` tautology. → APPROVE/REJECT
- [ ] **R3.3 GATE**: Oracle reviews Ajtai CRS binding in `ajtai_crs_binding.rs`. Trapdoor-grinding documented as infeasible. → APPROVE/REJECT

### Ω4.4 — R4 GATEs (Aggregator)

- [ ] **R4.1 GATE**: Oracle reviews `FoldingScheme` integration with Cyclo adapter. → APPROVE/REJECT
- [ ] **R4.3 GATE**: Oracle verifies release builds reject `legacy-fold` feature. `single_fold_path_release.rs` PASS. → APPROVE/REJECT
- [ ] **R4.4 GATE**: Oracle reviews `fold_e2e_soundness.rs` adversary model (1000 forge attempts, 0 successes with real-nizk). → APPROVE/REJECT

### Ω4.5 — R5 GATEs (Compressor)

- [ ] **R5.2 GATE**: Oracle reviews step circuit relation encoding. `CycloFoldStepCircuit` correctly represents R4 relation. → APPROVE/REJECT

### Ω4.6 — R8 GATEs (E2E Pipeline)

- [ ] **R8.2 GATE**: Oracle reviews `pre-reveal-binding.md` + API surface atomicity. → APPROVE/REJECT
- [ ] **R8.5 GATE**: Oracle reviews `e2e_pipeline_soundness.rs` adversary model. → APPROVE/REJECT

---

## Phase Ω5 — Final Wave Re-run (after Ω4)

All 5 reviewers launched in parallel via `subagent_type="oracle"` (F1–F3) and `category="unspecified-high"` (F4–F5).

- [ ] **Ω5.1 Re-run F2**: Code quality after real NIZK integration. Expected: now APPROVE (the NO-OP/stub issues were the REJECT cause).
- [ ] **Ω5.2 Re-run F3**: Security soundness after construction review + missing docs created + F55 fixed. Expected: APPROVE.
- [ ] **Ω5.3 Re-run F5**: Context mining after all findings mapped to closing CI tests. Expected: APPROVE.
- [ ] **Ω5.4 F4**: Already re-run in Ω1.2. Verify output still valid.
- [ ] **Ω5.5 GATE**: All 5 verdicts are APPROVE. Final Wave cleared.

---

## Phase Ω6 — Infrastructure Completion (weeks–months)

### Ω6.1 — R6.7 Real Test Fixtures

- [ ] **R7 fixture generation**: Run `bb prove --scheme ultra_honk -b target/aggregator_final.json -w target/aggregator_final.gz -o target` per canonical BB flow. Commit proof + public inputs to `contracts/test/fixtures/`.
- [ ] **R6.7 RED**: Replace tautology tests in `PvtFheVerifier.t.sol` with fixture-based tests.
- [ ] **R6.7 GREEN**: Tests pass against committed fixtures.
- [ ] **R6.7 GATE**: Real fixtures committed; CI regeneration check.
- [ ] **R6.2 GATE**: `forge build --root contracts` green; CI checks generated verifier matches committed copy.

### Ω6.2 — R10 Enclave Integration

- [ ] **TEE hardware available**: SGX DCAP-capable machine or cloud instance.
- [ ] **R10.1 RED**: `attestation_required.rs` — verify_proof rejects non-SGX quotes, accepts valid SGX DCAP quotes signed by trusted attestor keys.
- [ ] **R10.2 RED**: `no_unconditional_accept.rs` — syn scan verifies `verify_proof` body contains no literal `Ok(true)` without prior verification.
- [ ] **R10.3 GREEN**: Real DCAP quote verification using `intel-tee-quote-verification` crate. Trust roots from `SessionRegistry.attestorRoots()`.
- [ ] **R10 GATE**: CI integration test against genuine SGX DCAP quote.

---

## Acceptance Criteria (Plan Complete)

All items below must be satisfied before declaring the remediation complete:

1. [x] All 144 implementation tasks green (R0–R10 code, tests, design docs)
2. [ ] All 29 oracle GATE reviews APPROVE (Ω4)
3. [ ] All 5 Final Wave verdicts APPROVE (Ω5.5)
4. [ ] External construction review sign-off letter committed (Ω2.1)
5. [ ] Parameter freeze document signed by crypto lead + zk lead (Ω2.2)
6. [ ] Adversarial dress rehearsal complete, zero unclosed CRITICAL findings (Ω3.3)
7. [ ] R6.7 real test fixtures committed (Ω6.1)
8. [ ] R10 enclave integration test against real TEE quote (Ω6.2)
9. [ ] 69 audit findings (F1–F69) each have a closing CI test or documented rationale (Ω5.3)
10. [ ] Soundness budget composition R1.5⊕R2.4⊕R3.1+R3.2⊕R4.4⊕R5.2⊕R6.1⊕R8.5 ≥ 2⁻¹²⁸ formally verified (Ω4.2)

---

## Notepad Files

- Decisions: `.sisyphus/notepads/pvthfhe-remediation/decisions.md`
- Learnings: `.sisyphus/notepads/pvthfhe-remediation/learnings.md`
- Issues: `.sisyphus/notepads/pvthfhe-remediation/issues.md`

Append entries to each as gates are cleared.
