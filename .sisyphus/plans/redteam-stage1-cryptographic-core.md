# Red-Team Stage 1: Cryptographic Core Remediation for Interfold Deployment

## TL;DR

> **Quick Summary**: Replace all cryptographic surrogates with production-grade implementations. Resolve critical findings C2–C6 and high-severity findings H1–H8 by implementing real folding, proper Fiat-Shamir NIZKs, and on-chain verification registries.
>
> **Deliverables**:
> - BRANCH-A vs BRANCH-B decision record
> - Real Ajtai commitment and Schwartz–Zippel challenges in Cyclo
> - Production-ready Noir circuits for Nova/HyperNova relations
> - Fixed NIZK Fiat-Shamir transcript absorption
> - On-chain `(n, t, roster, sessionId)` registry
> - Forged-share rejection logic in `share_wf` and `decrypt_share`
> - Hermine PVSS simulation removal and real implementation
> - Norm-bound and hash-family alignment fixes
> - DoS and replay protection
> - Stage 1 oracle re-audit report
>
> **Estimated Effort**: XL (6–10 weeks)
> **Parallel Execution**: YES — Waves 1–3
> **Critical Path**: T0 → {T1, T3, T4} → T2 → T13 → T14

---

## Context

### Original Request

"Document all findings and develop a mitigation plan." (Building on Stage 0 findings).

### Confirmed Pre-Findings

- C2 — Tautological Noir circuits (now revert from Stage 0).
- C3 — `crates/pvthfhe-cyclo/src/fold.rs` is SHA-256 hash chain; "Ajtai" is `Sha256("init"||..)`; norm is byte-max.
- C4 — NIZK Fiat-Shamir does not absorb `pvss_commitment` before challenge.
- C5 — Threshold downgrade: any `1≤t≤n` accepted.
- C6 — Forged-share threshold collapse via composition.
- H1–H8 — Various implementation vulnerabilities (simulation, unconstrained hashes, norm-bound errors).

### Metis Review

Metis review pending — to be obtained before T1.

---

## Work Objectives

### Core Objective

Deliver a cryptographically sound core for PVTHFHE, suitable for deployment in The Interfold's decentralized environment.

### Concrete Deliverables

- Decision record: `.sisyphus/design/branch-decision.md`.
- Remediation for all C-class and H-class findings.
- RED-then-GREEN test pairs for every fix.
- Re-audit by an independent oracle.
- `just stage1-gate`.

### Definition of Done

- [ ] BRANCH decision recorded with user approval
- [ ] H1–H8 disposition matrix complete (no Deferred items for deployment-relevant Highs)
- [ ] Confidentiality side-channel audit complete (T11.5)
- [ ] Withholding/griefing resistance proven (T11.6)
- [ ] Liveness engineering complete (T11.7)
- [ ] Decentralized adversary model published (T11.8)
- [ ] All C2–C6 findings have RED-then-GREEN test pairs
- [ ] All five F1–F5 reviews APPROVE independently (T13)
- [ ] `just stage1-gate` passes (including all 3 phase gates)
- [ ] Banner downgraded to "RESEARCH PROTOTYPE" only after all above
- [ ] Interfold threat-model attack matrix published with cross-walk to T11.8 (T15)
- [ ] Stage 0 T2 tripwire and T3 opt-in mock policy preserved

### Must Have

- TDD: RED test before every implementation change.
- Multi-party threshold enforcement (`t > n/2`).
- Real lattice-based folding (or off-the-shelf cycles-over-curves).
- Canonical Noir+BB flow.

### Must NOT Have (Guardrails)

- No `#[allow]` suppressions.
- No `nargo prove` / `nargo verify`.
- No scalar verdict collapse.

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** — all verification is agent-executed.

### Test Decision

- **Framework**: `cargo test -p <crate>`, `forge test --root contracts`.
- **Criteria**: Falsification tests (adversarial) must pass.
- **Oracle**: Final review by `oracle` agent.

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 0 (Strategy):
└── T0: BRANCH-A vs BRANCH-B Decision [oracle + deep]

Wave 1 (Remediation Foundation):
├── T1: Real Ajtai/Nova folding [unspecified-high]
├── T3: NIZK Fiat-Shamir absorption fix [unspecified-high]
├── T4: On-chain (n, t) registry + replay [unspecified-high]
├── T10: Hash-family alignment [unspecified-high]
└── T7: Hermine simulation removal [unspecified-high]

Wave 2 (Circuits & Hardening):
├── T2: Re-author Noir circuits [unspecified-high]
├── T6: decrypt_share circuit constraints [unspecified-high]
├── T8: Norm-bound fix [unspecified-high]
└── T5: Forged-share rejection [unspecified-high]

Wave 2.5 (Confidentiality & Liveness):
├── T11.5: Side-channel & oracle leakage [unspecified-high]
├── T11.6: Committee withholding & griefing [unspecified-high]
├── T11.7: Liveness engineering [unspecified-high]
└── T11.8: Decentralized adversary model [writing]

Wave 3 (Theory & DoS):
├── T9: Lemma 9 formalization [unspecified-high]
└── T11: DoS hardening [unspecified-high]

Wave 4 (Threat Model):
└── T15: Interfold threat model [writing]

Wave 5 (Synthesis & Audit):
├── T13: Stage 1 multi-review re-audit [oracle]
└── T14: Final integration & Gate [unspecified-high]
```

### Dependency Matrix

- **T0**: No dependencies.
- **T1, T3, T7, T10**: Blocked by T0.
- **T2**: Blocked by T1, T3, T6, T10.
- **T4**: Blocked by T0.
- **T6**: Blocked by T1.
- **T5**: Blocked by T6, T7.
- **T11.5–T11.8**: Blocked by Wave 1.
- **T15**: Blocked by T11.8.
- **T13**: Blocked by T15, T11.5, T11.6, T11.7.
- **T14**: Blocked by T13.
- **Critical Path**: T0 → {T1, T3, T6, T7, T10} → T2 → T4 → T5 → T11/T11.5/T11.6/T11.7 → T15 → T13 → T14.

---

## TODOs

- [ ] 0. **BRANCH-A vs BRANCH-B Decision**

  **What to do**:
  - Compare (A) Custom LatticeFold+ implementation vs (B) Off-the-shelf Nova/HyperNova.
  - Apply weighted decision rubric: soundness confidence (0–5), implementation risk (0–5), AGENTS backend-lock compatibility (pass/fail), toolchain fit (0–5), calendar cost (weeks).
  - Explicitly verify branch compatibility with the locked FHE backend (`gnosisguild/fhe.rs`) and the `fhe-math` ring backend pin in `crates/pvthfhe-cyclo/Cargo.toml`.
  - Document Branch-specific deliverable matrix (ADR table): which subsequent tasks (T1–T15) change scope under BRANCH-A vs BRANCH-B. Forbid mixed terminology after decision.
  - Decision deadline: 14 calendar days from T0 start. If no consensus, default to BRANCH-B (Nova-over-cycles) with documented rationale.
  - Author ADR file `.sisyphus/design/branch-decision-adr.md` with rubric scores, decision, rejection reasons for losing branch, decision owner, and timestamp.
  - Obtain explicit user approval.

  **Must NOT do**:
  - Proceed with T1+ without the approval marker.

  **Recommended Agent Profile**:
  - **Category**: `oracle` then `deep`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 0
  - **Blocks**: ALL
  - **Blocked By**: none

  **References**:
  - `AGENTS.md`, `.sisyphus/design/spec-real-p2p3.md §4.1 addendum`.

  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/branch-decision-adr.md` exists with `APPROVED-BY-USER:` marker line.
  - [ ] Rubric scores and branch-specific task matrix included.
  - [ ] Decision owner and timestamp recorded.

  **QA Scenarios**:
  ```bash
  grep "APPROVED-BY-USER:" .sisyphus/design/branch-decision-adr.md
  ```

  **Commit**: `design: record branch decision with rubric and task matrix`.


- [ ] 1. **Real Ajtai/Nova folding**

  **What to do**:
  - Replace SHA-256 hash chain in `crates/pvthfhe-cyclo/src/fold.rs` with real Ajtai commitments (Branch A) or Nova/HyperNova (Branch B).
  - Implement Schwartz–Zippel challenge logic.
  - Ring algebra type signatures MUST cite the pinned `fhe-math` types from `gnosisguild/fhe.rs`.

  **Must NOT do**:
  - Leave SHA-256 stubs in production paths.
  - Fail to align with `fhe-math` pinned types.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T2
  - **Blocked By**: T0

  **References**:
  - `crates/pvthfhe-cyclo/src/fold.rs`, `crates/pvthfhe-cyclo/Cargo.toml`.

  **Acceptance Criteria**:
  - [ ] `cargo test -p pvthfhe-cyclo --test fold_binding_adversarial` exits 0 with a tamper-binding test that would PASS if old SHA-chain were still present.
  - [ ] Production fold path AST-grepped to confirm no `Sha256("init"||..)` or byte-max norm survives.
  - [ ] Ring algebra type signatures cite pinned `fhe-math` types.
  - [ ] At least one challenge-soundness test using Schwartz–Zippel.

  **QA Scenarios**:
  ```bash
  cargo test -p pvthfhe-cyclo --test folding_soundness
  ast-grep --lang rust --pattern 'Sha256::new()' crates/pvthfhe-cyclo/src/ # Should return 0 in production paths
  ```

  **Commit**: `fhe: implement real folding commitment aligned with fhe-math`.

- [ ] 2. **Re-author Noir circuits**

  **What to do**:
  - Author real `circuits/micronova_wrap/src/main.nr` and `aggregator_final` to enforce the chosen folding relation.

  **Must NOT do**:
  - Use `nargo prove` / `nargo verify`.
  - Leave tautological constraints.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: T13
  - **Blocked By**: T1, T3, T6, T10

  **Acceptance Criteria**:
  - [ ] `nargo execute` passes with real witnesses.
  - [ ] `bb verify` succeeds on generated proof.
  - [ ] Adversarial cases: at least one malicious witness, one tampered public input, one tampered proof — each must fail `bb verify`.

  **QA Scenarios**:
  ```bash
  (cd circuits && nargo execute --package micronova_wrap && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs)
  ```

  **Commit**: `circuits: implement production folding relations with adversarial tests`.

- [ ] 3. **NIZK Fiat-Shamir absorption fix**

  **What to do**:
  - Ensure all public components (especially `pvss_commitment`) are absorbed into the challenge hash.
  - Remove `ConditionalSoundnessDisclosure`.
  - Transcript hash MUST include `pvss_commitment` proven via differential testing.

  **Must NOT do**:
  - Leave unabsorbed inputs in the transcript.
  - Use `ConditionalSoundnessDisclosure` returning success.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T13
  - **Blocked By**: T0

  **References**:
  - `crates/pvthfhe-fhe/src/nizk.rs`.

  **Acceptance Criteria**:
  - [ ] AST absence of `ConditionalSoundnessDisclosure` returning success.
  - [ ] Test where mismatched commitment inputs produce verifier reject (NOT disclosure).
  - [ ] Transcript hash includes `pvss_commitment` via differential testing.

  **QA Scenarios**:
  ```bash
  cargo test -p pvthfhe-fhe --test lattice_nizk_adversarial
  ```

  **Commit**: `nizk: fix Fiat-Shamir transcript absorption and remove disclosure`.

- [ ] 4. **On-chain Registry & Replay Protection**

  **What to do**:
  - Implement a registry contract for sessions and rosters.
  - Enforce `t > n/2` and roster root matching in `PvtFheVerifier.sol`.
  - Add session-id replay protection and commit-reveal windows.

  **Must NOT do**:
  - Allow arbitrary threshold values.
  - Allow cross-session replay.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T13
  - **Blocked By**: T0

  **References**:
  - `contracts/src/PvtFheVerifier.sol`.

  **Acceptance Criteria**:
  - [ ] `forge test --root contracts` passes for registry enforcement.
  - [ ] Tests for: nonexistent session, wrong roster root, wrong sessionId, stale epoch, duplicate proof/replay, unregistered committee, expired window, cross-session replay.
  - [ ] `t > n/2` enforced on-chain.

  **QA Scenarios**:
  ```bash
  forge test --root contracts --match-test testRejectReplay
  ```

  **Commit**: `contracts: integrated registry and replay protection`.


- [ ] 5. **Forged-share rejection**

  **What to do**:
  - Fix binding in `share_wf` and `decrypt_share`.
  - Add composition tests demonstrating rejection of forged shares.
  - Specify exact forged-share construction.

  **Must NOT do**:
  - Leave rejection sites weak in `share_wf` or `decrypt_share`.

  **Recommended Agent Profile**: `unspecified-high`

  **Parallelization**:
  - **Blocks**: T13
  - **Blocked By**: T6, T7

  **Acceptance Criteria**:
  - [ ] `cargo test -p pvthfhe-fhe --test forged_share_rejection` passes.
  - [ ] Rejection sites verified in BOTH `share_wf` and `decrypt_share`.

  **QA Scenarios**:
  ```bash
  cargo test -p pvthfhe-fhe --test forged_share_construction
  ```

  **Commit**: `fhe: reject forged shares via binding fixes`.

- [ ] 6. **decrypt_share circuit constraints**

  **What to do**:
  - Constrain `ciphertext_hash` and `d_i_hash`.
  - Replace XOR-Merkle with Poseidon Merkle.

  **Must NOT do**:
  - Leave unconstrained hash outputs in the circuit.

  **Parallelization**:
  - **Blocks**: T5, T2
  - **Blocked By**: T1

  **Acceptance Criteria**:
  - [ ] Independent tamper tests for: leaf, path, ciphertext_hash, d_i_hash. Each mutation rejects.
  - [ ] Poseidon Merkle proof verified in-circuit.

  **QA Scenarios**:
  ```bash
  (cd circuits && nargo execute --package decrypt_share)
  ```

  **Commit**: `circuits: harden decrypt_share with real Merkle and hash constraints`.

- [ ] 7. **Hermine real PVSS implementation**

  **What to do**:
  - Replace simulation with the real PVSS protocol from the paper OR remove paper claim and acknowledge.
  - Requirement: AST grep for "admitted" returns 0 OR paper claim removed.

  **Must NOT do**:
  - Keep simulation while claiming real implementation.

  **Parallelization**:
  - **Blocks**: T5
  - **Blocked By**: Wave 0

  **Acceptance Criteria**:
  - [ ] AST grep for "admitted" returns 0 in `hermine.rs`.
  - [ ] `cargo test -p pvthfhe-keygen` passes with real PVSS.

  **Commit**: `keygen: implement real Hermine PVSS (retire simulation)`.

- [ ] 8. **Norm-bound fix**

  **What to do**: Correct shortness check (>255) in `hermine.rs`.

  **Commit**: `keygen: correct norm-bound check in shortness verification`.

- [ ] 9. **Lemma 9 formalization**

  **What to do**: Produce `docs/security-proofs/lemma9.md` with formal proof or conjecture downgrade.

  **Commit**: `docs: formalize Lemma 9 security status`.

- [ ] 10. **Hash-family alignment**

  **What to do**: Unify on Poseidon (in-circuit) and Keccak (on-chain).

  **Commit**: `crypto: unify hash family and domain separation`.

- [ ] 11. **DoS hardening**

  **What to do**:
  - Add input bounds and time limits to all verification paths.
  - Concrete bounds: max input size, max proof size, max roster size, gas/runtime ceiling per verification path.

  **Must NOT do**:
  - Allow unbounded allocations or loops.

  **Acceptance Criteria**:
  - [ ] Each bound (size, gas, time) has a rejection test.
  - [ ] `cargo test` and `forge test` confirm enforcement.

  **Commit**: `security: add DoS protections to verification entry points`.

- [ ] 12. **ABSORBED INTO T4**


- [ ] 13. **Stage 1 Multi-Review Anti-Rubber-Stamp Re-Audit**

  **What to do**:
  - Model audit on `pvthfhe-skeptical-audit`'s F1–F4 wave.
  - **F1: Plan compliance (oracle)** — verifies every Stage 1 task acceptance was met from raw logs, not summaries.
  - **F2: Code quality (unspecified-high)** — independently re-runs builds with `--no-default-features`, `--features mock`, and production features; confirms no regressions.
  - **F3: Hands-on QA (unspecified-high)** — actually executes every adversarial test from a clean checkout.
  - **F4: Scope fidelity (deep)** — cross-walks paper claims, threat model, and code; flags any drift.
  - **F5: Contradiction checker (deep)** — automated diff between raw log files and any JSON/markdown summary; ANY contradiction → REJECT.

  **Must NOT do**:
  - Accept summary reports without verifying raw logs.
  - Skip clean-state rerun.

  **Acceptance Criteria**:
  - [ ] All five F1–F5 reviews APPROVE independently.
  - [ ] `clean-state rerun` is mandatory; raw logs are sole source of truth.

  **Commit**: `audit: Stage 1 multi-review re-audit report`.

- [ ] 14. **Final integration & Gate**

  **What to do**:
  - Run full suite, lift tripwires for fixed issues, downgrade banner.
  - Gated on: T13 (all 5 reviews APPROVE) AND T15 (Interfold threat model published) AND T11.5/T11.6/T11.7 complete.
  - Stage 0 T2 build-time tripwire and T3 opt-in mock policy SURVIVE Stage 1 indefinitely.

  **Must NOT do**:
  - Lift tripwires for findings not yet fixed.
  - Downgrade banner before T13/T15/T11.5-7 completion.

  **Acceptance Criteria**:
  - [ ] `just stage1-gate` success.
  - [ ] Matrix file `.sisyphus/evidence/finding-disposition-matrix.md` with H1–H8 each disposed as Fixed / Accepted-Risk / Deferred — block downgrade if any deployment-relevant High remains "Deferred".
  - [ ] Stage 0 T2 and T3 policies preserved.

  **Commit**: `stage1: final integration and gate success`.

- [ ] 15. **Interfold Threat Model & Attack Matrix**

  **What to do**:
  - Produce an Interfold attack matrix (table) with columns: adversary type, capability, targeted asset, mitigation task ID, test/evidence pointer, residual risk.
  - Cross-walk to T11.8 assumption inventory.

  **Must NOT do**:
  - Leave major Interfold attack vectors unmitigated or unrecorded.

  **Acceptance Criteria**:
  - [ ] `docs/interfold-threat-model.md` published with attack matrix.
  - [ ] Cross-walk to T11.8 complete.

  **Commit**: `docs: publish Interfold-specific threat model and attack matrix`.
