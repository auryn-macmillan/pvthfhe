# Red-Team Stage 0: Emergency Kill-Switch & Honest-Disclosure Containment

## TL;DR

> **Quick Summary**: Eliminate the ability to falsely claim PVTHFHE provides cryptographic guarantees it does not, before any Interfold deployment is contemplated. This stage focuses on immediate risk mitigation via "hard-reverts" of vacuous verifiers and pervasive "DO NOT DEPLOY" disclosures across all documentation and build artifacts.
>
> **Deliverables**:
> - Quarantine of suspect F1–F4 APPROVE evidence (Wave 0, blocking)
> - Repo-wide "DO NOT DEPLOY" banner in all public docs
> - Build-time surrogate tripwire (Cargo/Just/Solidity)
> - Opt-in mock backends (no default mock feature)
> - `PvtFheVerifier.sol` hard-revert
> - Tautological Noir circuits replaced with `assert(false)`
> - `SECURITY-ADVISORY-001.md` (gated draft)
> - `just stage0-gate` recipe + synthesis report
>
> **Estimated Effort**: S–M (≤1 week wall clock)
> **Parallel Execution**: YES — Wave 1 (T1–T6), Wave 2 (T7)
> **Critical Path**: T0 → T1–T6 → T7

---

## Context

### Original Request

"I'd like to red-team this repo now. Aggressively hunt theoretical or implementation issues that would allow an adversary to break assumptions, gain access to information they should not, deny service, halt processes, etc. Bearing in mind that the application we have in mind for this is The Interfold, a decentralized protocol for collaborative confidential compute. Document all findings and develop a mitigation plan."

### Confirmed Pre-Findings

- **C1 (CRITICAL).** `contracts/src/generated/HonkVerifier.sol` line 7 returns `keccak256(proof) == publicInputs[0]`; `contracts/src/PvtFheVerifier.sol` lines 109–111 set `publicInputs[0] = keccak256(proof)` then forward to `_honkVerifier.verify(...)`. Net effect: ANY proof bytes are accepted. The on-chain "verifier" performs no verification of FHE correctness, threshold reconstruction, or NIZK validity.
- **C2 (CRITICAL).** `circuits/micronova_wrap/src/main.nr` lines 10–16 are seven `assert(x == x)` tautologies. `circuits/aggregator_final/src/main.nr` lines 1–3 are a single `assert(x == x)`. No constraint relates the public inputs to any cryptographic statement.
- **M1 (MEDIUM).** README.md and ARCHITECTURE.md describe these as functional verifiers without prominent disclosure that they are research surrogates.
- **M2 (MEDIUM).** Default cargo features may build mock paths; users running `just demo-e2e` see green output with no surrogate warning.

### Metis Review

Metis review pending — to be obtained before Wave 1.

---

## Work Objectives

### Core Objective

Neutralize the risk of accidental or malicious production deployment of the current insecure prototype by enforcing explicit failure on all vacuous code paths and saturating the repository with high-visibility warnings.

### Concrete Deliverables

- [x] Suspect F1–F4 APPROVE evidence quarantined to `.sisyphus/evidence/quarantine/` with forensic README
- Top-of-file "DO NOT DEPLOY" banners in README.md, ARCHITECTURE.md, SECURITY.md, STATUS.md, WARNING.txt, and paper/main.tex.
- Stderr build-time warning emitted by Cargo and Justfile.
- Modified `crates/*/Cargo.toml` removing default mock features.
- Reverted `PvtFheVerifier.sol` and tautological Noir circuits.
- `SECURITY-ADVISORY-001.md` draft.
- `.sisyphus/evidence/redteam-stage0-report.md`.

### Definition of Done

- [x] Suspect F1–F4 APPROVE evidence quarantined to `.sisyphus/evidence/quarantine/` with forensic README
- [x] DO-NOT-DEPLOY banner on README, ARCHITECTURE, SECURITY, STATUS, WARNING.txt, paper abstract (mandated 3-claim text in first 15 lines)
- [x] just demo-e2e --seed 1 emits visible warning before success
- [x] Build-time surrogate tripwire surfaces stderr on every cargo/just/forge build
- [x] No default-feature mock path resolves to a usable FHE primitive; feature inventory complete
- [x] PvtFheVerifier.verify reverts; vacuous accept path removed; random adversarial tests pass
- [x] Tautological Noir circuits replaced with assert(false); grep -rE 'assert\(([a-zA-Z_]+)\s*==\s*\1\)' returns 0
- [x] SECURITY-ADVISORY-001 drafted (min 80 lines), gated on user okay
- [x] just stage0-gate passes (reruns raw verification, no cached logs)
- [x] User has acknowledged Stage 0 completion before Stage 1 begins

### Must Have

- Hard-reverts (failure by default) for all C1/C2 findings.
- Explicit "DO NOT DEPLOY" language — no softening.
- Build-time detection of surrogate usage.
- Verification of revert paths in tests.

### Must NOT Have (Guardrails)

- Stage 0 containment (T2 tripwire, T3 opt-in mocks) survives Stage 1 — do not lift in T14 or any later task.
- No deletion of stub files (replace in place per AGENTS.md).
- No softening of advisory language.
- No "green" demo output while surrogates are active.
- No publication of the security advisory without explicit user approval.

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** — all verification is agent-executed.

### Test Decision

- **Infrastructure exists**: YES (cargo test, forge test, nargo execute)
- **Automated tests**: YES — assert reverts and build-time failure detections
- **Standard**: Negative testing (asserting failure on insecure paths)

### QA Policy

- **Doc Audit**: `grep` check for banner presence and position.
- **Solidity**: `forge test --root contracts` asserting revert strings.
- **Noir**: `nargo execute` asserting failure.
- **Cargo**: `cargo build` grep for stderr warnings.

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 0 (Pre-wave — BLOCKING):
└── T0: Quarantine suspect F1–F4 APPROVE evidence [quick]

Wave 1 (Remediation & Disclosure):
├── T1: Repo-Wide Big-Banner Disclosure [writing]
├── T2: Compile-Time Surrogate Tripwire [unspecified-high]
├── T3: Disable Mock-Default Feature Paths [unspecified-high]
├── T4: PvtFheVerifier verify() Hard-Revert [unspecified-high]
├── T5: Noir Circuit Hard-Revert Equivalent [unspecified-high]
└── T6: Public Advisory Drafting [writing]

Wave 2 (Synthesis):
└── T7: Stage 0 Final Synthesis & Gate [writing]
```

### Dependency Matrix

- **T0**: no deps; blocks T1–T7
- **T1–T6**: Blocked By T0; can run in parallel.
- **T7**: Blocked by T0, T1–T6.

### Agent Dispatch Summary

- **Wave 0**: 1 — T0 → `quick`
- **Wave 1**: 6 — T1, T6 → `writing`, T2, T3, T4, T5 → `unspecified-high`
- **Wave 2**: 1 — T7 → `writing`

---

## TODOs

- [x] 0. **Quarantine Suspect F1–F4 APPROVE Evidence**

  **What to do**:
  - Create directory `.sisyphus/evidence/quarantine/final-qa/`
  - `git mv` the four suspect APPROVE evidence JSONs into it:
    - `.sisyphus/evidence/final-qa/f1-plan-compliance.json`
    - `.sisyphus/evidence/final-qa/f2-code-quality.json`
    - `.sisyphus/evidence/final-qa/f3-e2e.json`
    - `.sisyphus/evidence/final-qa/f4-scope.json`
  - Search for any prior `pvthfhe-followon` final-qa JSONs (`find .sisyphus -name 'f[1-5]*.json' -not -path '*/quarantine/*'`); quarantine any matches under `.sisyphus/evidence/quarantine/followon-final-qa/` using `git mv`. If none, document that fact.
  - Author `.sisyphus/evidence/quarantine/README.md` documenting WHY: these APPROVE verdicts were issued for code that the red-team subsequently identified as containing CRITICAL vulnerabilities (C1 vacuous on-chain verifier; C2 tautological Noir circuits; C3 SHA-256 hash-chain Cyclo fold; C4 NIZK Fiat-Shamir absorption gap; C5 threshold downgrade; C6 forged-share threshold collapse). They are preserved for forensic comparison against the future Stage 1 T13 multi-review re-audit. List every quarantined file with original path → new path. Add reference to `.sisyphus/plans/redteam-stage0-killswitch.md` and `.sisyphus/plans/redteam-stage1-cryptographic-core.md`.
  - `git add .sisyphus/evidence/quarantine && git commit -m "quarantine: move suspect F1-F4 APPROVE evidence pending red-team re-audit"` (do NOT push)

  **Must NOT do**:
  - Delete any files (use `git mv`, never `rm`)
  - Modify the JSON contents
  - Push the commit (review locally first)
  - Treat absence of these files as evidence of correctness — the Stage 1 T13 multi-review supersedes them

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Pure file-management + git operation, no design judgment
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: NO (must complete before T1–T7 begin to ensure clean evidence directory)
  - **Parallel Group**: Wave 0 (pre-wave, blocking)
  - **Blocks**: T1, T2, T3, T4, T5, T6, T7
  - **Blocked By**: None

  **References**:
  - `.sisyphus/evidence/final-qa/` — current location of suspect JSONs
  - `.sisyphus/plans/pvthfhe-skeptical-audit.md` — plan that emitted the suspect verdicts
  - AGENTS.md — git is acceptable; preserve history via `git mv`

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/final-qa/` is empty (or contains only post-quarantine new evidence): `ls .sisyphus/evidence/final-qa/ | wc -l` returns 0
  - [ ] `.sisyphus/evidence/quarantine/final-qa/` contains the 4 quarantined JSONs: `ls .sisyphus/evidence/quarantine/final-qa/*.json | wc -l` returns 4
  - [ ] `.sisyphus/evidence/quarantine/README.md` exists, ≥30 lines, references all 6 CRITICAL findings (C1–C6) and both red-team plan files
  - [ ] `git log -1 --oneline` shows the quarantine commit; `git log -1 --stat` shows the moved files preserving history (renames detected)
  - [ ] Followon search documented (either files moved or "no prior followon final-qa evidence found" line in README)

  **QA Scenarios**:

  ```
  Scenario: Quarantine completed with history preserved
    Tool: Bash (git + ls)
    Steps:
      1. ls .sisyphus/evidence/final-qa/ | grep -c '^f[1-4]' → assert 0
      2. ls .sisyphus/evidence/quarantine/final-qa/ | grep -c '^f[1-4].*\.json$' → assert 4
      3. test -s .sisyphus/evidence/quarantine/README.md → assert exit 0
      4. wc -l .sisyphus/evidence/quarantine/README.md → assert ≥ 30
      5. git log -1 --stat | grep -c 'rename' → assert ≥ 4
      6. git log -1 --pretty=%s → assert matches "^quarantine: move suspect F1-F4"
    Expected Result: All 6 assertions pass; suspect evidence is no longer at the canonical final-qa location and is forensically preserved
    Evidence: .sisyphus/evidence/quarantine/

  Scenario: README cites all CRITICAL findings
    Tool: Bash (grep)
    Steps:
      1. grep -cE '\\bC[1-6]\\b' .sisyphus/evidence/quarantine/README.md → assert ≥ 6
      2. grep -q 'redteam-stage0-killswitch' .sisyphus/evidence/quarantine/README.md → assert exit 0
      3. grep -q 'redteam-stage1-cryptographic-core' .sisyphus/evidence/quarantine/README.md → assert exit 0
    Expected Result: README explicitly names every CRITICAL finding and references both red-team plans
    Evidence: .sisyphus/evidence/quarantine/README.md
  ```

  **Commit**: YES (the task IS the commit)
  - Message: `quarantine: move suspect F1-F4 APPROVE evidence pending red-team re-audit`
  - Files: `.sisyphus/evidence/quarantine/`, `.sisyphus/evidence/final-qa/` (deletions via rename)
  - Pre-commit: none (read-only investigation, file moves only)

- [x] 1. **Repo-Wide Big-Banner Disclosure**

  **What to do**:
  - Add a top-of-README "DO NOT DEPLOY" banner.
  - Add identical banner to ARCHITECTURE.md, SECURITY.md, paper/main.tex (abstract section).
  - Create `STATUS.md` and `WARNING.txt` with the same banner.
  - Banner text MUST contain these exact claims: (a) "no on-chain cryptographic verification — verifier accepts any proof bytes", (b) "Noir circuits are tautological surrogates", (c) "do not use for The Interfold or any production deployment".
  - Banners must appear within the first 15 lines of each target file.
  - Update `just demo-e2e --seed 1` to emit a visible warning before any success text.

  **Must NOT do**:
  - Soften language or bury the banner.

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T7
  - **Blocked By**: T0

  **References**:
  - README.md, ARCHITECTURE.md, SECURITY.md, paper/main.tex.

  **Acceptance Criteria**:
  - [ ] `grep -l "DO NOT DEPLOY" README.md ARCHITECTURE.md SECURITY.md STATUS.md WARNING.txt paper/main.tex` exits 0.
  - [ ] Banner appears in first 15 lines of each markdown and source file.
  - [ ] `just demo-e2e --seed 1` emits warning BEFORE success text.

  **QA Scenarios**:
  ```bash
  head -15 README.md | grep -q "no on-chain cryptographic verification" && echo "PASS" || echo "FAIL"
  just demo-e2e --seed 1 2>&1 | grep -B 5 "Success" | grep -q "DO NOT DEPLOY"
  ```

  **Commit**: `disclosure: add mandated DO NOT DEPLOY banner to all public docs`.

- [x] 2. **Compile-Time Surrogate Tripwire**

  **What to do**:
  - Add a `build.rs` or workspace metadata check that emits a stderr warning if surrogates are active.
  - Stderr must surface across: `cargo build`, `cargo build -q`, `cargo test`, `cargo test -q`, `just demo-e2e`, `forge build --root contracts`, and Noir build path.
  - Each must surface `SURROGATE ACTIVE` or fail closed.
  - Inject surrogate warnings into `just demo-e2e` recipe.
  - List specific surrogates: `HonkVerifier`, `micronova_wrap`, `aggregator_final`, etc.

  **Must NOT do**:
  - Use `--quiet` or hide behind debug flags.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T7
  - **Blocked By**: T0

  **References**:
  - Justfile `demo-e2e` recipe; Cargo.toml.

  **Acceptance Criteria**:
  - [ ] `cargo build -p pvthfhe-fhe -q 2>&1 | grep -q "SURROGATE ACTIVE"` exits 0.
  - [ ] `forge build --root contracts 2>&1 | grep -q "SURROGATE ACTIVE"` exits 0.
  - [ ] `just demo-e2e 2>&1 | head -20 | grep -q "SURROGATE ACTIVE"` exits 0.

  **QA Scenarios**:
  ```bash
  cargo test -q 2>&1 | grep "SURROGATE ACTIVE"
  ```

  **Commit**: `disclosure: surrogate-active build-time tripwire`.

- [x] 3. **Disable Mock-Default Feature Paths**

  **What to do**:
  - Remove mock backends from default features in all `Cargo.toml` files.
  - Require `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` env var for mock activation at runtime.
  - Produce workspace-wide feature inventory in `.sisyphus/evidence/feature-inventory.md`.

  **Must NOT do**:
  - Delete mock code needed for CI.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T7
  - **Blocked By**: T0

  **References**:
  - `crates/pvthfhe-fhe/Cargo.toml`, `crates/pvthfhe-aggregator/Cargo.toml`.

  **Acceptance Criteria**:
  - [ ] `cargo build --workspace` with default features results in non-functional FHE (sentinel error).
  - [ ] `cargo build --features mock` + `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` succeeds.
  - [ ] `.sisyphus/evidence/feature-inventory.md` exists and is complete.

  **QA Scenarios**:
  ```bash
  cargo run -p pvthfhe-cli -- demo # Expect sentinel error: "PVTHFHE: default-features build cannot produce a usable FHE primitive"
  PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 cargo run -p pvthfhe-cli --features mock -- demo # Expect success
  ```

  **Commit**: `feature-flags: opt-in mock backends with understanding env var`.

- [x] 4. **PvtFheVerifier `verify()` Hard-Revert**

  **What to do**:
  - Replace body of `PvtFheVerifier.verify` with `revert("PVTHFHE: on-chain verifier is a research surrogate — do not deploy");`.
  - Forbid feature-flag/env conditional return paths in Solidity.
  - Add ABI-level adversarial Forge tests: random `proof` bytes × random `publicInputs` arrays × multiple senders → all revert.
  - Update `RealVerifier.t.sol` to expect this revert.

  **Must NOT do**:
  - Leave any code path returning `true`.
  - Use conditional logic that could bypass the revert.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T7
  - **Blocked By**: T0

  **References**:
  - `contracts/src/PvtFheVerifier.sol:97-112`.

  **Acceptance Criteria**:
  - [ ] `forge test --root contracts` passes with the revert expectation.
  - [ ] `grep -nE 'return\s+true|return\s+_honkVerifier' contracts/src/PvtFheVerifier.sol` returns 0.
  - [ ] Fuzz tests for proof/inputs all revert.

  **QA Scenarios**:
  ```bash
  forge test --root contracts --match-test testVerifyAlwaysReverts -vv
  ```

  **Commit**: `contracts: PvtFheVerifier hard-revert until real verifier lands`.

- [x] 5. **Noir Circuit Hard-Revert Equivalent**

  **What to do**:
  - Replace `circuits/micronova_wrap/src/main.nr` and `circuits/aggregator_final/src/main.nr` with `assert(false)`.
  - Ensure `nargo check --package <pkg>` still succeeds (compilation OK).
  - Ensure `nargo execute` fails with assertion error containing surrogate notice.
  - Forbid any remaining `assert(x == x)` patterns across all circuits.

  **Must NOT do**:
  - Leave `assert(x == x)` tautologies.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T7
  - **Blocked By**: T0

  **References**:
  - `circuits/micronova_wrap/src/main.nr`, `circuits/aggregator_final/src/main.nr`.

  **Acceptance Criteria**:
  - [ ] `nargo execute --package micronova_wrap --prover-name Prover` fails with surrogate notice.
  - [ ] `grep -rE 'assert\(([a-zA-Z_]+)\s*==\s*\1\)' circuits/` returns 0.

  **QA Scenarios**:
  ```bash
  (cd circuits && nargo check && nargo execute --package micronova_wrap) # Should compile then fail execution
  ```

  **Commit**: `circuits: hard-revert tautological surrogate circuits`.

- [x] 6. **Public Advisory Drafting**

  **What to do**:
  - Draft `SECURITY-ADVISORY-001.md` covering C1/C2/C3 findings.
  - Include CVSS-style severity and mitigation steps.
  - Include explicit sections: Impact, Affected Components, Exploit Sketch, Mitigation, Deployment Warning, Publication State (DRAFT).
  - Minimum 80 lines of substantive content.
  - Mark as `STATUS: DRAFT` — do not publish yet.

  **Must NOT do**:
  - Publish without user approval.

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T7
  - **Blocked By**: T0

  **References**:
  - .sisyphus/evidence/audit-report.md.

  **Acceptance Criteria**:
  - [ ] File exists with required sections and draft status.
  - [ ] `wc -l SECURITY-ADVISORY-001.md` is >= 80.

  **QA Scenarios**:
  ```bash
  grep "STATUS: DRAFT" SECURITY-ADVISORY-001.md
  ```

  **Commit**: `advisory: draft SECURITY-ADVISORY-001 (gated on user approval)`.

- [x] 7. **Stage 0 Final Synthesis & Gate**

  **What to do**:
  - Compile reports and evidence.
  - Add `just stage0-gate` recipe to Justfile.
  - Recipe must rerun raw verification commands (not parse cached evidence), archive logs, and FAIL if any summary file disagrees with raw logs.
  - Include a contradiction-checker subscript.

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 2
  - **Blocks**: completion
  - **Blocked By**: T0, T1–T6

  **References**:
  - All prior tasks.

  **Acceptance Criteria**:
  - [ ] `just stage0-gate` exits 0.
  - [ ] Any summary vs log contradiction causes failure.

  **QA Scenarios**:
  ```bash
  just stage0-gate
  ```

  **Commit**: `stage0: gate recipe + synthesis report`.
