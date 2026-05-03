# PVTHFHE Skeptical Audit & Remediation

## TL;DR

> **Quick Summary**: Conduct a skeptical, evidence-based audit of the four PVTHFHE novel constructions (P1 Lattice NIZK, P2 Real Folding, P3 On-chain Verifier, P4 Aggregator) — verifying implementation reality, theorem-faithfulness, test adequacy (adversarial standard), and paper-claim fidelity — then remediate any bugs, vacuous claims, or coverage gaps found.
>
> **Deliverables**:
> - Per-construction matrix: implementation × proof × test verdict + severity + confidence (`.sisyphus/evidence/audit-matrix.md`)
> - RED falsification test demonstrating P3 verifier vacuity (or structural proof if not constructible)
> - SURROGATE reachability table (5 files × 3 build paths)
> - Clippy-suppression cast audit (every `as` cast in `hermine.rs` classified)
> - Theorem inventory: identify missing 1/20, cite proof content for each "PROVED" row
> - Adversarial test classification (REAL / WEAK / TRIVIAL / MOCK per test)
> - Paper-claim fidelity classification (supported / overstated / contradicted / untestable)
> - Remediation: adversarial tests added, surrogates retired, suppressions fixed, paper claims corrected, missing theorem proved
> - Final severity-rated audit report (`.sisyphus/evidence/audit-report.md`)
>
> **Estimated Effort**: XL
> **Parallel Execution**: YES — 4 waves
> **Critical Path**: T4 (theorems) → T9/T10/T11/T12 (per-construction verdicts) → T13 (claim fidelity) → T17–T21 (remediation) → T22 (synthesis) → F1–F4

---

## Context

### Original Request

User: "review the theory and codebase for errors and bugs. Ensure any novel cryptography is proven with code. Ensure any novel code is thoroughly tested."

User is questioning whether the prior `pvthfhe-followon` "all APPROVE" verdict was honest, given:
- F2-code REJECT was "fixed" by `#![allow(clippy::as_conversions, clippy::manual_contains)]` — suppression, not a fix
- F1 REJECT was fixed by adding keywords/headings to satisfy text-pattern gates
- F5 REJECT was deferred as "environmental" (missing `pdflatex`)
- The `surrogate-retirement-check.py` PASSes when SURROGATE markers ARE PRESENT (annotation gate, not retirement gate)

### Confirmed Pre-Findings

1. **P3 Vacuity**: `contracts/src/P3RealVerifier.sol` (67 lines) uses `ecrecover` against hardcoded `TRUSTED_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` (Anvil account #0). It authenticates a signer; it does NOT verify any FHE computation. The "O(1) gas verifier" headline novelty is a trusted-party signature check.
2. **5 SURROGATE-marked files** still in tree: `contracts/src/generated/HonkVerifier.sol`, `circuits/aggregator_final/src/main.nr`, `circuits/decrypt_share/src/main.nr`, `crates/pvthfhe-fhe/src/fhers.rs`, `crates/pvthfhe-aggregator/src/keygen/protocol.rs` (latter is only 4 lines).
3. **Clippy suppressions** in `crates/pvthfhe-keygen/src/hermine.rs` (475 lines) silence `as_conversions` and `manual_contains`.
4. **1 of 20 theorems** was not fully proved per F2-proof review — identity unknown.

### Metis Review

**Gaps identified and addressed**:
- Single verdict per construction is too lossy → switched to **3 axes** (Implementation × Proof × Test) per P1–P4 + severity + confidence
- "Thoroughly tested" was undefined → user chose **adversarial / falsification standard**
- Honesty inference is unsupportable from code → reframe as "unsupported by evidence" not "dishonest"
- Lost-evidence risk → all investigation outputs MUST land in `.sisyphus/evidence/audit-*` durable files
- Dead-code risk → reachability check before severity assignment

**Guardrails applied**:
- No motive/honesty inference; only evidence-based claims
- Surrogate dead-code check before treating as severity issue
- Per-axis verdicts mandatory (no scalar collapse)
- Theorem audit bounded to "cited proof content per PROVED row"

---

## Work Objectives

### Core Objective

Determine whether PVTHFHE's four novel cryptographic constructions are correctly implemented, faithfully proved, and adversarially tested — then remediate every gap found.

### Concrete Deliverables

- `.sisyphus/evidence/audit-matrix.md` — per-construction × per-axis verdict matrix
- `.sisyphus/evidence/p3-vacuity-test/` — Forge test proving P3 verifier vacuity (or structural proof artifact)
- `.sisyphus/evidence/surrogate-reachability.md` — 5 files × {default, test, release} build-path table
- `.sisyphus/evidence/cast-audit.md` — every `as` cast in `hermine.rs` with src/dst types and risk class
- `.sisyphus/evidence/theorem-inventory.md` — 20-row table; missing one identified; proof citation per PROVED
- `.sisyphus/evidence/test-classification.md` — every test rated REAL/WEAK/TRIVIAL/MOCK with rationale
- `.sisyphus/evidence/paper-claims.md` — every P1–P4 claim from `paper/main.tex`/README/docs classified
- New adversarial tests for P1, P2, P4 covering theorem statements
- Surrogates retired (replaced, not annotated) OR documented as benign-dead with reachability proof
- Clippy suppressions removed and underlying casts fixed
- Missing theorem proof completed
- Paper claims updated to remove unsupported language
- `.sisyphus/evidence/audit-report.md` — final severity-rated synthesis

### Definition of Done

- [ ] All 20 theorems have cited proof content OR are explicitly marked as gaps
- [ ] Every `as` cast in clippy-suppressed files is documented as safe or fixed
- [ ] All 5 SURROGATE files are either retired or proved benign-dead
- [ ] P3 has either a real cryptographic verifier OR paper/docs explicitly disclose the trusted-signer model
- [ ] Each P1–P4 has at least one falsification (adversarial) test per major claim
- [ ] Paper contains zero "overstated" or "contradicted" claims per audit classification
- [ ] All gates (`just phase1-gate`, `just phase2-gate`, `just phase3-gate`) pass without suppressions

### Must Have

- Per-axis (Implementation × Proof × Test) verdicts for each of P1–P4
- Durable evidence artifacts for every investigation task
- Adversarial / falsification tests for every theorem-implementation pair
- Reachability analysis before severity assignment (no false positives from dead code)
- Honest reframing of P3 (real verifier OR explicit trusted-signer disclosure)

### Must NOT Have (Guardrails)

- No motive/honesty inference — only evidence-based claims
- No scalar verdict collapse (must keep 3 axes separate)
- No `#[allow(clippy::...)]` suppressions added or retained without per-cast justification
- No SURROGATE annotations counted as "retirement" — retirement = replacement
- No PROVED row without a citation to actual proof content
- No paper claim left "supported" without a concrete code/proof/test reference
- No human-manual acceptance criteria — all verifications must be agent-executable
- No silencing of failing tests (RED tests must turn GREEN by fixing the bug, not the test)

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** — all verification is agent-executed.

### Test Decision

- **Infrastructure exists**: YES (cargo test, forge test, nargo execute, bb verify)
- **Automated tests**: YES (TDD) — RED falsification test before each remediation
- **Framework**: `cargo test`, `forge test --root contracts`, `nargo execute --package <pkg>`, `bb verify --scheme ultra_honk`
- **Standard**: Adversarial / falsification — every claim must have a test that would FAIL if the claim were violated

### QA Policy

Every task MUST capture durable evidence to `.sisyphus/evidence/audit-*`. Investigation tasks emit markdown artifacts; remediation tasks emit test-run logs.

- **Solidity**: `forge test --root contracts --match-test <name> -vvv` → save logs
- **Rust**: `cargo test -p <crate> --test <test> -- --nocapture` → save logs
- **Noir + BB**: canonical flow only (`nargo execute` → `bb write_vk` → `bb prove` → `bb verify`); never `nargo prove`/`nargo verify`
- **Reachability**: `cargo build --tests` + `lsp_find_references` + `ast_grep_search`
- **Paper**: `grep -nE 'theorem|claim|novel|O\(1\)' paper/main.tex` + per-claim citation hunt

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Investigation — fire all in parallel, foundation):
├── T1: P3 vacuity falsification test [unspecified-high]
├── T2: SURROGATE reachability matrix [explore + unspecified-high]
├── T3: Clippy suppression cast audit [unspecified-high]
├── T4: Theorem inventory audit (20 rows) [deep]
├── T5: Test classification (REAL/WEAK/TRIVIAL/MOCK) [unspecified-high]
├── T6: Paper claim extraction [writing]
├── T7: P1 NIZK code-path reachability [explore]
└── T8: P2 folding code-path reachability [explore]

Wave 2 (Per-construction verdicts — depends on Wave 1):
├── T9:  P1 per-axis verdict (uses T4, T5, T7) [deep]
├── T10: P2 per-axis verdict (uses T4, T5, T8) [deep]
├── T11: P3 per-axis verdict (uses T1, T6) [deep]
├── T12: P4 per-axis verdict (uses T2, T4, T5) [deep]
├── T13: Paper claim fidelity classification (uses T6, T9–T12) [deep]
└── T14: Adversarial test gap analysis (uses T5, T9–T12) [unspecified-high]

Wave 3 (Remediation — depends on Wave 2 findings):
├── T15: Add P1 falsification tests for gaps from T14 [unspecified-high]
├── T16: Add P2 falsification tests for gaps from T14 [unspecified-high]
├── T17: P3 honesty fix — add disclosure OR design real-verifier sketch [artistry]
├── T18: SURROGATE retirement — replace OR prove dead per T2 [unspecified-high]
├── T19: Fix clippy suppressions — replace `as` casts with checked conversions [quick]
├── T20: Complete missing 20th theorem proof per T4 [deep]
└── T21: Update paper claims per T13 fidelity classification [writing]

Wave 4 (Synthesis):
├── T22: Final severity-rated audit report [writing]
└── T23: Update obligations.md, claims-table.md, gates [unspecified-high]

Wave FINAL (4 parallel reviews + user okay):
├── F1: Plan compliance audit (oracle)
├── F2: Code quality review (unspecified-high)
├── F3: Real manual QA — re-execute every adversarial test (unspecified-high)
└── F4: Scope fidelity check (deep)
→ Present results → user explicit "okay" → done

Critical Path: T4 → T9/T10/T11/T12 → T13 → T17/T20/T21 → T22 → F1–F4
Max Concurrent: 8 (Wave 1)
```

### Dependency Matrix

- **T1–T8**: no deps; fire immediately
- **T9**: T4, T5, T7
- **T10**: T4, T5, T8
- **T11**: T1, T6
- **T12**: T2, T4, T5
- **T13**: T6, T9, T10, T11, T12
- **T14**: T5, T9, T10, T11, T12
- **T15**: T14 (P1 portion)
- **T16**: T14 (P2 portion)
- **T17**: T11, T13
- **T18**: T2, T12
- **T19**: T3
- **T20**: T4
- **T21**: T13
- **T22**: T9–T21
- **T23**: T22
- **F1–F4**: T22, T23

### Agent Dispatch Summary

- **Wave 1**: 8 — T1 → `unspecified-high`, T2 → `unspecified-high`, T3 → `unspecified-high`, T4 → `deep`, T5 → `unspecified-high`, T6 → `writing`, T7 → `explore`, T8 → `explore`
- **Wave 2**: 6 — T9–T12 → `deep`, T13 → `deep`, T14 → `unspecified-high`
- **Wave 3**: 7 — T15/T16 → `unspecified-high`, T17 → `artistry`, T18 → `unspecified-high`, T19 → `quick`, T20 → `deep`, T21 → `writing`
- **Wave 4**: 2 — T22 → `writing`, T23 → `unspecified-high`
- **FINAL**: 4 — F1 → `oracle`, F2 → `unspecified-high`, F3 → `unspecified-high`, F4 → `deep`

---

## TODOs

- [x] 1. **P3 Vacuity Falsification Test**

  **What to do**:
  - Read `contracts/src/P3RealVerifier.sol` (67 lines) end-to-end
  - Confirm hardcoded `TRUSTED_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` and that `verify()` only does `ecrecover(digest, v, r, s) == TRUSTED_SIGNER`
  - Construct a Forge test that:
    1. Signs a digest representing a *false* FHE result (e.g., claims "ciphertext C decrypts to plaintext P" where P is arbitrary attacker choice) using the Anvil account #0 private key (`0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`)
    2. Calls `P3RealVerifier.verify(digest, v, r, s)` and asserts it returns `true`
    3. Demonstrates that nothing about FHE correctness is checked
  - Save test to `contracts/test/P3VacuityProof.t.sol`
  - Save run output to `.sisyphus/evidence/audit-p3-vacuity/`

  **Must NOT do**:
  - Modify `P3RealVerifier.sol` itself (this is the audit, not the fix)
  - Skip if test "feels redundant" — it is the canonical evidence artifact
  - Treat this as a bug-in-test: the test SHOULD pass (because the verifier IS vacuous)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Solidity test authoring + Forge tooling + cryptographic reasoning; not visual, not trivial
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T11
  - **Blocked By**: None

  **References**:
  - `contracts/src/P3RealVerifier.sol:30-65` — verifier implementation; note `ecrecover` only
  - `contracts/test/RealVerifier.t.sol` — existing test pattern for signing with Anvil keys
  - Foundry docs: `vm.sign(uint256 privateKey, bytes32 digest) returns (uint8 v, bytes32 r, bytes32 s)`
  - AGENTS.md: "Foundry: run `forge ... --root contracts` from repo root"

  **Acceptance Criteria**:
  - [ ] `contracts/test/P3VacuityProof.t.sol` exists
  - [ ] `forge test --root contracts --match-test testVacuousVerifierAcceptsFalseClaim -vvv` exits 0
  - [ ] Evidence file `.sisyphus/evidence/audit-p3-vacuity/forge-output.log` is non-empty and contains "PASS"
  - [ ] Markdown summary `.sisyphus/evidence/audit-p3-vacuity/SUMMARY.md` documents: hardcoded signer address, exact `ecrecover` call site (`P3RealVerifier.sol:63`), what is NOT verified (FHE ciphertext correctness, threshold reconstruction, NIZK validity)

  **QA Scenarios**:

  ```
  Scenario: Vacuous verifier accepts attacker-chosen false claim
    Tool: Bash (forge)
    Preconditions: contracts/test/P3VacuityProof.t.sol exists with attacker-controlled digest signed by Anvil key
    Steps:
      1. Run: forge test --root contracts --match-test testVacuousVerifierAcceptsFalseClaim -vvv
      2. Assert exit code == 0
      3. Assert stdout contains "[PASS] testVacuousVerifierAcceptsFalseClaim"
      4. Save full output to .sisyphus/evidence/audit-p3-vacuity/forge-output.log
    Expected Result: Test passes — proves verifier accepts arbitrary false claims signed by trusted signer
    Failure Indicators: Test fails (would mean verifier does check FHE correctness — invalidates the suspicion)
    Evidence: .sisyphus/evidence/audit-p3-vacuity/forge-output.log
  ```

  **Commit**: YES
  - Message: `audit(p3): RED test demonstrating verifier vacuity`
  - Files: `contracts/test/P3VacuityProof.t.sol`, `.sisyphus/evidence/audit-p3-vacuity/`
  - Pre-commit: `forge test --root contracts -vv`

- [x] 2. **SURROGATE Reachability Matrix**

  **What to do**:
  - For each of the 5 SURROGATE-marked files:
    1. `contracts/src/generated/HonkVerifier.sol`
    2. `circuits/aggregator_final/src/main.nr`
    3. `circuits/decrypt_share/src/main.nr`
    4. `crates/pvthfhe-fhe/src/fhers.rs`
    5. `crates/pvthfhe-aggregator/src/keygen/protocol.rs`
  - Determine for each file whether it is referenced/compiled/executed under three build profiles:
    - **default**: `cargo build` / `forge build --root contracts` / `nargo compile`
    - **test**: `cargo test --no-run` / `forge test --root contracts --no-match-test never`
    - **release**: `cargo build --release` / `forge build --root contracts --optimize`
  - Use `lsp_find_references` and `ast_grep_search` for cross-language reference tracing
  - For Solidity: check if `HonkVerifier` is imported by any deployed contract or test
  - For Noir: check if `aggregator_final` and `decrypt_share` packages are referenced by other circuits or by Rust integration tests
  - For Rust: check if `fhers` and `protocol.rs` are reachable from any binary or integration test entry point

  **Must NOT do**:
  - Treat presence of SURROGATE marker as proof of liveness — must trace actual reachability
  - Skip release-mode check (some surrogates may only be excluded under `cfg(test)`)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Multi-language reachability analysis across Rust/Solidity/Noir
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T12, T18
  - **Blocked By**: None

  **References**:
  - `crates/pvthfhe-aggregator/src/keygen/protocol.rs` (4 lines — likely a re-export shim)
  - `crates/pvthfhe-fhe/src/fhers.rs` — primary FHE backend module
  - `circuits/aggregator_final/Nargo.toml`, `circuits/decrypt_share/Nargo.toml`
  - `contracts/foundry.toml` for include/exclude paths
  - AGENTS.md: "Stub protocol — replace stubs in place, never delete and recreate"

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/surrogate-reachability.md` contains a 5×3 table (file × {default,test,release}) with values in {referenced, compiled, executed, dead}
  - [ ] Each row cites at least one referencing file:line OR proves no references exist via `grep -rn '<symbol>' .` output saved to `.sisyphus/evidence/audit-surrogate/grep-<file>.log`
  - [ ] Per-file verdict: `LIVE` (used at runtime), `TEST-ONLY` (only in tests), or `DEAD` (no references)

  **QA Scenarios**:

  ```
  Scenario: All 5 SURROGATE files classified
    Tool: Bash + grep
    Preconditions: cargo/forge/nargo build artifacts available
    Steps:
      1. For each surrogate file, run: grep -rn "<top-level symbol>" --include='*.rs' --include='*.sol' --include='*.nr' . > .sisyphus/evidence/audit-surrogate/grep-<file>.log
      2. Run: cargo build --tests 2>&1 | grep -E '(fhers|protocol)' > .sisyphus/evidence/audit-surrogate/cargo-build.log
      3. Verify .sisyphus/evidence/surrogate-reachability.md table has 5 rows × 3 columns populated
    Expected Result: 5×3 matrix complete with grep evidence per cell
    Evidence: .sisyphus/evidence/audit-surrogate/
  ```

  **Commit**: YES
  - Message: `audit(surrogate): reachability matrix for 5 SURROGATE files`
  - Files: `.sisyphus/evidence/audit-surrogate/`, `.sisyphus/evidence/surrogate-reachability.md`
  - Pre-commit: none (read-only investigation)

- [x] 3. **Clippy Suppression Cast Audit**

  **What to do**:
  - Read `crates/pvthfhe-keygen/src/hermine.rs` (475 lines) end-to-end
  - Locate the `#![allow(clippy::as_conversions, clippy::manual_contains)]` directive
  - For every `as` cast in the file, record:
    - Line number
    - Source type (e.g., `u64`)
    - Destination type (e.g., `i32`)
    - Risk class: `safe` (provably no truncation/sign-loss), `truncating` (loses bits), `sign-changing` (signed↔unsigned), `lossy-float` (float↔int)
    - Justification or fix recommendation
  - For every `manual_contains` instance, record line number and recommended `.contains()` rewrite
  - Save table to `.sisyphus/evidence/cast-audit.md`

  **Must NOT do**:
  - Add new `#[allow]` directives anywhere
  - Modify `hermine.rs` in this task (fix is T19)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Static analysis of Rust casts requires type inference + risk reasoning
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T19
  - **Blocked By**: None

  **References**:
  - `crates/pvthfhe-keygen/src/hermine.rs:1` — `#![allow(...)]` directive
  - Rust reference on `as`: https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions
  - Clippy lints: `clippy::as_conversions`, `clippy::cast_possible_truncation`, `clippy::cast_sign_loss`

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/cast-audit.md` enumerates every `as` cast with src/dst/risk/justification
  - [ ] Total count of casts matches: `grep -nE ' as [a-z_][a-z0-9_]*' crates/pvthfhe-keygen/src/hermine.rs | wc -l`
  - [ ] Each `manual_contains` instance documented with rewrite recommendation
  - [ ] Risk classes summed: N safe, N truncating, N sign-changing, N lossy-float

  **QA Scenarios**:

  ```
  Scenario: All casts enumerated and classified
    Tool: Bash (grep + manual analysis script)
    Preconditions: hermine.rs unchanged
    Steps:
      1. Run: grep -nE ' as [a-z_][a-z0-9_]*' crates/pvthfhe-keygen/src/hermine.rs > .sisyphus/evidence/audit-cast/grep-casts.log
      2. Verify line count in cast-audit.md matches grep count
      3. Verify each row has all 5 fields populated
    Expected Result: Complete cast inventory with risk classification
    Evidence: .sisyphus/evidence/audit-cast/, .sisyphus/evidence/cast-audit.md
  ```

  **Commit**: YES
  - Message: `audit(clippy): cast risk classification for hermine.rs`
  - Files: `.sisyphus/evidence/cast-audit.md`, `.sisyphus/evidence/audit-cast/`

- [x] 4. **Theorem Inventory Audit**

  **What to do**:
  - Read `docs/security-proofs/obligations.md` and confirm row count (should be 20)
  - For each of the 20 theorems:
    - Read `docs/security-proofs/{p1,p2,p3,p4}/T<N>.md` proof document
    - Locate cited proof content (formal argument, reduction, hybrid sequence, lemma chain)
    - Classify: `PROVED-WITH-CITATION` (cited content exists and is non-trivial), `PROVED-VACUOUS` (cited "proof" is restatement of claim), `GAP` (no proof content), `MISSING` (file/section absent)
  - Identify the 1/20 theorem flagged as not fully proved in F2-proof review
  - Cross-reference each theorem to its protected code path (e.g., T1 of P1 should bind to a specific function in `crates/pvthfhe-fhe/`)
  - Save `.sisyphus/evidence/theorem-inventory.md` with 20-row table

  **Must NOT do**:
  - Accept "PROVED" without a quote of the actual proof content
  - Skip cross-reference to code (theorem without code binding = orphan claim)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Cryptographic proof reading + cross-document reasoning + identifying subtle gaps
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T9, T10, T12, T20
  - **Blocked By**: None

  **References**:
  - `docs/security-proofs/obligations.md` — master inventory
  - `docs/security-proofs/{p1,p2,p3,p4}/T1.md` … `T5.md` — proof documents
  - `paper/main.tex` — 19 theorem environments (vs 20 obligations — discrepancy?)
  - `paper/claims-table.md` — claim-to-theorem mapping

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/theorem-inventory.md` has 20 rows
  - [ ] Each row has: theorem ID, statement, proof file path, classification (PROVED-WITH-CITATION / PROVED-VACUOUS / GAP / MISSING), cited proof excerpt (≥3 lines or "N/A"), code path, code file:line
  - [ ] The 1/20 unproved theorem is explicitly identified
  - [ ] Discrepancy between 20 obligations vs 19 paper theorems is resolved (which is missing?)

  **QA Scenarios**:

  ```
  Scenario: All 20 theorems classified with citations
    Tool: Bash (grep + read)
    Preconditions: docs/security-proofs/* present
    Steps:
      1. Run: grep -c "^| T" docs/security-proofs/obligations.md → expect 20
      2. Run: grep -c "\\\\begin{theorem}" paper/main.tex → expect 19 (discrepancy to resolve)
      3. Verify theorem-inventory.md has 20 rows with all required fields
      4. Verify at least 1 row is classified GAP or MISSING (the unproved one)
    Expected Result: Complete 20-row inventory with explicit gap identification
    Evidence: .sisyphus/evidence/theorem-inventory.md
  ```

  **Commit**: YES
  - Message: `audit(theorems): 20-row inventory with classification and citations`
  - Files: `.sisyphus/evidence/theorem-inventory.md`

- [x] 5. **Test Classification (REAL/WEAK/TRIVIAL/MOCK)**

  **What to do**:
  - Enumerate every test file under `crates/*/tests/`, `crates/*/src/**/*test*.rs`, `contracts/test/`, and `circuits/*/tests/` (if any)
  - For each test, classify per these rubrics:
    - **REAL**: Exercises the actual cryptographic primitive end-to-end with non-trivial inputs and checks an invariant that would fail if the primitive were broken
    - **WEAK**: Exercises the primitive but checks only weak invariants (e.g., "function returns" without checking output correctness)
    - **TRIVIAL**: Smoke test, type check, or roundtrip with degenerate inputs (zero, default, single element)
    - **MOCK**: Tests against a stubbed/mocked implementation, not the real cryptography
  - For adversarial tests in `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs` and `crates/pvthfhe-aggregator/tests/adversarial/*.rs`, verify each actually mutates inputs in a way that should be rejected (not a no-op tamper)
  - Save `.sisyphus/evidence/test-classification.md` with rows: test path, name, construction (P1–P4 or other), classification, rationale (1–2 sentences)

  **Must NOT do**:
  - Mark a test REAL without quoting the assertion that detects breakage
  - Conflate test pass count with test quality

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Reading test code + reasoning about what the assertion actually verifies
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T9, T10, T12, T14
  - **Blocked By**: None

  **References**:
  - `crates/pvthfhe-fhe/tests/lattice_nizk.rs`, `lattice_nizk_adversarial.rs`
  - `crates/pvthfhe-aggregator/tests/folding_n64.rs`, `folding_tamper.rs`, `tests/adversarial/*.rs`
  - `contracts/test/RealVerifier.t.sol`, `RealVerifierAdversarial.t.sol`
  - All `crates/*/tests/*.rs`

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/test-classification.md` lists every test (count from `grep -rn 'fn test_\|#\[test\]\|function test'`)
  - [ ] Each row classified REAL/WEAK/TRIVIAL/MOCK with rationale
  - [ ] Summary section: per-construction (P1–P4) count of REAL vs other

  **QA Scenarios**:

  ```
  Scenario: Test inventory complete and classified
    Tool: Bash (grep)
    Preconditions: workspace clean
    Steps:
      1. Run: grep -rn '#\[test\]\|fn test_' crates/ | wc -l > .sisyphus/evidence/audit-tests/rust-count.log
      2. Run: grep -rn 'function test' contracts/test/ | wc -l > .sisyphus/evidence/audit-tests/sol-count.log
      3. Verify test-classification.md row count == sum of above
    Expected Result: Complete classified test inventory
    Evidence: .sisyphus/evidence/test-classification.md, .sisyphus/evidence/audit-tests/
  ```

  **Commit**: YES
  - Message: `audit(tests): REAL/WEAK/TRIVIAL/MOCK classification`
  - Files: `.sisyphus/evidence/test-classification.md`, `.sisyphus/evidence/audit-tests/`

- [x] 6. **Paper Claim Extraction**

  **What to do**:
  - Read `paper/main.tex` end-to-end
  - Read `README.md`, `ARCHITECTURE.md` (repo root), `paper/claims-table.md`, and any `docs/*.md` discovered via `find docs -name '*.md'`
  - Extract every claim about P1–P4 that asserts:
    - Novelty ("first", "novel", "new", "we introduce")
    - Performance ("O(1)", "O(n)", "O(polylog)", concrete gas/time numbers)
    - Security ("secure under", "binding", "soundness", "hiding")
    - Correctness ("verifies", "proves", "guarantees")
  - For each claim, record: source file:line, exact quote, claim type, construction (P1–P4 or general)
  - Save `.sisyphus/evidence/paper-claims.md` with extracted claim list (will be classified for fidelity in T13)

  **Must NOT do**:
  - Paraphrase claims — quote exactly
  - Skip docs/README claims (paper consistency includes all public docs)

  **Recommended Agent Profile**:
  - **Category**: `writing`
    - Reason: Careful reading of paper text and structured extraction
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T11, T13
  - **Blocked By**: None

  **References**:
  - `paper/main.tex`
  - `paper/claims-table.md`
  - `README.md`
  - `ARCHITECTURE.md` (repo root — confirmed present)
  - `docs/` (discover via `find docs -name '*.md'`)

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/paper-claims.md` contains every novelty/performance/security/correctness claim
  - [ ] Each claim has: source file:line, exact quote (in backticks), claim type, construction
  - [ ] Total count matches manual `grep -nE 'novel|first|O\\(|secure|prove|verify' paper/main.tex` (sanity check; not exact match)

  **QA Scenarios**:

  ```
  Scenario: Claims extracted with citations
    Tool: Bash (grep) + manual extraction
    Preconditions: paper/main.tex present
    Steps:
      1. Run: grep -nE 'novel|first|\\\\bO\\\\(|secure|prove|verify' paper/main.tex README.md ARCHITECTURE.md $(find docs -name '*.md') > .sisyphus/evidence/audit-claims/grep-candidates.log
      2. Verify paper-claims.md cites at least every grep hit OR justifies exclusion
      3. Verify every claim row has all 4 fields populated AND source set includes paper/main.tex, README.md, ARCHITECTURE.md, plus any docs/*.md
    Expected Result: Complete claim inventory ready for fidelity classification
    Evidence: .sisyphus/evidence/paper-claims.md
  ```

  **Commit**: YES
  - Message: `audit(paper): extract P1-P4 claims with citations`
  - Files: `.sisyphus/evidence/paper-claims.md`, `.sisyphus/evidence/audit-claims/`

- [x] 7. **P1 NIZK Code-Path Reachability**

  **What to do**:
  - Map every public entry point of `crates/pvthfhe-fhe/` related to lattice NIZK
  - Identify which entry points are reached from:
    - Library users (`crates/pvthfhe-aggregator`, `crates/pvthfhe-keygen`, `crates/pvthfhe-cli`)
    - Tests (unit + integration)
    - Production binaries (CLI, API)
  - Use `lsp_find_references` and `cargo tree` for dependency tracing
  - For each entry point, confirm it is either USED or document why it is unused (dead code)
  - Save `.sisyphus/evidence/p1-reachability.md`

  **Must NOT do**:
  - Skip private functions called by reachable public ones (must trace the chain)

  **Recommended Agent Profile**:
  - **Category**: `explore`
    - Reason: Pure code reachability mapping; explore agent has thorough search
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T9
  - **Blocked By**: None

  **References**:
  - `crates/pvthfhe-fhe/src/lib.rs` — public API
  - `crates/pvthfhe-fhe/src/lattice_nizk*.rs` (or wherever NIZK lives)
  - `crates/pvthfhe-fhe/Cargo.toml`

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/p1-reachability.md` lists every public NIZK function with reachability classification
  - [ ] Each entry has: function signature, defined at file:line, used by [list of file:line callers]
  - [ ] Functions with zero callers are flagged as DEAD candidates

  **QA Scenarios**:

  ```
  Scenario: P1 NIZK entry points mapped
    Tool: Bash + lsp_find_references
    Steps:
      1. Run: grep -nE '^pub fn|^pub struct' crates/pvthfhe-fhe/src/*.rs > .sisyphus/evidence/audit-p1/api.log
      2. For each pub fn, run lsp_find_references and save output
      3. Verify p1-reachability.md covers every pub item
    Expected Result: Complete P1 API reachability map
    Evidence: .sisyphus/evidence/p1-reachability.md, .sisyphus/evidence/audit-p1/
  ```

  **Commit**: YES
  - Message: `audit(p1): NIZK code-path reachability map`

- [x] 8. **P2 Folding Code-Path Reachability**

  **What to do**:
  - Same as T7 but for `crates/pvthfhe-aggregator/` folding-related code (feature `real-folding`)
  - Confirm the `real-folding` feature is enabled by which build profiles
  - Trace folding entry points to actual usage (not just test usage)
  - Save `.sisyphus/evidence/p2-reachability.md`

  **Must NOT do**:
  - Conflate test-only paths with production paths

  **Recommended Agent Profile**:
  - **Category**: `explore`
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: T10
  - **Blocked By**: None

  **References**:
  - `crates/pvthfhe-aggregator/Cargo.toml` — feature flags
  - `crates/pvthfhe-aggregator/src/folding*.rs` or wherever folding lives
  - `crates/pvthfhe-aggregator/tests/folding_*.rs`

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/p2-reachability.md` documents folding API + reachability
  - [ ] Feature-flag analysis: which builds enable `real-folding`
  - [ ] Test-only vs production-path distinction explicit

  **QA Scenarios**:

  ```
  Scenario: P2 folding reachability mapped with feature analysis
    Tool: Bash + cargo
    Steps:
      1. Run: cargo build -p pvthfhe-aggregator --features real-folding 2>&1 | head -50 > .sisyphus/evidence/audit-p2/build.log
      2. Run: grep -rn 'fold\|Fold' crates/pvthfhe-aggregator/src/ > .sisyphus/evidence/audit-p2/symbols.log
      3. Verify p2-reachability.md classifies each symbol
    Expected Result: P2 folding API map with feature-flag context
    Evidence: .sisyphus/evidence/p2-reachability.md
  ```

  **Commit**: YES
  - Message: `audit(p2): folding code-path reachability map`

- [x] 9. **P1 Per-Axis Verdict (Implementation × Proof × Test)**

  **What to do**:
  - Synthesize T4 (theorem inventory rows for P1), T5 (test classification rows for P1), T7 (reachability) into a 3-axis verdict for P1 Lattice NIZK
  - **Implementation axis**: Is the lattice NIZK actually implemented (vs stubbed/mocked)? Cite code file:line. Verdict: `REAL` / `PARTIAL` / `STUB` / `MOCK`
  - **Proof axis**: Are P1's theorems (T1–T5 of P1) proved with cited content? Verdict: `PROVED` / `PARTIAL` / `GAP`
  - **Test axis**: Does P1 have falsification (adversarial) tests for each theorem claim? Verdict: `ADVERSARIAL` / `REGRESSION-ONLY` / `INSUFFICIENT`
  - Severity: combine three axes into overall risk: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE`
  - Confidence: `HIGH` / `MEDIUM` / `LOW` based on evidence completeness
  - Add P1 row to `.sisyphus/evidence/audit-matrix.md`

  **Must NOT do**:
  - Collapse three axes into one verdict
  - Inflate confidence without complete evidence

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Multi-document synthesis with crypto reasoning
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES (with T10, T11, T12)
  - **Parallel Group**: Wave 2
  - **Blocks**: T13, T14
  - **Blocked By**: T4, T5, T7

  **References**:
  - `.sisyphus/evidence/theorem-inventory.md` (P1 rows)
  - `.sisyphus/evidence/test-classification.md` (P1 rows)
  - `.sisyphus/evidence/p1-reachability.md`
  - `crates/pvthfhe-fhe/` source

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/audit-matrix.md` contains P1 row with: Impl axis, Proof axis, Test axis, Severity, Confidence, Evidence pointers
  - [ ] Each axis has a 1–3 sentence rationale citing prior evidence files
  - [ ] No axis collapsed or omitted

  **QA Scenarios**:

  ```
  Scenario: P1 verdict synthesizes all input evidence
    Tool: grep + read
    Steps:
      1. Verify audit-matrix.md contains a "## P1" section
      2. Verify section has Impl/Proof/Test/Severity/Confidence subheadings
      3. Verify each subheading body references at least one prior evidence file
    Evidence: .sisyphus/evidence/audit-matrix.md (P1 section)
  ```

  **Commit**: YES (groups with 10, 11, 12)
  - Message: `audit(p1): per-axis verdict (Impl × Proof × Test)`

- [x] 10. **P2 Per-Axis Verdict**

  **What to do**: Same as T9 but for P2 Real Folding. Use T4, T5, T8 inputs. Append P2 row to `audit-matrix.md`.

  **Recommended Agent Profile**: `deep`, skills `[]`

  **Parallelization**: Wave 2; blocks T13, T14; blocked by T4, T5, T8

  **References**: `.sisyphus/evidence/{theorem-inventory,test-classification,p2-reachability}.md`, `crates/pvthfhe-aggregator/`

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/audit-matrix.md` contains P2 section with all three axes + severity + confidence
  - [ ] Folding's `real-folding` feature flag status (enabled in which builds) cited

  **QA Scenarios**:

  ```
  Scenario: P2 verdict complete
    Steps: grep -A20 '## P2' .sisyphus/evidence/audit-matrix.md
    Expected: Section has Impl/Proof/Test/Severity/Confidence
    Evidence: .sisyphus/evidence/audit-matrix.md
  ```

  **Commit**: groups with 9, 11, 12

- [x] 11. **P3 Per-Axis Verdict**

  **What to do**: Synthesize T1 (vacuity test) and T6 (paper claims) into P3 verdict. Per-axis:
  - **Impl**: `MOCK` if vacuity test passes (verifier doesn't verify FHE) — cite `P3RealVerifier.sol:63` `ecrecover` line
  - **Proof axis**: Theorems P3-T1..T5 — do they prove what is claimed about the *trusted-signer* construction, or do they prove something about a hypothetical SNARK verifier that isn't built?
  - **Test axis**: Adversarial tests in `RealVerifierAdversarial.t.sol` — do they catch the vacuity (i.e., would they fail if we substituted a no-op verifier)?
  - Append P3 section to `audit-matrix.md`

  **Recommended Agent Profile**: `deep`, skills `[]`

  **Parallelization**: Wave 2; blocks T13, T14, T17; blocked by T1, T6

  **References**: `.sisyphus/evidence/{audit-p3-vacuity,paper-claims}.md`, `contracts/src/P3RealVerifier.sol`, `docs/security-proofs/p3/`

  **Acceptance Criteria**:
  - [ ] P3 section in audit-matrix.md
  - [ ] Explicit statement of whether P3's claimed novelty is REAL (cryptographic verifier) or VACUOUS (trusted-signer authenticator)
  - [ ] Cite `P3RealVerifier.sol:63` and the vacuity test result

  **QA Scenarios**:

  ```
  Scenario: P3 section present with all axes
    Tool: Bash (grep)
    Steps:
      1. grep -n '^### P3' .sisyphus/evidence/audit-matrix.md
      2. assert exit 0
      3. awk '/^### P3/,/^### P4|^## /' .sisyphus/evidence/audit-matrix.md > /tmp/p3-section.txt
      4. grep -E '^- \*\*(Impl|Proof|Test|Severity|Confidence)\*\*' /tmp/p3-section.txt | wc -l
      5. assert count == 5
    Expected Result: P3 block contains all 5 axis lines
    Evidence: .sisyphus/evidence/audit-matrix.md

  Scenario: P3 verdict cites vacuity evidence
    Tool: Bash (grep)
    Steps:
      1. awk '/^### P3/,/^### P4|^## /' .sisyphus/evidence/audit-matrix.md > /tmp/p3-section.txt
      2. grep -q 'P3RealVerifier.sol:63' /tmp/p3-section.txt
      3. assert exit 0
      4. grep -qE '(VACUOUS|MOCK|trusted-signer)' /tmp/p3-section.txt
      5. assert exit 0
    Expected Result: P3 verdict cites the ecrecover line and labels construction honestly
    Evidence: .sisyphus/evidence/audit-matrix.md
  ```

  **Commit**: groups with 9, 10, 12

- [x] 12. **P4 Per-Axis Verdict**

  **What to do**: Synthesize T2 (surrogate reachability for `protocol.rs`), T4 (P4 theorems), T5 (P4 tests) into P4 Aggregator verdict. Append to `audit-matrix.md`.

  **Recommended Agent Profile**: `deep`, skills `[]`

  **Parallelization**: Wave 2; blocks T13, T14, T18; blocked by T2, T4, T5

  **References**: `.sisyphus/evidence/{surrogate-reachability,theorem-inventory,test-classification}.md`, `crates/pvthfhe-aggregator/src/keygen/protocol.rs`

  **Acceptance Criteria**:
  - [ ] P4 section in audit-matrix.md
  - [ ] Statement of whether `protocol.rs` (4 lines) is a real implementation or a re-export shim
  - [ ] If shim: cite the actual implementation file:line

  **QA Scenarios**:

  ```
  Scenario: P4 section present with all axes
    Tool: Bash (grep)
    Steps:
      1. awk '/^### P4/,/^## /' .sisyphus/evidence/audit-matrix.md > /tmp/p4-section.txt
      2. grep -E '^- \*\*(Impl|Proof|Test|Severity|Confidence)\*\*' /tmp/p4-section.txt | wc -l
      3. assert count == 5
    Expected Result: P4 block contains all 5 axis lines
    Evidence: .sisyphus/evidence/audit-matrix.md

  Scenario: P4 verdict classifies protocol.rs (shim vs real)
    Tool: Bash (grep)
    Steps:
      1. awk '/^### P4/,/^## /' .sisyphus/evidence/audit-matrix.md > /tmp/p4-section.txt
      2. grep -qE '(shim|re-export|real implementation)' /tmp/p4-section.txt
      3. assert exit 0
      4. grep -qE 'crates/pvthfhe-aggregator/src/keygen/protocol\.rs' /tmp/p4-section.txt
      5. assert exit 0
    Expected Result: P4 verdict explicitly classifies protocol.rs and cites file path
    Evidence: .sisyphus/evidence/audit-matrix.md
  ```

  **Commit**: groups with 9, 10, 11

 - [x] 13. **Paper Claim Fidelity Classification**

  **What to do**:
  - For each claim in `.sisyphus/evidence/paper-claims.md`, classify against the per-axis verdicts (T9–T12):
    - `supported`: claim matches code+proof+test reality
    - `overstated`: claim exaggerates beyond what evidence supports (e.g., "novel verifier" when it's a trusted-signer)
    - `contradicted`: code or proof actively contradicts the claim
    - `untestable from repo`: claim is about external systems / future work
  - Cite specific evidence row per classification
  - Save updated `.sisyphus/evidence/paper-claims.md` (add classification column)
  - Generate summary: count per category

  **Must NOT do**:
  - Mark "supported" without citing the supporting evidence file:line
  - Use "untestable" as an escape hatch for testable claims

  **Recommended Agent Profile**: `deep`, skills `[]`

  **Parallelization**: Wave 2; blocks T17, T21; blocked by T6, T9, T10, T11, T12

  **References**: All Wave-1 and Wave-2 evidence files

  **Acceptance Criteria**:
  - [ ] Every row in paper-claims.md has a fidelity classification + evidence citation
  - [ ] Summary section: N supported, N overstated, N contradicted, N untestable
  - [ ] At least one claim about P3 is classified `overstated` or `contradicted` (given confirmed pre-finding)

  **QA Scenarios**:

  ```
  Scenario: All paper claims classified with citations
    Steps: grep -c '^|.*|.*|.*|.*|' .sisyphus/evidence/paper-claims.md (count rows with fidelity column)
    Expected: row count == claim count from T6
    Evidence: .sisyphus/evidence/paper-claims.md
  ```

  **Commit**: YES
  - Message: `audit(claims): paper-claim fidelity classification`

- [x] 14. **Adversarial Test Gap Analysis**

  **What to do**:
  - For each P1–P4 verdict (T9–T12) where Test axis is `REGRESSION-ONLY` or `INSUFFICIENT`, enumerate the missing falsification tests
  - For each missing test, specify:
    - Theorem/claim it would falsify
    - Test name (snake_case)
    - Tampering strategy (e.g., flip 1 bit in NIZK proof, replace folding accumulator, sign different claim)
    - Expected assertion (e.g., `verify()` returns false, decryption fails)
  - Save `.sisyphus/evidence/adversarial-gaps.md` — this is the input for T15, T16

  **Recommended Agent Profile**: `unspecified-high`, skills `[]`

  **Parallelization**: Wave 2; blocks T15, T16; blocked by T5, T9, T10, T11, T12

  **References**: `audit-matrix.md`, existing adversarial tests in `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs`, `crates/pvthfhe-aggregator/tests/adversarial/`

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/adversarial-gaps.md` enumerates every missing test as actionable spec
  - [ ] Each entry: claim being falsified, test name, tamper strategy, expected assertion, target file path

  **QA Scenarios**:

  ```
  Scenario: Adversarial gap file exists and non-empty
    Tool: Bash
    Steps:
      1. test -s .sisyphus/evidence/adversarial-gaps.md
      2. assert exit 0
    Expected Result: file exists with non-zero size
    Evidence: .sisyphus/evidence/adversarial-gaps.md

  Scenario: Each gap entry has all 5 required fields
    Tool: Bash (grep)
    Steps:
      1. grep -cE '^\s*-\s+\*\*Claim\*\*:' .sisyphus/evidence/adversarial-gaps.md > /tmp/n_claim
      2. grep -cE '^\s*-\s+\*\*Test name\*\*:' .sisyphus/evidence/adversarial-gaps.md > /tmp/n_name
      3. grep -cE '^\s*-\s+\*\*Tamper(ing)? strategy\*\*:' .sisyphus/evidence/adversarial-gaps.md > /tmp/n_tamp
      4. grep -cE '^\s*-\s+\*\*Expected assertion\*\*:' .sisyphus/evidence/adversarial-gaps.md > /tmp/n_exp
      5. grep -cE '^\s*-\s+\*\*Target file\*\*:' .sisyphus/evidence/adversarial-gaps.md > /tmp/n_tgt
      6. assert all five counts equal and > 0
    Expected Result: every entry has Claim, Test name, Tamper strategy, Expected assertion, Target file
    Evidence: .sisyphus/evidence/adversarial-gaps.md

  Scenario: Each gap references a verdict with INSUFFICIENT or REGRESSION-ONLY test axis
    Tool: Bash (grep)
    Steps:
      1. grep -qE '(INSUFFICIENT|REGRESSION-ONLY)' .sisyphus/evidence/audit-matrix.md
      2. assert exit 0 (precondition: gap analysis only triggered when matrix flags weak test axis)
    Expected Result: gaps are derived from real verdict deficiencies, not invented
    Evidence: .sisyphus/evidence/audit-matrix.md
  ```

  **Commit**: YES
  - Message: `audit(tests): adversarial gap inventory`

 - [x] 15. **Add P1 Falsification Tests**

  **What to do**:
  - Read `.sisyphus/evidence/adversarial-gaps.md` (P1 entries)
  - For each P1 gap, write a RED-then-GREEN adversarial test:
    1. Write the failing test first (RED): tamper input as specified, assert verifier rejects
    2. Run test — if it passes immediately, the implementation is already correct (document) OR the test is too weak (strengthen)
    3. If test fails because verifier ACCEPTS tampered input, that is a real bug — document and fix
  - Add tests to `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs` (replace stubs in place per AGENTS.md; do not delete-and-recreate)
  - Save logs to `.sisyphus/evidence/audit-p1/adversarial-runs.log`

  **Must NOT do**:
  - Skip tests that fail "because they're hard to write"
  - Silence failing tests with `#[ignore]`
  - Delete and recreate the test file (stub protocol violation)

  **Recommended Agent Profile**: `unspecified-high`, skills `[]`

  **Parallelization**: Wave 3; blocks T22; blocked by T14

  **References**: `.sisyphus/evidence/adversarial-gaps.md`, `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs`, AGENTS.md stub protocol

  **Acceptance Criteria**:
  - [ ] Every P1 gap from `adversarial-gaps.md` has a corresponding test in the adversarial test file
  - [ ] `cargo test -p pvthfhe-fhe --test lattice_nizk_adversarial -- --nocapture` exits 0
  - [ ] Test count increased by N (where N = P1 gap count)
  - [ ] Any newly discovered bugs documented in `.sisyphus/evidence/audit-p1/bugs-found.md` (may be empty)

  **QA Scenarios**:

  ```
  Scenario: All P1 adversarial tests added and pass
    Tool: Bash (cargo)
    Steps:
      1. Run: cargo test -p pvthfhe-fhe --test lattice_nizk_adversarial -- --nocapture > .sisyphus/evidence/audit-p1/adversarial-runs.log 2>&1
      2. Assert exit code 0
      3. Verify test count >= prior count + N (per gap inventory)
    Evidence: .sisyphus/evidence/audit-p1/adversarial-runs.log
  ```

  **Commit**: YES
  - Message: `test(p1): add adversarial falsification tests for NIZK claims`
  - Pre-commit: `cargo test -p pvthfhe-fhe`

 - [x] 16. **Add P2 Falsification Tests**

  **What to do**: Same as T15 but for P2 folding gaps. Add to `crates/pvthfhe-aggregator/tests/folding_tamper.rs` or `tests/adversarial/`.

  **Recommended Agent Profile**: `unspecified-high`, skills `[]`

  **Parallelization**: Wave 3; blocks T22; blocked by T14

  **References**: `crates/pvthfhe-aggregator/tests/folding_tamper.rs`, `tests/adversarial/`

  **Acceptance Criteria**:
  - [ ] Every P2 gap has a corresponding test
  - [ ] `cargo test -p pvthfhe-aggregator --features real-folding -- --nocapture` exits 0
  - [ ] Bugs (if any) documented in `.sisyphus/evidence/audit-p2/bugs-found.md`

  **QA Scenarios**:

  ```
  Scenario: All P2 adversarial tests added and pass
    Steps: cargo test -p pvthfhe-aggregator --features real-folding > .sisyphus/evidence/audit-p2/adversarial-runs.log 2>&1
    Assert: exit 0, test count increased
    Evidence: .sisyphus/evidence/audit-p2/adversarial-runs.log
  ```

  **Commit**: YES
  - Message: `test(p2): add adversarial falsification tests for folding claims`

- [x] 17. **P3 Honesty Fix — Disclosure OR Real-Verifier Sketch**

  **What to do**:
  - **If T13 classified P3 claims as `overstated`/`contradicted`** (expected outcome):
    - **Option A (DISCLOSE)**: Update `paper/main.tex` and `README.md` to explicitly state that the on-chain verifier is a trusted-signer authenticator (not a cryptographic verifier of FHE correctness). Add disclaimer language: "Currently the on-chain verifier authenticates claims signed by a trusted threshold-of-N committee; replacing this with a SNARK verifier of the FHE computation is future work."
    - **Option B (DESIGN)**: Produce a design sketch for a real verifier in `.sisyphus/evidence/p3-real-verifier-sketch.md`: SNARK choice (Honk/Plonk/Groth16), proof-system inputs (FHE ciphertext relation), gas estimate, integration plan. Do NOT implement (out of scope for this plan).
  - The agent must do BOTH A (disclose) AND B (design sketch) — disclosure is non-optional honesty fix; sketch records the path forward
  - Update `paper/claims-table.md` to reflect new claim language

  **Must NOT do**:
  - Implement the real verifier in this task (separate plan)
  - Leave any "novel verifier" or "O(1) gas verifier" language without immediate "trusted-signer" qualification
  - Delete the P3RealVerifier contract (it may be useful as a trusted-signer baseline)

  **Recommended Agent Profile**:
  - **Category**: `artistry`
    - Reason: Requires non-conventional honesty repositioning + cryptographic design sketch
  - **Skills**: `[]`

  **Parallelization**: Wave 3; blocks T21, T22; blocked by T11, T13

  **References**: `paper/main.tex`, `README.md`, `paper/claims-table.md`, `.sisyphus/evidence/{audit-p3-vacuity,paper-claims}.md`

  **Acceptance Criteria**:
  - [ ] `paper/main.tex` and `README.md` contain trusted-signer disclosure (verifiable via `grep -n "trusted.signer\|trusted-signer" paper/main.tex README.md`)
  - [ ] Zero remaining unqualified "novel verifier" / "cryptographic verifier" / "O(1) gas verifier" claims (verifiable via `grep -niE "novel verifier|cryptographic verifier|O\\(1\\) gas verifier" paper/main.tex README.md` returns ONLY qualified contexts)
  - [ ] `.sisyphus/evidence/p3-real-verifier-sketch.md` non-empty with: SNARK choice + rationale, public/private inputs schema, gas estimate range, deployment plan

  **QA Scenarios**:

  ```
  Scenario: P3 disclosure language present and unqualified novelty claims absent
    Tool: Bash (grep with context)
    Steps:
      1. Run: grep -niE 'trusted[- ]signer' paper/main.tex README.md > .sisyphus/evidence/audit-p3-fix/disclosure.log
      2. Assert: file is non-empty (wc -l > 0)
      3. Run: grep -niC 2 -E 'novel verifier|cryptographic verifier|O\(1\) gas verifier' paper/main.tex README.md > .sisyphus/evidence/audit-p3-fix/novelty-with-context.log
      4. Run scripted check (saved to scripts/check-p3-disclosure.sh):
         For each grep hit in step 3, verify the surrounding 2 lines (-C 2) contain at least one of: "trusted-signer", "trusted signer", "future work", "not a SNARK". Exit 1 if any hit lacks qualifier.
      5. Assert: scripts/check-p3-disclosure.sh exits 0
    Expected Result: Trusted-signer disclosure present; every novelty mention is contextualized within ±2 lines (verified by script, no human review)
    Evidence: .sisyphus/evidence/audit-p3-fix/, scripts/check-p3-disclosure.sh

  Scenario: Real-verifier sketch produced
    Steps: test -s .sisyphus/evidence/p3-real-verifier-sketch.md
    Evidence: .sisyphus/evidence/p3-real-verifier-sketch.md
  ```

  **Commit**: YES
  - Message: `fix(p3): disclose trusted-signer model and sketch real-verifier path`

 - [x] 18. **SURROGATE Retirement OR Dead-Code Proof**

  **What to do**:
  - For each of 5 SURROGATE files, based on T2 reachability classification:
    - **If LIVE**: replace SURROGATE implementation with real implementation (per AGENTS.md stub protocol — replace in place)
    - **If TEST-ONLY**: move to `tests/` directory and remove SURROGATE marker; document role
    - **If DEAD**: remove file; verify build still passes
  - Update `surrogate-retirement-check.py` to PASS only when ZERO SURROGATE markers remain (invert current logic)
  - For files where real-implementation replacement is out of scope (e.g., `HonkVerifier.sol` requires running `bb write_solidity_verifier`), document the canonical regeneration command in `.sisyphus/evidence/audit-surrogate/regeneration.md`

  **Must NOT do**:
  - Delete-and-recreate any file (stub protocol)
  - Leave SURROGATE markers in retired files
  - Update the check to pass without inverting its logic

  **Recommended Agent Profile**: `unspecified-high`, skills `[]`

  **Parallelization**: Wave 3; blocks T22; blocked by T2, T12

  **References**: `.sisyphus/evidence/surrogate-reachability.md`, `surrogate-retirement-check.py` (find via `find . -name 'surrogate-retirement-check.py'`), AGENTS.md stub protocol, AGENTS.md canonical Noir+BB flow

  **Acceptance Criteria**:
  - [ ] `grep -rn 'SURROGATE' --include='*.rs' --include='*.sol' --include='*.nr' .` returns 0 hits (or only annotated test fixtures)
  - [ ] `surrogate-retirement-check.py` passes with zero markers (verifies inverted logic)
  - [ ] All gates still pass: `just phase1-gate && just phase2-gate && just phase3-gate`
  - [ ] `.sisyphus/evidence/audit-surrogate/regeneration.md` documents canonical regeneration commands for any auto-generated files

  **QA Scenarios**:

  ```
  Scenario: All SURROGATE markers retired
    Tool: Bash (grep + just)
    Steps:
      1. Run: grep -rn 'SURROGATE' --include='*.rs' --include='*.sol' --include='*.nr' . | tee .sisyphus/evidence/audit-surrogate/post-retirement.log
      2. Assert: empty (or only files explicitly listed as test fixtures in evidence)
      3. Run: just phase1-gate && just phase2-gate && just phase3-gate
      4. Assert: all gates exit 0
    Evidence: .sisyphus/evidence/audit-surrogate/post-retirement.log
  ```

  **Commit**: YES
  - Message: `fix(surrogate): retire SURROGATE markers (replace or remove)`

- [x] 19. **Fix Clippy Suppressions**

  **What to do**:
  - Read `.sisyphus/evidence/cast-audit.md`
  - For each `as` cast in `crates/pvthfhe-keygen/src/hermine.rs`:
    - **safe**: replace with `From`/`Into` or `try_from().unwrap()` with documented invariant
    - **truncating/sign-changing/lossy-float**: replace with `u32::try_from(x).expect("documented invariant")` or `checked_*` arithmetic returning `Result`
  - For each `manual_contains` instance: rewrite with `.contains()`
  - Remove the `#![allow(clippy::as_conversions, clippy::manual_contains)]` directive
  - Verify `cargo clippy -p pvthfhe-keygen --all-targets -- -D warnings` passes

  **Must NOT do**:
  - Add new `#[allow]` anywhere
  - Use `as` for any cast that could truncate/sign-change without `try_from` rationale

  **Recommended Agent Profile**: `quick`, skills `[]`

  **Parallelization**: Wave 3; blocks T22; blocked by T3

  **References**: `.sisyphus/evidence/cast-audit.md`, `crates/pvthfhe-keygen/src/hermine.rs`

  **Acceptance Criteria**:
  - [ ] `grep -n '#!\[allow' crates/pvthfhe-keygen/src/hermine.rs` returns 0 hits
  - [ ] `cargo clippy -p pvthfhe-keygen --all-targets -- -D warnings` exits 0
  - [ ] `cargo test -p pvthfhe-keygen` exits 0 (no behavioral regression)

  **QA Scenarios**:

  ```
  Scenario: Clippy clean without suppressions
    Steps:
      1. grep -n '#!\\[allow' crates/pvthfhe-keygen/src/hermine.rs > .sisyphus/evidence/audit-cast/post-fix-allows.log; assert empty
      2. cargo clippy -p pvthfhe-keygen --all-targets -- -D warnings > .sisyphus/evidence/audit-cast/clippy.log 2>&1; assert exit 0
      3. cargo test -p pvthfhe-keygen > .sisyphus/evidence/audit-cast/test.log 2>&1; assert exit 0
    Evidence: .sisyphus/evidence/audit-cast/
  ```

  **Commit**: YES
  - Message: `fix(keygen): replace as casts with checked conversions; remove clippy allows`

- [x] 20. **Complete Missing 20th Theorem Proof**

  **What to do**:
  - From T4, identify the unproved theorem (the 1/20)
  - Read its statement and existing proof skeleton (if any)
  - Write the complete proof — formal argument with reduction/hybrid/lemma chain
  - Add to appropriate `docs/security-proofs/{p1,p2,p3,p4}/T<N>.md`
  - Update `docs/security-proofs/obligations.md` row from `GAP` to `PROVED-WITH-CITATION`
  - Add corresponding theorem environment to `paper/main.tex` (if missing — recall paper had 19 vs 20 obligations)

  **Must NOT do**:
  - Mark proved without writing the proof content
  - Use vague "by inspection" or "obvious" arguments without justification

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Cryptographic proof writing requires deep reasoning
  - **Skills**: `[]`

  **Parallelization**: Wave 3; blocks T22; blocked by T4

  **References**: T4 evidence, existing proofs in `docs/security-proofs/{p1,p2,p3,p4}/T*.md` for style

  **Acceptance Criteria**:
  - [ ] The previously-unproved theorem has a non-trivial proof (≥20 lines of formal argument)
  - [ ] `docs/security-proofs/obligations.md` shows all 20 rows as `PROVED-WITH-CITATION`
  - [ ] `paper/main.tex` theorem count == 20 (verifiable via `grep -c '\\\\begin{theorem}' paper/main.tex`)

  **QA Scenarios**:

  ```
  Scenario: All 20 theorems proved with content
    Steps:
      1. grep -c 'PROVED-WITH-CITATION' docs/security-proofs/obligations.md → expect 20
      2. grep -c 'GAP\|MISSING' docs/security-proofs/obligations.md → expect 0
      3. grep -c '\\\\begin{theorem}' paper/main.tex → expect 20
    Evidence: docs/security-proofs/obligations.md, paper/main.tex
  ```

  **Commit**: YES
  - Message: `proof: complete missing 20th theorem (T<N> of P<X>)`

 - [x] 21. **Update Paper Claims per Fidelity Classification**

  **What to do**:
  - Read `.sisyphus/evidence/paper-claims.md` (post-T13)
  - For each `overstated` claim: rewrite to match evidence (e.g., "novel verifier" → "trusted-signer authenticator (real-verifier future work)")
  - For each `contradicted` claim: remove or correct
  - For each `untestable from repo`: ensure it is clearly marked as future work / out-of-scope
  - Update `paper/main.tex`, `paper/claims-table.md`, `README.md` accordingly
  - Re-run T13 fidelity check: every claim now `supported` or `untestable from repo`

  **Must NOT do**:
  - Leave any `overstated` or `contradicted` claim untouched
  - Introduce new claims while editing

  **Recommended Agent Profile**: `writing`, skills `[]`

  **Parallelization**: Wave 3; blocks T22; blocked by T13, T17

  **References**: `.sisyphus/evidence/paper-claims.md`, `paper/main.tex`, `README.md`, `paper/claims-table.md`

  **Acceptance Criteria**:
  - [ ] After update, T13 classification re-run shows: 0 overstated, 0 contradicted
  - [ ] All "supported" claims still cite evidence file:line
  - [ ] `pdflatex paper/main.tex` (or `tectonic`/`latexmk`) builds without undefined-reference errors

  **QA Scenarios**:

  ```
  Scenario: Paper claims aligned with evidence
    Steps:
      1. Re-classify each claim row in paper-claims.md against current evidence
      2. Save updated paper-claims-v2.md
      3. grep -cE 'overstated|contradicted' .sisyphus/evidence/paper-claims-v2.md → expect 0
    Evidence: .sisyphus/evidence/paper-claims-v2.md
  ```

  **Commit**: YES
  - Message: `docs(paper): align claims with audit evidence (remove overstated/contradicted)`

 - [x] 22. **Final Severity-Rated Audit Report**

  **What to do**:
  - Synthesize all evidence files into `.sisyphus/evidence/audit-report.md`
  - Sections:
    1. **Executive Summary** (1 page): What was audited, what was found, severity distribution
    2. **Per-Construction Findings** (P1, P2, P3, P4): Final per-axis verdict + severity + remediation status
    3. **Cross-Cutting Findings**: SURROGATE retirement, clippy suppressions, theorem completion
    4. **Paper Fidelity**: Before/after claim classification
    5. **Residual Risk**: What was NOT covered (e.g., side channels, parameter selection, deployment)
    6. **Honesty Statement**: Reframe of prior "all APPROVE" verdict — what was supported, what was not, what is now corrected
  - Cite every claim with evidence file:line

  **Must NOT do**:
  - Make claims about reviewer motive/honesty
  - Omit residual risk section
  - Inflate severity beyond evidence

  **Recommended Agent Profile**: `writing`, skills `[]`

  **Parallelization**: Wave 4; blocks F1–F4; blocked by T9–T21

  **References**: All `.sisyphus/evidence/audit-*` files

  **Acceptance Criteria**:
  - [ ] `.sisyphus/evidence/audit-report.md` exists with all 6 sections
  - [ ] Per-construction section has all P1–P4 with final verdicts
  - [ ] Every finding cites evidence file
  - [ ] Residual risk section non-empty

  **QA Scenarios**:

  ```
  Scenario: Audit report has all 6 required sections
    Tool: Bash (grep)
    Steps:
      1. test -s .sisyphus/evidence/audit-report.md
      2. grep -cE '^## (Executive Summary|Per-Construction Findings|Cross-Cutting Findings|Paper Fidelity|Residual Risk|Honesty Statement)' .sisyphus/evidence/audit-report.md
      3. assert count == 6
    Expected Result: all 6 H2 section headers present
    Evidence: .sisyphus/evidence/audit-report.md

  Scenario: Per-construction section covers P1–P4
    Tool: Bash (grep)
    Steps:
      1. awk '/^## Per-Construction Findings/,/^## /' .sisyphus/evidence/audit-report.md > /tmp/perc.txt
      2. grep -cE '^### P[1-4]\b' /tmp/perc.txt
      3. assert count == 4
    Expected Result: P1, P2, P3, P4 all have subsections
    Evidence: .sisyphus/evidence/audit-report.md

  Scenario: Residual Risk section is non-empty
    Tool: Bash (awk+wc)
    Steps:
      1. awk '/^## Residual Risk/,/^## /' .sisyphus/evidence/audit-report.md | sed '1d;$d' | grep -cE '\S'
      2. assert count >= 3 (at least three lines of substantive content)
    Expected Result: residual risk section contains substantive content
    Evidence: .sisyphus/evidence/audit-report.md

  Scenario: Findings cite evidence files
    Tool: Bash (grep)
    Steps:
      1. grep -cE '\.sisyphus/evidence/[A-Za-z0-9_./-]+\.md' .sisyphus/evidence/audit-report.md
      2. assert count >= 8 (at least 2 citations per construction)
    Expected Result: report cross-references upstream evidence files
    Evidence: .sisyphus/evidence/audit-report.md
  ```

  **Commit**: YES
  - Message: `docs(audit): final severity-rated audit report`

- [ ] 23. **Update Obligations, Claims-Table, and Gates**

  **What to do**:
  - Update `docs/security-proofs/obligations.md` to reflect final theorem state (all 20 PROVED-WITH-CITATION)
  - Update `paper/claims-table.md` to reflect updated claims (post-T21)
  - Strengthen gate scripts:
    - `surrogate-retirement-check.py`: invert to PASS only on zero SURROGATE markers
    - Add new gate: `cargo clippy --all-targets --all-features -- -D warnings` (no suppressions tolerance)
    - Add new gate: paper-claim fidelity script (`scripts/audit-paper-claims.py`) that checks `paper-claims.md` has zero overstated/contradicted entries
  - Run all gates: `just phase1-gate && just phase2-gate && just phase3-gate`

  **Recommended Agent Profile**: `unspecified-high`, skills `[]`

  **Parallelization**: Wave 4; blocks F1–F4; blocked by T22

  **References**: `docs/security-proofs/obligations.md`, `paper/claims-table.md`, `justfile`, `scripts/`, `surrogate-retirement-check.py`

  **Acceptance Criteria**:
  - [ ] All 3 phase gates pass
  - [ ] `surrogate-retirement-check.py` PASSes with inverted logic (zero markers)
  - [ ] New paper-claim gate exists and passes
  - [ ] `cargo clippy --all-targets --all-features -- -D warnings` exits 0 across workspace

  **QA Scenarios**:

  ```
  Scenario: All gates pass with strengthened checks
    Steps:
      1. just phase1-gate > .sisyphus/evidence/final-gates/phase1.log 2>&1; assert exit 0
      2. just phase2-gate > .sisyphus/evidence/final-gates/phase2.log 2>&1; assert exit 0
      3. just phase3-gate > .sisyphus/evidence/final-gates/phase3.log 2>&1; assert exit 0
      4. cargo clippy --all-targets --all-features -- -D warnings > .sisyphus/evidence/final-gates/clippy.log 2>&1; assert exit 0
    Evidence: .sisyphus/evidence/final-gates/
  ```

  **Commit**: YES
  - Message: `chore(gates): strengthen audit gates (no suppressions, claim fidelity)`

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.
>
> **Do NOT auto-proceed after verification. Wait for user's explicit approval before marking work complete.**

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read this plan end-to-end. For each "Must Have": verify deliverable exists (read evidence file, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Verify all evidence files exist in `.sisyphus/evidence/`. Cross-check every TODO acceptance criterion against actual artifacts.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `just phase1-gate`, `just phase2-gate`, `just phase3-gate`, `cargo clippy --all-targets -- -D warnings`, `forge test --root contracts`. Review every changed file for: any new `#[allow(clippy::...)]`, `as any`/`@ts-ignore`, empty catches, commented-out code, AI slop (over-abstraction, generic names, excessive comments).
  Output: `Gates [N/3 pass] | Clippy [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [ ] F3. **Real Manual QA** — `unspecified-high`
  From clean state, execute EVERY adversarial test added in Wave 3 (T15, T16) plus the P3 vacuity test (T1). Re-run all canonical Noir+BB flows for affected circuits. Verify each evidence file in `.sisyphus/evidence/audit-*` is non-empty and parseable. Save outputs to `.sisyphus/evidence/final-qa/`.
  Output: `Adversarial Tests [N/N pass] | Evidence Files [N/N valid] | BB Verify [N/N] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff (`git log/diff`). Verify 1:1 — everything in spec was built (no missing), nothing beyond spec was built (no creep). Check "Must NOT Have" compliance. Detect cross-task contamination. Verify per-axis verdicts (Impl × Proof × Test) are present for every P1–P4 row in `audit-matrix.md` (no scalar collapse).
  Output: `Tasks [N/N compliant] | Per-Axis [N/4 constructions] | Contamination [CLEAN/N issues] | VERDICT`

---

## Commit Strategy

- **Investigation commits** (Wave 1–2): `audit(<scope>): <evidence file>` — one commit per evidence artifact
- **Remediation commits** (Wave 3): `fix(<scope>): <what>` or `test(<scope>): add adversarial test for <claim>`
- **Synthesis commits** (Wave 4): `docs(audit): final report and updated obligations`
- Pre-commit gate: relevant `just phase{1,2,3}-gate` for the changed area

---

## Success Criteria

### Verification Commands

```bash
# All gates pass without suppressions
just phase1-gate && just phase2-gate && just phase3-gate

# Clippy strict (no allows)
cargo clippy --all-targets --all-features -- -D warnings

# Adversarial test suite
cargo test -p pvthfhe-fhe --test lattice_nizk_adversarial
cargo test -p pvthfhe-aggregator --test folding_tamper
forge test --root contracts -vv

# Evidence artifacts present and non-empty
test -s .sisyphus/evidence/audit-matrix.md
test -s .sisyphus/evidence/audit-report.md
test -s .sisyphus/evidence/theorem-inventory.md
test -s .sisyphus/evidence/paper-claims.md
test -s .sisyphus/evidence/test-classification.md
test -s .sisyphus/evidence/cast-audit.md
test -s .sisyphus/evidence/surrogate-reachability.md
```

### Final Checklist

- [ ] Audit matrix has per-axis (Impl × Proof × Test) verdict for all 4 constructions
- [ ] All 20 theorems cited or explicitly gap-marked
- [ ] All 5 SURROGATE files retired or proved benign-dead
- [ ] All `as` casts in suppressed files documented as safe or fixed
- [ ] P3 has real verifier OR paper explicitly discloses trusted-signer model
- [ ] Every theorem claim has at least one falsification test
- [ ] Paper has zero "overstated" or "contradicted" claims
- [ ] All gates pass without `#[allow]` suppressions
