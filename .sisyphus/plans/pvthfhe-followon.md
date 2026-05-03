# PVTHFHE Follow-On — Solving Open Problems P1–P4

## TL;DR

> **Quick Summary**: Replace the four surrogates remaining in the completed `pvt-fhe-scaling.md` plan with sound, novel cryptographic constructions, sequenced strictly **P4 → P1 → P2 → P3**, culminating in a single unified publication-grade paper targeting Crypto/Eurocrypt 2027 or CCS 2026.
>
> **Deliverables**:
> - Real Hermine-style PVSS keygen replacing simulated DKG (P4)
> - Sound lattice NIZK for decryption-share well-formedness, noise bounds, PK consistency (P1)
> - Novel folding scheme for RLWE-with-noise replacing SHA256 hash-chain aggregation (P2)
> - Succinct on-chain verifier replacing surrogate `HonkVerifier.sol` (P3)
> - Single unified paper + reproducible research artifact + extended technical report
>
> **Estimated Effort**: XL (9–18 months calendar, unbounded by directive)
> **Parallel Execution**: Sequential between problems; heavy parallelism within each problem's phases (5–7 tasks per wave)
> **Critical Path**: Phase 0 Governance → P4 Research/Design/Impl → P1 R/D/I → P2 R/D/I → P3 R/D/I → Phase E Paper → Final Verification

---

## Context

### Original Request
"Develop a follow-on plan from here for the research, design and then implementation of the solutions to these four problems that have been raised. Don't let Noir be a blocker. Don't be afraid of novelty."

### Interview Summary
**Key Decisions Confirmed**:
- Sequencing: STRICTLY SEQUENTIAL P4 → P1 → P2 → P3
- Target: Publication-grade research artifact, single unified paper (Crypto/Eurocrypt 2027 or CCS 2026)
- Proving stack: Anything goes per-problem (Halo2/KZG, Plonky3, SP1, RISC0, Jolt, Nexus, Boojum, Binius, custom lattice circuits, Rust-in-zkVM fallback). Multi-proof composition allowed. Noir explicitly NOT a blocker.
- Novelty: UNRESTRICTED, AGGRESSIVE BETS. Invent new primitives if literature insufficient.
- Effort: UNBOUNDED. Quality over speed.
- Surrogates: Keep as regression baseline; replace one-by-one. CI green throughout. Adapters, not surrogate-shaped APIs.
- Adversary model & FHE parameters: Defer concrete choice to Research/Design phase per problem.

**Defaults Applied** (override at any time):
- Novelty bar: theorem-level novelty sufficient for top-venue submission
- Review model: in-house primary, external cryptographer review at Design exit (advisory, non-blocking unless catastrophic)
- Security-proof obligation before implementation: theorem statements + proof skeleton with reduction outline; full proof concurrent with implementation
- Acceptable proof models: ROM baseline, QROM where feasible, static corruption baseline with adaptive as stretch goal, knowledge-soundness for NIZKs
- Bounded downstream reconnaissance: ALLOWED (look-ahead memos only; no design or implementation work)
- Negative result / narrowed claim: ACCEPTABLE with formal pivot procedure
- Constraint priority on conflict: security ≥ scale ≥ verifier-cost (with documented downgrade paths)
- Unified paper: PRIMARY path, with formal split-paper decision at end of P2 Design
- Shadow writing track: ENABLED from day one (claims table, bib, figure scripts grow continuously)
- Formal verification scope: selective component-level (serialization codecs, public-input encodings); no full mechanization
- Surrogate interface preservation: NO. Adapters only. Final design defines its own semantic interfaces.
- Trusted setup: universal/transparent setup ACCEPTABLE; one-time MPC ceremony ACCEPTABLE; per-protocol CRS DISCOURAGED.
- Authority on disagreement: project lead (user) has final call.

### Research Findings (from prior plan)
- ePrint 2024/1285 (PV Threshold BFV) underpins P1
- ePrint 2025/247 (LatticeFold+) for P2 — currently over commitments-to-small-witnesses; adapting to RLWE-with-noise is open research
- ePrint 2024/2099 (MicroNova) for P3
- ePrint 2025/901 (Hermine PVSS) for P4
- Existing surrogates: `circuits/decrypt_share/`, `circuits/aggregator_final/`, `contracts/src/generated/HonkVerifier.sol`, `crates/pvthfhe-aggregator/src/keygen/protocol.rs`, `crates/pvthfhe-fhe/src/fhers.rs`

### Metis Review (governance gaps addressed)
- Added Phase 0 governance preamble (novelty review cadence, reviewer model, theorem obligations, pivot policy, publication strategy)
- Per-problem **Problem Charter** required (goals, non-goals, theorem obligations, success metrics, downstream outputs)
- Per-problem **Downstream Contract Bundle** required at gate exit (assumptions, interface spec, parameter schema, transcript/public-input schema, encoding commitments, unresolved-risk list)
- Each phase has **3 gates**: Research Gate (RG), Design Gate (DG), Implementation Gate (IG)
- Primary + fallback construction must be frozen at each Research exit
- Unified-paper-vs-split decision point: end of P2 Design
- Shadow writing track starts in Phase 0
- Adapters mandatory; no surrogate-shaped APIs leak into final design

---

## Work Objectives

### Core Objective
Replace P1–P4 surrogates with sound constructions backed by formal security proofs and a unified publication-grade paper. Each problem must produce theorem-level novelty (or rigorously argued negative result) verifiable by external cryptographer review.

### Concrete Deliverables
- `crates/pvthfhe-aggregator/src/keygen/protocol.rs`: real Hermine-derived PVSS DKG (no simulation)
- `crates/pvthfhe-keygen/`: new crate housing protocol primitives if needed (Phase A Design)
- New circuits/prover crates replacing `circuits/decrypt_share/` (P1 stack TBD)
- New folding-prover crate replacing `circuits/aggregator_final/` (P2 stack TBD)
- New on-chain verifier replacing `contracts/src/generated/HonkVerifier.sol` (P3 stack TBD)
- `paper/`: unified paper draft + bib + figure scripts + claims table
- `.sisyphus/research/`: per-problem research artifacts (lit matrix, novelty memo, threat model, theorem inventory, candidate scorecard, primary+fallback freeze, reviewer memos)
- `.sisyphus/design/`: per-problem design artifacts (frozen interfaces, stack decision matrix, theorem statements, proof skeleton, benchmark plan, migration plan)
- `.sisyphus/evidence/`: per-task evidence (test runs, benchmarks, screenshots, proof artifacts)
- `bench/`: extended benchmarks at n=128, n=512, n=1024 across all four real constructions
- `docs/security-proofs/`: full security proofs per problem, peer-reviewable
- `REPRODUCING.md`: pinned versions for all new toolchain additions
- `just` gate targets: `p4-{research,design,impl}-gate`, `p1-{research,design,impl}-gate`, `p2-{research,design,impl}-gate`, `p3-{research,design,impl}-gate`, `paper-gate`, `final-verification-gate`

### Definition of Done
- [ ] All four surrogates removed from production paths; CI references real constructions
- [ ] All security theorems stated, proven, externally reviewed
- [ ] Unified paper draft passes internal review and at least one external cryptographer review
- [ ] Artifact appendix reproducible from clean checkout via single command
- [ ] Final Verification Wave (F1–F5) APPROVES with zero blocking issues
- [ ] User explicitly oks completion

### Must Have
- Real Hermine-style PVSS DKG with public verifiability (P4)
- Sound lattice NIZK with knowledge-soundness proof (P1)
- Real folding scheme over RLWE with noise-bound preservation theorem (P2)
- Succinct on-chain verifier with O(polylog n) verification cost claim, instantiated and benchmarked (P3)
- Per-problem downstream contract bundle published before next problem starts
- Primary + fallback construction frozen at each Research Gate
- Shadow writing track maintained continuously from Phase 0
- External cryptographer review at each Design Gate (advisory)
- Adapter layer keeping CI green during transition; surrogates preserved as regression baseline until each replacement passes its Implementation Gate

### Must NOT Have (Guardrails)
- Replacing the underlying FHE scheme (continue with fhe.rs / Poulpy choice from prior plan)
- Changing threshold/adversary model beyond what each problem's Charter justifies
- Building general-purpose zkVM or prover tooling beyond what selected constructions require
- Building production DKG/networking infrastructure beyond what the artifact needs
- Performance optimization beyond paper's claim surface
- Implementing more than one stack per problem after Research Gate selects primary+fallback
- Turning P3 into a general-purpose on-chain verifier framework
- Letting surrogate API shapes define final semantic interfaces
- Starting downstream implementation/design before upstream verification gate passes
- Treating "promising idea," "draft proof," or "tests pass locally" as gate completion
- Hidden proof debt in prose or TODOs (proof obligations must be tracked in `docs/security-proofs/obligations.md`)
- Per-protocol trusted setups (universal/transparent or one-time MPC only)
- Skipping shadow writing track until Phase E

---

## Verification Strategy (MANDATORY)

> **MIXED-EXECUTION GATE MODEL** — gate criteria split into TWO categories, both REQUIRED for gate pass:
>
> **(A) Agent-Executable Criteria**: schema validators, build/test/bench commands, file-presence checks, regression baselines. These run via `just <gate>` and exit 0/non-zero.
>
> **(B) Human-Dependent Criteria** (Human-Dependent Gates Registry below): external cryptographer or program-lead sign-off captured as a structured reviewer memo at `.sisyphus/reviews/{external|internal}-{name}-{topic}.md` with a verdict line `VERDICT: APPROVE|REJECT|REQUEST_CHANGES`. Gate scripts MUST grep for `VERDICT: APPROVE` in the required memo file(s) and fail if missing or non-APPROVE. The agent does NOT fabricate human sign-offs; it BLOCKS until the memo file exists with the required verdict.
>
> **Human-Dependent Gates Registry** (these gates require an external human sign-off captured as a memo file before the gate script will pass): A.D.4 (DG-P4), A.I.6 (IG-P4 + P4→P1 bundle), B.R.1, B.R.2, B.R.3, B.R.5 (RG-P1), B.D.3 (proof skeletons external review), B.D.4 (DG-P1), B.I.4 (full-proofs external review), B.I.6 (IG-P1 + P1→P2 bundle), C.R.5 (RG-P2), C.D.3, C.D.5 (paper-strategy decision signed by program lead + advisor), C.I.4, C.I.6 (IG-P2 + P2→P3 bundle), D.R.5 (RG-P3), D.D.3, D.D.4 (DG-P3), D.I.4, D.I.6 (IG-P3), E.5 (≥3 internal reviewer memos), E.6 (≥1 external cryptographer memo), E.7 (paper-gate), Final Verification Wave user-okay step.
>
> **Operationally**: when an agent reaches a human-dependent step it (i) prepares the artifact (memo template stub, draft for advisor), (ii) records a `WAITING_FOR_HUMAN_REVIEW` marker in the relevant evidence directory, (iii) ends its turn. The orchestrator surfaces the wait to the program lead. The next agent run resumes once the memo lands with `VERDICT: APPROVE`. This is by design and is NOT a contradiction with task-level QA scenarios — those scenarios verify ARTIFACT presence and validity, not human approval.

### Test Decision
- **Infrastructure exists**: YES (Rust+Cargo, Foundry, Noir/BB, fhe.rs adapters, custom test harnesses from prior plan)
- **Automated tests**: YES (TDD strict — RED test before every implementation change, per AGENTS.md)
- **New stacks**: each Design Gate must specify exact test framework for chosen stack (e.g., Halo2 dev-mode, Plonky3 verifier tests, SP1 mock prover, RISC0 dev mode, Foundry forge for new verifier)
- **Each task** follows: RED (failing test) → GREEN (minimal impl) → REFACTOR

### QA Policy
Every task includes agent-executed QA scenarios. Evidence saved to `.sisyphus/evidence/task-{id}-{slug}.{ext}`.

- **Cryptographic library code**: `cargo test -p <crate>`, property-based tests via `proptest`, KAT vectors where applicable
- **Circuits / provers**: dev-mode constraint satisfaction tests, end-to-end prove+verify, malicious-witness rejection tests
- **On-chain verifier**: `forge test --root contracts`, gas snapshots, fuzz tests
- **Benchmarks**: `cargo bench` + custom scripts in `bench/`, output committed to `.sisyphus/evidence/benchmarks/`
- **Proofs (mathematical)**: peer-reviewable LaTeX + reviewer memos in `.sisyphus/reviews/`
- **Reproducibility**: `just reproduce-bench`, `just paper-build`, `just final-verification-gate`

### Per-Problem Gate Structure
Each problem (P4, P1, P2, P3) has THREE gates:
- **Research Gate (RG)**: prior-art matrix ✓, novelty memo ✓, threat model ✓, theorem inventory ✓, candidate scorecard ✓, primary+fallback freeze ✓, feasibility evidence ✓, reviewer memo ✓
- **Design Gate (DG)**: frozen interfaces ✓, stack decision memo ✓, theorem statements ✓, proof skeleton (with unresolved-lemma list) ✓, benchmark plan ✓, migration/adapter plan ✓, exact impl test commands ✓, reviewer memo ✓, **(P2 only)** unified-paper-vs-split decision ✓
- **Implementation Gate (IG)**: code+tests+benchmarks pass ✓, surrogate baseline regression green via adapter ✓, full proof updated in `docs/security-proofs/` ✓, parameter tables reproduced ✓, downstream contract bundle published ✓, reviewer memo ✓

---

## Execution Strategy

### Strict Sequential Phases (between problems)
```
Phase 0 (Governance — must complete first)
  ↓
Phase A: P4 (PVSS Keygen) — Research → Design → Impl → G4
  ↓
Phase B: P1 (Lattice NIZK) — Research → Design → Impl → G1
  ↓
Phase C: P2 (LatticeFold+ over RLWE) — Research → Design → Impl → G2
                                       └ Unified-paper decision at end of Design
  ↓
Phase D: P3 (On-chain encoding) — Research → Design → Impl → G3
  ↓
Phase E: Unified Paper + Artifact
  ↓
Final Verification Wave (F1–F5 in parallel) → user okay
```

### Parallel Execution Within Each Phase
Within each Research / Design / Implementation wave: 5–7 parallel tasks. Each problem's full lifecycle: ~16–18 tasks.

### Bounded Look-Ahead Reconnaissance
Allowed at end of each problem's Design phase: produce a "downstream interface preview" memo (1–2 pages) so the next problem doesn't surprise-block on incompatible formats. **No** design or implementation work for downstream problems before their phase begins.

### Critical Path
Phase 0 → P4 IG → P1 IG → P2 DG (unified-paper decision) → P2 IG → P3 IG → Phase E → Final Verification → user okay

---

## TODOs

### Phase 0 — Program Governance & Shadow Writing Scaffold

- [x] 0.1. Write program governance preamble document

  **What to do**:
  - Create `docs/governance/program-charter.md` documenting: novelty review cadence (per Research/Design Gate), reviewer model (in-house primary + external advisory), theorem-proof obligation (skeleton before impl, full proof concurrent), pivot/kill criteria (impossibility, infeasible parameters, reviewer rejection, novelty preemption), publication strategy (unified-paper primary; split-paper decision at end of P2 Design), constraint-priority ladder (security ≥ scale ≥ verifier-cost), authority-on-disagreement (project lead).
  - Create `docs/governance/problem-charter-template.md` defining required fields: Goal / Non-Goals / Required Theorems / Allowed Assumptions / Success Metrics / Downstream Outputs.
  - Create `docs/governance/downstream-contract-bundle-template.md`: assumptions, interface spec, parameter schema, transcript/public-input schema, encoding commitments, unresolved-risk list.

  **Must NOT do**: Define concrete cryptographic constructions here — this is policy only.

  **Recommended Agent Profile**:
  - **Category**: `writing` — Reason: documentation-only governance artifacts.
  - **Skills**: [] — None needed; clear writing task.

  **Parallelization**:
  - **Can Run In Parallel**: YES (with 0.2–0.5)
  - **Parallel Group**: Wave 0 (with 0.2, 0.3, 0.4, 0.5)
  - **Blocks**: All Phase A–E tasks
  - **Blocked By**: None

  **References**:
  - Pattern: `.sisyphus/plans/pvt-fhe-scaling.md` — prior plan structure
  - Pattern: `AGENTS.md` — existing repo conventions
  - External: Metis review output (this session, ses_215754901ffemXT9KPVmztYwjd) — governance directives

  **Acceptance Criteria**:
  - [ ] `docs/governance/program-charter.md` exists with all required sections
  - [ ] Both template files exist and validate against test fixtures in `.sisyphus/evidence/governance/`
  - [ ] `just phase0-gate` returns success

  **QA Scenarios**:
  ```
  Scenario: Governance documents render and parse
    Tool: Bash
    Steps:
      1. Run: `markdownlint docs/governance/`
      2. Run: `grep -E "^## (Goal|Non-Goals|Required Theorems|Allowed Assumptions|Success Metrics|Downstream Outputs)" docs/governance/problem-charter-template.md | wc -l`
    Expected: lint clean; grep returns 6
    Evidence: .sisyphus/evidence/task-0.1-governance-render.log
  ```

  **Commit**: YES — `gov: add program charter and templates`

- [x] 0.2. Scaffold shadow writing track (paper repo)

  **What to do**:
  - Create `paper/` directory: `main.tex`, `bib.bib`, `claims-table.md`, `figures/` directory with placeholder generators, `Makefile` or `just paper-build` target.
  - Define paper outline: Abstract / Intro / Related Work / Preliminaries / P4 (PVSS) / P1 (Lattice NIZK) / P2 (Folding) / P3 (On-chain) / Security / Implementation & Evaluation / Discussion / Conclusion.
  - Initialize `claims-table.md` with stub rows (claims will be added/frozen as each problem completes).

  **Must NOT do**: Write real paper content yet — Phase 0 only scaffolds the track.

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**: Wave 0; parallel with 0.1, 0.3, 0.4, 0.5; blocked by none.

  **References**:
  - Pattern: top-venue submission templates (Springer LNCS or ACM acmart)

  **Acceptance Criteria**:
  - [ ] `paper/main.tex` builds via `just paper-build` producing `paper/main.pdf` (skeleton)
  - [ ] `paper/claims-table.md` exists with stub rows for each P#

  **QA Scenarios**:
  ```
  Scenario: Paper skeleton builds
    Tool: Bash
    Steps:
      1. Run: `just paper-build`
      2. Verify: `paper/main.pdf` exists and ≥1 page
    Expected: PDF generated successfully
    Evidence: .sisyphus/evidence/task-0.2-paper-build.log + paper/main.pdf
  ```

  **Commit**: YES — `paper: scaffold shadow writing track`

- [x] 0.3. Scaffold proof-obligation tracker

  **What to do**:
  - Create `docs/security-proofs/obligations.md` — registry of all theorem statements + status (stated/skeleton/proven/reviewed) with cross-references to per-problem theorem inventories.
  - Create `docs/security-proofs/README.md` — guidelines for proof writing (notation, model, reduction style).

  **Must NOT do**: State theorems before they're identified in Research phase.

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**: Wave 0; blocked by none.

  **References**:
  - Pattern: standard cryptographic proof-writing conventions (BR93, UC, real/ideal)

  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/obligations.md` exists with empty status table
  - [ ] `docs/security-proofs/README.md` defines notation conventions

  **QA Scenarios**:
  ```
  Scenario: Obligation tracker schema valid
    Tool: Bash
    Steps:
      1. Run: `python .sisyphus/scripts/validate-obligations-schema.py docs/security-proofs/obligations.md`
    Expected: schema valid, status table empty
    Evidence: .sisyphus/evidence/task-0.3-obligations-schema.log
  ```

  **Commit**: YES — `gov: scaffold proof obligation tracker`

- [x] 0.4. Add `just` gate targets for all 12 problem gates + paper gate + final gate

  **What to do**:
  - Update root `justfile` with: `phase0-gate`, `p4-research-gate`, `p4-design-gate`, `p4-impl-gate`, `p1-research-gate`, `p1-design-gate`, `p1-impl-gate`, `p2-research-gate`, `p2-design-gate`, `p2-impl-gate`, `p3-research-gate`, `p3-design-gate`, `p3-impl-gate`, `paper-gate`, `final-verification-gate`.
  - Each gate target invokes a `.sisyphus/scripts/{gate-name}.py` that checks required artifacts exist and validates against schema.
  - Initial implementation: scripts return success-with-warning if artifacts missing; warnings become errors as each phase completes.

  **Must NOT do**: Implement actual gate validation logic for downstream phases now — only stubs that fail loud when artifacts are required.

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**: Wave 0; blocked by 0.1 (templates needed).

  **References**:
  - Pattern: `.sisyphus/scripts/phase{1,2,3}-gate.py` from prior plan

  **Acceptance Criteria**:
  - [ ] `just --list` shows all 15 gate targets
  - [ ] All 15 gate scripts exist in `.sisyphus/scripts/`
  - [ ] `just phase0-gate` passes after 0.1, 0.2, 0.3 complete

  **QA Scenarios**:
  ```
  Scenario: All gate targets registered
    Tool: Bash
    Steps:
      1. Run: `just --list | grep -E "(p[0-4]-(research|design|impl)-gate|paper-gate|final-verification-gate|phase0-gate)" | wc -l`
    Expected: 15
    Evidence: .sisyphus/evidence/task-0.4-gates-list.log
  ```

  **Commit**: YES — `gov: register all phase/problem gate targets`

- [x] 0.5. Establish external reviewer engagement plan

  **What to do**:
  - Create `docs/governance/reviewer-roster.md` listing target external cryptographers (areas of expertise: lattice NIZKs, FHE, folding schemes, on-chain verification) with engagement status (prospective / contacted / engaged) and review windows (advance scheduling for each Design Gate).
  - Define review-memo template: `docs/governance/reviewer-memo-template.md`.
  - Define reviewer-feedback-disposition workflow: how feedback maps to plan changes; blocking-vs-advisory rules.

  **Must NOT do**: Actually contact reviewers in this task — this is roster + process only. Engagement happens during each Design phase.

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: []

  **Parallelization**: Wave 0; blocked by none.

  **References**:
  - External: Crypto/Eurocrypt/CCS PC composition (public roster pages)

  **Acceptance Criteria**:
  - [ ] `docs/governance/reviewer-roster.md` exists with ≥6 prospective reviewers spanning 4 expertise areas
  - [ ] Reviewer-memo template + disposition workflow documented

  **QA Scenarios**:
  ```
  Scenario: Roster covers all expertise areas
    Tool: Bash
    Steps:
      1. Run: `grep -c "Expertise: lattice NIZK" docs/governance/reviewer-roster.md`
      2. Run: same for "FHE", "folding", "on-chain"
    Expected: each ≥1; total ≥6 reviewers
    Evidence: .sisyphus/evidence/task-0.5-reviewer-roster.log
  ```

  **Commit**: YES — `gov: establish external reviewer engagement plan`

- [x] 0.6. Validator + helper script suite (Phase 0 tooling)

  **What to do**: Ship the COMPLETE set of validator and helper scripts that downstream tasks reference, so every QA scenario in Phases A–E has a runnable target on day one. Create:
  - **Schema validators** (Python, `.sisyphus/scripts/`): `validate-obligations-schema.py` (validates `docs/security-proofs/obligations.md` rows + cross-checks against per-problem `theorem-inventory.md` and `paper/claims-table.md`; accepts `--claims`, `--theorems`, `--inventory`, `--gates`, `--novelty-memos`, `--require-bijection`), `validate-prior-art.py` (validates research prior-art matrices and `paper/bib.bib`; accepts `--bib`, `--max-age-days`, `--eprint-check`), `validate-pins.py` (verifies pinned references inside paper TeX sources and Justfiles; accepts `--paper`, `--required-pins`), `validate-proof-skeletons.py` (verifies `docs/security-proofs/**` files contain required fields; accepts `--dir`, `--require-fields`), `validate-bundle.py` (downstream contract bundle validator and generic structured-bundle validator; accepts `--bundle`, `--required-fields`, `--check {charter-invariants}`, `--charters` (one or more charter files, e.g. `docs/governance/program-charter.md`), `--research-dirs` (per-problem research directory globs), `--target`), `validate-reviewer-memo.py` (verifies reviewer memo files: required `VERDICT: APPROVE|REJECT|REQUEST_CHANGES` line and required sections; accepts `--memo` for single file, `--memos-dir` + `--min-count` for directory globs, `--required-fields` for field list).
  - **Per-problem gate scripts** (Python, `.sisyphus/scripts/`): `phase0-gate.py`, `p{4,1,2,3}-{research,design,impl}-gate.py` (12 scripts), `paper-gate.py`, `final-verification-gate.py`. Each accepts `--check <subcheck>` and emits PASS/FAIL with structured JSON to `.sisyphus/evidence/`.
  - **Operational helpers** (`.sisyphus/scripts/`): `surrogate-retirement-check.py` (audits feature-flag state of all 4 surrogates; supports `--check {api-leakage,on-chain-verifier}` modes with `--reject-pattern`/`--frozen-interfaces`/`--target` flags), `clean-clone-reproduce.sh` (E.4 / F3 artifact reproduction harness), `human-review-wait.py` (creates `WAITING_FOR_HUMAN_REVIEW` markers and grep-checks memo files for the required `VERDICT: APPROVE`), `ai-slop-scan.py` (lints crates/contracts/circuits for AI-slop patterns: excessive comments, over-abstraction, generic identifiers `data|result|item|temp`, `as any`/`unwrap`/`panic!` in non-test, commented-out code, unused imports), `scope-fidelity-check.py` (parses plan task list, maps each task's `What to do` + file references to file ownership, walks `git diff <base>..<head>`, flags unaccounted files and cross-task contamination; accepts `--plan`, `--base-ref`, `--head-ref`, `--output`).
  - **Justfile targets** (root `Justfile`): `phase0-gate`, `p4-research-gate`, `p4-design-gate`, `p4-impl-gate`, `p1-research-gate`, `p1-design-gate`, `p1-impl-gate`, `p2-research-gate`, `p2-design-gate`, `p2-impl-gate`, `p3-research-gate`, `p3-design-gate`, `p3-impl-gate`, `paper-gate`, `final-verification-gate`, `p1-bench`, `p2-bench`, `p3-bench`, `e2e-real`, `artifact-reproduce`. Each target invokes the corresponding script and propagates exit code.
  - **Stub mode**: each script ships with a `--stub` flag that returns PASS for any subcheck whose corresponding artifact has not yet been produced (allowing TDD RED phase to commit before the artifact exists). Stub mode is OFF in CI default; downstream gate runs require `--stub=false`.

  **Must NOT do**: Defer script creation to first-use tasks (Momus blocker — many scripts referenced before any task creates them); ship scripts that only echo PASS without real validation; bake task-specific data into validators (must accept paths/schemas as args).

  **Recommended Agent Profile**: `unspecified-high`. Skills: [].

  **Parallelization**: Wave 0 FINAL; depends on 0.1–0.5 (charters and templates inform schemas). Blocks ALL downstream phases (A.R.* through E.*).

  **References**: `.sisyphus/scripts/` (existing patterns from prior plan), `Justfile` (existing patterns), `docs/governance/*` (templates from 0.1–0.5), Momus rejection blocker #1.

  **Acceptance Criteria**:
  - [ ] All 6 schema validators present and unit-tested (each has ≥3 fixtures: valid, missing-field, malformed).
  - [ ] All 14 gate scripts present, each accepts `--check <subcheck>`, returns 0 on PASS / non-zero on FAIL, emits `.sisyphus/evidence/<gate>-<subcheck>.json`.
  - [ ] All 5 operational helpers present and unit-tested (`surrogate-retirement-check.py`, `clean-clone-reproduce.sh`, `human-review-wait.py`, `ai-slop-scan.py`, `scope-fidelity-check.py`).
  - [ ] All 20 Justfile targets present and invoke the corresponding script.
  - [ ] `python -m pytest .sisyphus/scripts/tests/` passes (new test directory).
  - [ ] `just phase0-gate` exits 0 (validates 0.1–0.5 outputs + this task's own outputs).

  **QA Scenarios**:
  ```
  Scenario: validator suite present and unit-tested
    Tool: Bash
    Steps:
      1. ls .sisyphus/scripts/validate-*.py | wc -l   # expect 6
      2. ls .sisyphus/scripts/p?-{research,design,impl}-gate.py | wc -l   # expect 12
      3. ls .sisyphus/scripts/{phase0,paper,final-verification}-gate.py | wc -l   # expect 3
      4. python -m pytest .sisyphus/scripts/tests/ -v
    Expected: counts match (6, 12, 3); pytest exits 0 with ≥18 passing tests (≥3 per validator).
    Evidence: .sisyphus/evidence/phase0/validator-suite.txt

  Scenario: Justfile targets resolve
    Tool: Bash
    Steps:
      1. for t in phase0-gate p4-research-gate p4-design-gate p4-impl-gate p1-research-gate p1-design-gate p1-impl-gate p2-research-gate p2-design-gate p2-impl-gate p3-research-gate p3-design-gate p3-impl-gate paper-gate final-verification-gate p1-bench p2-bench p3-bench e2e-real artifact-reproduce; do just --show "$t" >/dev/null || echo "MISSING: $t"; done
    Expected: zero MISSING lines; all 20 targets resolvable.
    Evidence: .sisyphus/evidence/phase0/justfile-targets.txt

  Scenario: stub mode works for RED phase
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p4-research-gate.py --check prior-art-matrix --stub
    Expected: exit 0 with PASS (stub) even though artifact not yet produced.
    Evidence: .sisyphus/evidence/phase0/stub-mode.txt
  ```

  **Commit**: YES — `tooling(phase0): validator + gate-script suite + Justfile targets`

---

### Phase A — P4: PVSS Keygen via Hermine

#### Wave A.R — P4 Research

- [x] A.R.1. P4 prior-art matrix

  **What to do**:
  - Compile literature matrix of PVSS / DKG / threshold-key-generation schemes: Pedersen, Feldman, Gennaro et al., GLOW, FROST/FROST2, Hermine (ePrint 2025/901), Groth's PVSS, SCRAPE, ALBATROSS, Dyadic, classDist-PVSS.
  - For each: assumption (DLOG/DDH/lattice), public-verifiability (yes/no), abort-with-blame (yes/no), communication complexity, dealer-freeness, suitability for BFV-key derivation.
  - Save to `.sisyphus/research/p4/prior-art-matrix.md`.

  **Must NOT do**: Pick a winner yet — that's task A.R.5.

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []
  - Reason: literature synthesis, primary expertise area cryptography research

  **Parallelization**: Wave A.R; parallel with A.R.2–A.R.4; blocked by Phase 0 complete.

  **References**:
  - External: ePrint 2025/901 (Hermine), 2017/216 (SCRAPE), 2018/1011 (ALBATROSS)
  - Librarian: launch broad ePrint search for "publicly verifiable secret sharing" 2020–2026

  **Acceptance Criteria**:
  - [ ] Matrix covers ≥10 schemes with ≥6 attribute columns
  - [ ] Hermine row complete with detailed protocol-flow summary
  - [ ] All citations resolvable via DOI or ePrint ID

  **QA Scenarios**:
  ```
  Scenario: Matrix completeness
    Tool: Bash
    Steps:
      1. Run: `python .sisyphus/scripts/validate-prior-art.py .sisyphus/research/p4/prior-art-matrix.md --min-rows 10 --min-cols 6`
    Expected: validation pass
    Evidence: .sisyphus/evidence/task-A.R.1-matrix.log
  ```

  **Commit**: YES — `research(p4): prior-art matrix for PVSS/DKG schemes`

- [x] A.R.2. P4 novelty gap memo

  **What to do**:
  - Write `.sisyphus/research/p4/novelty-gap-memo.md` analyzing what existing schemes lack for our use case (BFV-key derivation, n=1024, abort-with-blame, post-quantum FHE coupling, zero trusted setup beyond universal CRS).
  - Identify novelty opportunities: Hermine adaptation gaps, integration novelty with BFV public-key derivation, public-verifiability optimizations for n=1024.

  **Must NOT do**: Propose constructions — that's A.R.5.

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**: Wave A.R; blocked by A.R.1.

  **References**:
  - Self: `.sisyphus/research/p4/prior-art-matrix.md` (from A.R.1)

  **Acceptance Criteria**:
  - [ ] Memo identifies ≥3 novelty opportunities with rigor argument for each
  - [ ] Each gap cross-references prior-art matrix rows

  **QA Scenarios**:
  ```
  Scenario: Memo cross-references prior art
    Tool: Bash
    Steps:
      1. Run: `grep -c "see prior-art-matrix" .sisyphus/research/p4/novelty-gap-memo.md`
    Expected: ≥3
    Evidence: .sisyphus/evidence/task-A.R.2-novelty.log
  ```

  **Commit**: YES — `research(p4): novelty gap memo`

- [x] A.R.3. P4 threat model + adversary model

  **What to do**:
  - Write `.sisyphus/research/p4/threat-model.md` formalizing: corruption model (static vs adaptive — default static, adaptive as stretch), threshold (t = ⌊n/2⌋+1), public-verifiability (anyone can verify keygen output), abort-with-blame (cheating dealer/participant publicly identified), network model (synchronous/partial-synchronous), simulator/extractor obligations.
  - Compose with FHE threat model (P1 will refine for decryption-share NIZK).

  **Must NOT do**: Specify protocol details.

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**: Wave A.R; parallel with A.R.1, A.R.2, A.R.4.

  **References**:
  - External: Canetti UC framework, Lindell's tutorial on simulation-based proofs
  - Pattern: Hermine's threat model (ePrint 2025/901)

  **Acceptance Criteria**:
  - [ ] Threat model is precise enough for theorem statements
  - [ ] Composition note with downstream P1 threat model

  **QA Scenarios**:
  ```
  Scenario: Threat model has all required sections
    Tool: Bash
    Steps:
      1. Run: `grep -E "^## (Corruption Model|Threshold|Public Verifiability|Abort with Blame|Network|Simulator)" .sisyphus/research/p4/threat-model.md | wc -l`
    Expected: 6
    Evidence: .sisyphus/evidence/task-A.R.3-threat-model.log
  ```

  **Commit**: YES — `research(p4): threat model and adversary model`

- [x] A.R.4. P4 theorem inventory

  **What to do**:
  - Write `.sisyphus/research/p4/theorem-inventory.md` listing required theorems: (T1) Correctness of keygen output, (T2) Secrecy against <t corruptions, (T3) Public verifiability soundness, (T4) Robustness / abort-with-blame, (T5) Composition with BFV-key derivation.
  - Each theorem: informal statement + reduction sketch + dependency on threat model.
  - Register obligations in `docs/security-proofs/obligations.md`.

  **Must NOT do**: Prove anything — that comes during Implementation phase.

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**: Wave A.R; blocked by A.R.3.

  **References**:
  - Self: `.sisyphus/research/p4/threat-model.md`
  - Pattern: `docs/security-proofs/README.md` from task 0.3

  **Acceptance Criteria**:
  - [ ] ≥5 theorems registered with informal statement + reduction sketch
  - [ ] All registered in `docs/security-proofs/obligations.md` with status `stated`

  **QA Scenarios**:
  ```
  Scenario: Obligations registered
    Tool: Bash
    Steps:
      1. Run: `grep -c "P4-T" docs/security-proofs/obligations.md`
    Expected: ≥5
    Evidence: .sisyphus/evidence/task-A.R.4-theorem-inventory.log
  ```

  **Commit**: YES — `research(p4): theorem inventory and obligations`

- [x] A.R.5. P4 candidate scorecard + primary/fallback freeze + Research Gate

  **What to do**:
  - Write `.sisyphus/research/p4/candidate-scorecard.md` evaluating ≥3 candidate constructions against criteria from threat model (correctness, secrecy, PV, abort-with-blame, n=1024 efficiency, integration with BFV).
  - Score with rubric; freeze ONE primary + ONE fallback; document kill criteria for primary.
  - Run `just p4-research-gate` to capture evidence.

  **Must NOT do**: Implement anything.

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []
  - Optional: oracle review at end via task delegation.

  **Parallelization**: Wave A.R; blocked by A.R.1, A.R.2, A.R.3, A.R.4.

  **References**:
  - All prior A.R artifacts

  **Acceptance Criteria**:
  - [ ] ≥3 candidates scored
  - [ ] Primary + fallback frozen with explicit rationale
  - [ ] `just p4-research-gate` returns success
  - [ ] Internal reviewer memo at `.sisyphus/reviews/p4-research-gate-review.md` with VERDICT line

  **QA Scenarios**:
  ```
  Scenario: P4 Research Gate passes
    Tool: Bash
    Steps:
      1. Run: `just p4-research-gate`
      2. Run: `grep "VERDICT: APPROVE" .sisyphus/reviews/p4-research-gate-review.md`
    Expected: gate success; VERDICT APPROVE
    Evidence: .sisyphus/evidence/task-A.R.5-research-gate.log

  Scenario: Gate fails when primary not frozen
    Tool: Bash
    Preconditions: temporarily remove "Primary:" line from scorecard
    Steps:
      1. Run: `just p4-research-gate`
    Expected: gate fails with "primary not frozen" error
    Evidence: .sisyphus/evidence/task-A.R.5-gate-negative.log
  ```

  **Commit**: YES — `research(p4): candidate scorecard, freeze, RG pass`

---

<!-- PHASE_A_DESIGN_IMPL_INSERT -->

#### Wave A.D — P4 Design

- [x] A.D.1. P4 frozen interface spec

  **What to do**: Write `.sisyphus/design/p4/interface-spec.md` defining exact Rust traits + serde formats for: `KeygenSession`, `Share`, `PublicVerificationArtifact`, `BlameProof`, `BFVPublicKey` derivation. Define wire formats. NO surrogate-shaped types.

  **Must NOT do**: Inherit shape from `crates/pvthfhe-aggregator/src/keygen/protocol.rs` surrogate — adapter layer translates.

  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave A.D; parallel with A.D.2–A.D.4; blocked by A.R Gate pass.

  **References**: `.sisyphus/research/p4/candidate-scorecard.md`; surrogate `protocol.rs` (for adapter); `crates/pvthfhe-fhe/src/fhers.rs` BFV API.

  **Acceptance Criteria**: [ ] `cargo check -p pvthfhe-keygen-spec`; [ ] KAT vectors at `.sisyphus/design/p4/kat/`.

  **QA Scenarios**:
  ```
  Scenario: Trait stubs compile
    Tool: Bash
    Steps: 1. `cargo check -p pvthfhe-keygen-spec`
    Expected: compile success
    Evidence: .sisyphus/evidence/task-A.D.1-trait-check.log
  Scenario: KAT vectors round-trip
    Tool: Bash
    Steps: 1. `cargo test -p pvthfhe-keygen-spec --test kat_roundtrip`
    Expected: all KAT pass
    Evidence: .sisyphus/evidence/task-A.D.1-kat.log
  ```

  **Commit**: YES — `design(p4): frozen interface spec`

- [x] A.D.2. P4 stack decision memo

  **What to do**: Write `.sisyphus/design/p4/stack-decision.md` choosing commitment scheme, NIZK for share validity, hash-to-group, Rust crates, proof system if any. Justify against scorecard. Pin versions in `REPRODUCING.md` draft.

  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave A.D; parallel with A.D.1, A.D.3, A.D.4.
  **References**: A.R.5; library docs via librarian.

  **Acceptance Criteria**: [ ] Decision memo explicit; [ ] Versions pinned.

  **QA Scenarios**:
  ```
  Scenario: Pinned versions resolve
    Tool: Bash
    Steps: 1. `python .sisyphus/scripts/validate-pins.py REPRODUCING.md`
    Expected: all pinned versions resolve
    Evidence: .sisyphus/evidence/task-A.D.2-pins.log
  Scenario: Stack decision references scorecard
    Tool: Bash
    Steps: 1. `grep -c "scorecard" .sisyphus/design/p4/stack-decision.md`
    Expected: ≥3
    Evidence: .sisyphus/evidence/task-A.D.2-refs.log
  ```

  **Commit**: YES — `design(p4): stack decision`

- [x] A.D.3. P4 theorem statements + proof skeleton

  **What to do**: Write `docs/security-proofs/p4/` — precise theorem statements (T1–T5) + proof skeletons + unresolved-lemma list. Update `obligations.md` status: stated → skeleton.

  **Must NOT do**: Hide proof debt; every unresolved step listed.

  **Recommended Agent Profile**: `deep` + `oracle` review. Skills: [].
  **Parallelization**: Wave A.D; blocked by A.D.1.
  **References**: A.R.4 inventory; A.D.1 interfaces.

  **Acceptance Criteria**: [ ] All 5 theorems with skeletons; [ ] `obligations.md` updated; [ ] Reviewer memo APPROVE.

  **QA Scenarios**:
  ```
  Scenario: Skeletons complete
    Tool: Bash
    Steps: 1. `python .sisyphus/scripts/validate-proof-skeletons.py docs/security-proofs/p4/ --min-thms 5`
    Expected: validation pass
    Evidence: .sisyphus/evidence/task-A.D.3-skeletons.log
  Scenario: Unresolved lemma list non-hidden
    Tool: Bash
    Steps: 1. `grep -c "Unresolved Lemma" docs/security-proofs/p4/*.md`
    Expected: ≥1 per theorem with open lemmas
    Evidence: .sisyphus/evidence/task-A.D.3-lemmas.log
  ```

  **Commit**: YES — `design(p4): theorem statements + skeletons`

- [x] A.D.4. P4 benchmark + migration plan + Design Gate

  **What to do**: Write `.sisyphus/design/p4/bench-plan.md` (n=128/512/1024 targets, metrics) and `migration-plan.md` (adapter strategy from surrogate `protocol.rs`; CI-green guarantee). External reviewer engagement (advisory). Reviewer memo. Run `just p4-design-gate`.

  **Must NOT do**: Skip external advisory review.

  **Recommended Agent Profile**: `unspecified-high` + external reviewer. Skills: [].
  **Parallelization**: Wave A.D; blocked by A.D.1–A.D.3.
  **References**: prior plan `bench/` patterns; reviewer roster (0.5).

  **Acceptance Criteria**: [ ] Bench plan reproducible; [ ] Migration adapter compiles as stub; [ ] `just p4-design-gate` pass; [ ] Reviewer memo with VERDICT.

  **QA Scenarios**:
  ```
  Scenario: Migration stub compiles
    Tool: Bash
    Steps: 1. `cargo check -p pvthfhe-keygen --features migration-stub`
    Expected: compile success
    Evidence: .sisyphus/evidence/task-A.D.4-stub.log
  Scenario: Design Gate passes
    Tool: Bash
    Steps: 1. `just p4-design-gate`; 2. `grep "VERDICT:" .sisyphus/reviews/p4-design-gate-review.md`
    Expected: gate pass; VERDICT line exists
    Evidence: .sisyphus/evidence/task-A.D.4-design-gate.log
  ```

  **Commit**: YES — `design(p4): bench/migration plan + DG pass`

#### Wave A.I — P4 Implementation

- [x] A.I.1. RED tests for real PVSS protocol

  **What to do**: Per AGENTS.md TDD, write failing tests in `crates/pvthfhe-keygen/tests/protocol_test.rs`: dealer share generation, participant verification, public reconstruction soundness, abort-with-blame triggers. ≥10 tests, all RED.

  **Must NOT do**: Implement protocol in this task.
  **Recommended Agent Profile**: `quick`. Skills: [].
  **Parallelization**: Wave A.I; blocked by A.D Gate.
  **References**: A.D.1, A.D.3.

  **Acceptance Criteria**: [ ] Tests compile; [ ] All FAIL with `unimplemented!()`; [ ] ≥10 tests.

  **QA Scenarios**:
  ```
  Scenario: RED tests fail
    Tool: Bash
    Steps: 1. `cargo test -p pvthfhe-keygen --test protocol_test 2>&1 | grep -cE "FAILED|panicked"`
    Expected: ≥10
    Evidence: .sisyphus/evidence/task-A.I.1-red.log
  Scenario: Tests compile cleanly
    Tool: Bash
    Steps: 1. `cargo test -p pvthfhe-keygen --no-run`
    Expected: success
    Evidence: .sisyphus/evidence/task-A.I.1-compile.log
  ```

  **Commit**: YES — `impl(p4): RED tests`

- [x] A.I.2. GREEN: implement Hermine-style PVSS dealer + participant

  **What to do**: Implement primary construction. Replace simulation in `crates/pvthfhe-aggregator/src/keygen/protocol.rs` via adapter from new `crates/pvthfhe-keygen`. Surrogate stays behind `--features surrogate-baseline`.

  **Must NOT do**: Modify FHE backend; change threshold model.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave A.I; blocked by A.I.1.
  **References**: A.D.1, A.D.2, A.D.3.

  **Acceptance Criteria**: [ ] All A.I.1 RED tests pass; [ ] `cargo test -p pvthfhe-keygen` green; [ ] Surrogate baseline still passes under `--features surrogate-baseline`.

  **QA Scenarios**:
  ```
  Scenario: Real protocol passes RED tests
    Tool: Bash
    Steps: 1. `cargo test -p pvthfhe-keygen --test protocol_test`
    Expected: all PASS
    Evidence: .sisyphus/evidence/task-A.I.2-green.log
  Scenario: Surrogate baseline regression
    Tool: Bash
    Steps: 1. `cargo test --workspace --features surrogate-baseline`
    Expected: all PASS
    Evidence: .sisyphus/evidence/task-A.I.2-surrogate.log
  ```

  **Commit**: YES — `impl(p4): real Hermine-style PVSS`

 - [x] A.I.3. Public verification + adversarial tests

  **What to do**: Implement public-verifier. Add adversarial tests: forged share, replayed share, malicious dealer, colluding-threshold-1 participants, abort-with-blame correctness.

  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave A.I; blocked by A.I.2.
  **References**: A.D.3 (T3, T4); prior `adversarial-suite`.

  **Acceptance Criteria**: [ ] ≥6 adversarial scenarios; [ ] Cheater-ID 100% correct.

  **QA Scenarios**:
  ```
  Scenario: Adversarial suite identifies cheater
    Tool: Bash
    Steps: 1. `cargo test -p pvthfhe-keygen --test adversarial`
    Expected: all pass; correct cheater ID
    Evidence: .sisyphus/evidence/task-A.I.3-adversarial.log
  Scenario: Honest run rejects no one
    Tool: Bash
    Steps: 1. `cargo test -p pvthfhe-keygen --test honest_run`
    Expected: zero blame events
    Evidence: .sisyphus/evidence/task-A.I.3-honest.log
  ```

  **Commit**: YES — `impl(p4): public verification + adversarial`

 - [x] A.I.4. Full security proofs

  **What to do**: Promote skeletons in `docs/security-proofs/p4/` to full proofs. Resolve all lemmas. Update `obligations.md`: skeleton → proven. Internal + external advisory review.

  **Recommended Agent Profile**: `deep` + `oracle`. Skills: [].
  **Parallelization**: Wave A.I; parallel with A.I.5 once A.I.3 done.
  **References**: A.D.3 skeletons; A.I.2 final implementation.

  **Acceptance Criteria**: [ ] All P4 statuses = proven; [ ] Lemma list empty; [ ] Reviewer memo APPROVE.

  **QA Scenarios**:
  ```
  Scenario: All P4 theorems proven
    Tool: Bash
    Steps: 1. `python .sisyphus/scripts/validate-obligations-schema.py docs/security-proofs/obligations.md --problem P4 --status proven`
    Expected: all P4 entries proven
    Evidence: .sisyphus/evidence/task-A.I.4-proofs.log
  Scenario: Reviewer memo present
    Tool: Bash
    Steps: 1. `grep "VERDICT: APPROVE" .sisyphus/reviews/p4-proofs-review.md`
    Expected: match
    Evidence: .sisyphus/evidence/task-A.I.4-review.log
  ```

  **Commit**: YES — `impl(p4): full security proofs`

 - [x] A.I.5. Benchmarks at n=128, n=512, n=1024 + paper figures

  **What to do**: Run benchmarks per A.D.4. Capture to `.sisyphus/evidence/benchmarks/p4/`. Add `just bench-p4`. Generate paper figures into `paper/figures/p4/`. Update `paper/claims-table.md` row for P4.

  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave A.I; blocked by A.I.2.
  **References**: A.D.4 plan.

  **Acceptance Criteria**: [ ] All 3 sizes run; [ ] Numbers match claims within tolerance; [ ] Figures regenerate.

  **QA Scenarios**:
  ```
  Scenario: Benchmark reproduces
    Tool: Bash
    Steps: 1. `just bench-p4`
    Expected: completes for n∈{128,512,1024}
    Evidence: .sisyphus/evidence/benchmarks/p4/run.log
  Scenario: Figures regenerate from script
    Tool: Bash
    Steps: 1. `just paper-build`; 2. ls paper/figures/p4/*.pdf
    Expected: figures present
    Evidence: .sisyphus/evidence/task-A.I.5-figures.log
  ```

  **Commit**: YES — `impl(p4): benchmarks + paper figures`

 - [x] A.I.6. P4 Implementation Gate + downstream contract bundle for P1

  **What to do**: Run `just p4-impl-gate`. Publish `.sisyphus/contracts/p4-to-p1-bundle.md` (assumptions, public-key format BFV consumes, share format P1 will prove well-formedness over, parameter schema, transcript schema, encoding commitments, unresolved-risk list). Mark P4 row in claims-table "frozen".

  **Must NOT do**: Begin P1 work before bundle published.
  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave A.I; blocked by A.I.1–A.I.5.

  **Acceptance Criteria**: [ ] `just p4-impl-gate` pass; [ ] Bundle has all 7 sections; [ ] Reviewer memo APPROVE; [ ] Claims row frozen.

  **QA Scenarios**:
  ```
  Scenario: IG + bundle published
    Tool: Bash
    Steps: 1. `just p4-impl-gate`; 2. `python .sisyphus/scripts/validate-bundle.py .sisyphus/contracts/p4-to-p1-bundle.md`
    Expected: gate pass; bundle valid (7 sections)
    Evidence: .sisyphus/evidence/task-A.I.6-impl-gate.log
  Scenario: Bundle rejection on missing section
    Tool: Bash
    Preconditions: temporarily remove "Parameter Schema" section
    Steps: 1. `python .sisyphus/scripts/validate-bundle.py .sisyphus/contracts/p4-to-p1-bundle.md`
    Expected: validation fails
    Evidence: .sisyphus/evidence/task-A.I.6-negative.log
  ```

  **Commit**: YES — `impl(p4): IG pass + P4→P1 bundle`

---

### Phase B — P1: Lattice NIZK for Decryption Share Correctness

> **Surrogate to replace**: `circuits/decrypt_share/src/main.nr` (Noir/UltraHonk surrogate that proves a SHA-256 commitment, NOT actual lattice relation). Real construction must prove: "ciphertext c, decryption share d_i, secret share s_i ∈ R_q satisfy d_i = c·s_i + e_i mod q with bounded e_i, AND s_i is the share committed in P4's PVSS commitment." Soundness and ZK in ROM (or QROM if feasible) are MANDATORY claims.
> **Carry forward**: P4→P1 downstream contract bundle (commitment scheme to s_i, public params, threshold structure).
> **Stack freedom**: Halo2/KZG, Plonky3, Binius, Boojum, custom lattice Σ-protocol + Fiat–Shamir, SP1/RISC0/Jolt running Rust lattice prover, or hybrid. Decision deferred to B.D.2.

#### Phase B Research Wave (B.R.*)

 - [x] B.R.1. P1 prior-art matrix

  **What to do**: Survey lattice NIZKs and proofs of knowledge of RLWE/Module-LWE secrets and decryption-share correctness. Required entries: Lyubashevsky Σ-protocols (FS), LANES/LNS19/LNS21, Esgin et al. lattice ZK, Beullens (one-shot lattice ZK), short-secret PoK (Bootle–Lyubashevsky–Seiler), Albrecht–Lai (lattice SNARGs), Lattice Bulletproofs, SLAP, Greyhound, transparent lattice IOPs, and zkVM-as-NIZK (SP1/RISC0/Jolt proving a Rust verifier of the lattice relation), and SNARK-friendly hash-of-RLWE-witness encodings.
  **Must NOT do**: Skip schemes with weaker assumptions; ignore proof-size vs. prover-time vs. verifier-time tradeoffs; conflate proof-of-knowledge with simulation-soundness.
  **Recommended Agent Profile**: `deep`. Skills: [`paperclip`].
  **Parallelization**: Wave B.R; can start immediately after A.I.6 publishes P4→P1 bundle. Blocked by: A.I.6.
  **References**: ePrint 2024/1285, ePrint 2025/247 (LF+ over RLWE), `circuits/decrypt_share/src/main.nr` (surrogate to replace), P4→P1 bundle from `.sisyphus/contracts/p4-to-p1-bundle.md`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p1/prior-art.md` with ≥10 entries; each entry: scheme, assumption (M-SIS/M-LWE/SIS/RingSIS/etc.), prover time, proof size, verifier time, ROM/QROM, post-quantum, recursion-friendly, on-chain feasibility, license.
  - [ ] Comparison table including a "Rust-in-zkVM" row with realistic prover/verifier estimates (cite SP1/RISC0/Jolt benchmarks).
  - [ ] At least 3 candidates marked "viable primary"; at least 2 marked "viable fallback".
  - [ ] Reviewer memo from external advisor with VERDICT line.
  **QA Scenarios**:
  ```
  Scenario: prior-art matrix completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-research-gate.py --check prior-art-matrix
    Expected: exit 0, ≥10 entries, all required columns populated, Rust-in-zkVM row present.
    Evidence: .sisyphus/evidence/p1-research/prior-art-check.txt
  ```
  **Commit**: YES — `research(p1): prior-art matrix for lattice NIZK candidates`

 - [x] B.R.2. P1 novelty gap memo

  **What to do**: Identify what is genuinely missing for our setting: (a) joint proof of decryption-share correctness AND consistency with P4 PVSS commitment under one Fiat–Shamir transcript; (b) batch-amortization across t shares; (c) compatibility with downstream P2 folding; (d) on-chain or recursive verification path (P3). Articulate concretely which novel construction, security argument, or engineering technique is required. Aggressive bets allowed.
  **Must NOT do**: Re-state textbook lattice ZK; defer hard novelty to "future work."
  **Recommended Agent Profile**: `artistry`. Skills: [].
  **Parallelization**: Wave B.R; depends on B.R.1.
  **References**: `.sisyphus/research/p1/prior-art.md`, P4→P1 bundle, P2 surrogate `circuits/aggregator_final/src/main.nr` (downstream consumer).
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p1/novelty-memo.md` with sections: Required Novelty, Aggressive Bets, Risk Register, Pivot Triggers.
  - [ ] At least one "aggressive bet" candidate (e.g., new lattice IOP for share-consistency, or zkVM-with-custom-precompile).
  - [ ] External advisor memo with VERDICT.
  **QA Scenarios**:
  ```
  Scenario: novelty memo schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-research-gate.py --check novelty-memo
    Expected: required sections present; ≥1 aggressive bet documented; pivot triggers concrete (measurable).
    Evidence: .sisyphus/evidence/p1-research/novelty-memo-check.txt
  ```
  **Commit**: YES — `research(p1): novelty gap memo and aggressive-bet candidates`

 - [x] B.R.3. P1 threat model + adversary model

  **What to do**: Lock down: malicious participants up to t-1, rushing adversary, adaptive vs. static corruption, ROM vs. QROM, simulation-soundness vs. plain soundness, knowledge soundness extractor model (rewinding vs. straight-line), composability with P2 folding (does P2 require simulation-extractable proofs?), and concrete FHE parameter exposure (q, ring degree, error distribution) that the proof commits to.
  **Must NOT do**: Allow assumption drift between this and P4/P2; weaken to honest-verifier ZK without justification.
  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave B.R; depends on B.R.1 and P4 charter (Phase 0 + A.I.6).
  **References**: P4 threat model (`.sisyphus/research/p4/threat-model.md`), `docs/governance/problem-charter-template.md`, P4→P1 bundle.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p1/threat-model.md` filling Problem Charter §Threat Model.
  - [ ] Explicit row: simulation-soundness REQUIRED/NOT-REQUIRED with justification tied to P2 needs.
  - [ ] Reviewer memo VERDICT line.
  **QA Scenarios**:
  ```
  Scenario: threat-model schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-research-gate.py --check threat-model
    Expected: required fields all set; consistency check vs. P4 threat model passes.
    Evidence: .sisyphus/evidence/p1-research/threat-model-check.txt
  ```
  **Commit**: YES — `research(p1): threat and adversary model`

- [x] B.R.4. P1 theorem inventory + proof obligations

  **What to do**: Enumerate REQUIRED theorems: (T1) completeness, (T2) (knowledge) soundness in ROM/QROM, (T3) zero-knowledge/HVZK→NIZK via FS, (T4) simulation-extractability if T3-required-by-P2, (T5) batch-soundness if amortizing. For each: assumption, model, statement sketch, expected proof technique, and reduction target. Add to `docs/security-proofs/obligations.md`.
  **Must NOT do**: Defer T2/T3 statements; assume "standard" without writing them.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave B.R; depends on B.R.3.
  **References**: `docs/security-proofs/obligations.md`, B.R.3 threat model.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p1/theorem-inventory.md` with T1–T5 sketches.
  - [ ] `docs/security-proofs/obligations.md` updated with P1 rows.
  - [ ] Oracle review memo with VERDICT.
  **QA Scenarios**:
  ```
  Scenario: theorem inventory tracker update
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-research-gate.py --check theorem-inventory
    Expected: ≥5 theorem rows for P1, all with assumption/model/statement-sketch.
    Evidence: .sisyphus/evidence/p1-research/theorem-inventory-check.txt
  ```
  **Commit**: YES — `research(p1): theorem inventory and proof obligations`

- [x] B.R.5. P1 candidate scorecard + primary/fallback freeze + Research Gate (RG-P1)

  **What to do**: Score viable candidates from B.R.1 against scale (n=1024), verifier cost (downstream P2 consumption), prover memory, FHE-parameter compatibility, novelty cost, and PQ posture. FREEZE primary + at least one fallback. Run `just p1-research-gate`. External advisory review required.
  **Must NOT do**: Pick single candidate without fallback; allow surrogate-shape leakage from `decrypt_share/src/main.nr` into the frozen design.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave B.R FINAL; depends on B.R.1–B.R.4.
  **References**: B.R.1–B.R.4 outputs, `.sisyphus/scripts/p1-research-gate.py`, justfile target `p1-research-gate`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p1/scorecard.md` with weighted scores; primary + fallback declared.
  - [ ] `.sisyphus/research/p1/RG-P1-decision.md` signed by Prometheus + external advisor.
  - [ ] `just p1-research-gate` exits 0.
  - [ ] Reviewer memo with `VERDICT: APPROVE` line.
  **QA Scenarios**:
  ```
  Scenario: research gate full check
    Tool: Bash
    Steps:
      1. just p1-research-gate
    Expected: exit 0; gate report enumerates all 4 prior checks PASS; primary + fallback frozen.
    Evidence: .sisyphus/evidence/p1-research/gate-output.txt
  ```
  **Commit**: YES — `research(p1): RG-P1 passed, primary+fallback frozen`

#### Phase B Design Wave (B.D.*)

- [x] B.D.1. P1 frozen interface spec (NIZK API + statement encoding)

  **What to do**: Define the prover/verifier interface used by the rest of the system. Statement encoding must commit to: ciphertext c, claimed share d_i, public PVSS commitment to s_i (from P4→P1 bundle), and FHE public params. Specify input wire formats, error-bound parameters, public-input layout, and serialization (deterministic, recursion-friendly). Adapter to legacy surrogate behind `surrogate-decrypt-share` Cargo feature.
  **Must NOT do**: Bake Noir-isms into the interface; expose internal lattice gadgetry that locks us into one prover.
  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave B.D; depends on B.R.5. Blocks B.D.2–B.D.4.
  **References**: P4→P1 bundle, `crates/pvthfhe-fhe/src/fhers.rs`, `circuits/decrypt_share/src/main.nr` (legacy surrogate, kept).
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p1/interface-spec.md` with full statement, witness, public-input schemas.
  - [ ] Rust trait sketch in `.sisyphus/design/p1/trait-sketch.rs.md` (markdown excerpt only — no source-code change yet).
  - [ ] Adapter strategy section explicit: surrogate stays behind feature flag; real impl is default.
  **QA Scenarios**:
  ```
  Scenario: interface spec schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-design-gate.py --check interface-spec
    Expected: required fields all present; surrogate-shape contamination check passes (no Noir-specific types in interface).
    Evidence: .sisyphus/evidence/p1-design/interface-check.txt
  ```
  **Commit**: YES — `design(p1): frozen NIZK interface and statement encoding`

- [x] B.D.2. P1 stack decision memo (Halo2 / Plonky3 / custom-lattice-Σ / Rust-in-zkVM / hybrid)

  **What to do**: Pick the implementation stack for primary AND fallback. Quantitative comparison: prover time at n=1024, proof size, verifier time, recursion fit (must compose with P2), PQ posture, license, audit surface. Rust-in-zkVM allowed and explicitly evaluated as fallback. Decision must be reversible at IG via the adapter.
  **Must NOT do**: Pick a stack that Noir's UltraHonk can't recurse into without justifying the recursion path.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave B.D; depends on B.D.1.
  **References**: B.R.5 scorecard, `bench/` baselines, P4 stack memo for consistency.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p1/stack-decision.md` declaring primary + fallback with rationale.
  - [ ] Bench-projection table with ≥3 datapoints (n=128, 512, 1024).
  - [ ] Reviewer memo with VERDICT.
  **QA Scenarios**:
  ```
  Scenario: stack memo schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-design-gate.py --check stack-decision
    Expected: primary + fallback both declared; bench projections present.
    Evidence: .sisyphus/evidence/p1-design/stack-check.txt
  ```
  **Commit**: YES — `design(p1): stack decision (primary + fallback)`

- [x] B.D.3. P1 theorem statements + full proof skeletons

  **What to do**: Write formal statements for T1–T5 from B.R.4 against the chosen stack. Provide proof skeletons with reduction outline (e.g., M-SIS extractor construction for T2, simulator for T3). Skeletons must be detailed enough that an external cryptographer can verify the structure without reading the implementation.
  **Must NOT do**: Hand-wave reductions; leave "standard" steps undefined.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave B.D; depends on B.D.2.
  **References**: B.R.4 inventory, `docs/security-proofs/obligations.md`.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p1/proof-skeletons.md` covering T1–T5.
  - [ ] Each skeleton ≥1 page; reduction target named; tightness loss bounded.
  - [ ] External advisor memo with VERDICT (mandatory at DG-P1).
  **QA Scenarios**:
  ```
  Scenario: proof skeletons completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-design-gate.py --check proof-skeletons
    Expected: all T1–T5 present; advisor VERDICT line found.
    Evidence: .sisyphus/evidence/p1-design/proof-skeletons-check.txt
  ```
  **Commit**: YES — `design(p1): theorem statements and proof skeletons`

- [x] B.D.4. P1 benchmark plan + migration plan + Design Gate (DG-P1)

  **What to do**: Define benchmark matrix (n × FHE params × prover stack), migration plan from surrogate (adapter rollout, feature-flag flip, surrogate retirement schedule), and rollback criteria. Run `just p1-design-gate`.
  **Must NOT do**: Skip rollback criteria; leave surrogate retirement open-ended.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave B.D FINAL; depends on B.D.1–B.D.3.
  **References**: A.D.4 benchmark template, `bench/`, P4→P1 bundle.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p1/bench-plan.md` and `migration-plan.md`.
  - [ ] `just p1-design-gate` exits 0.
  - [ ] External advisor VERDICT: APPROVE.
  **QA Scenarios**:
  ```
  Scenario: design gate full check
    Tool: Bash
    Steps:
      1. just p1-design-gate
    Expected: exit 0; gate report enumerates B.D.1–B.D.3 PASS; advisor APPROVE present.
    Evidence: .sisyphus/evidence/p1-design/gate-output.txt
  ```
  **Commit**: YES — `design(p1): DG-P1 passed`

#### Phase B Implementation Wave (B.I.*)

- [x] B.I.1. RED tests for real lattice NIZK

  **What to do**: Write failing tests that exercise the frozen interface from B.D.1: (a) honest prover → verifier accepts; (b) tampered share → verifier rejects with specific error code; (c) wrong PVSS commitment binding → reject; (d) batch verification correctness; (e) determinism / transcript stability. Tests live in `crates/pvthfhe-fhe/tests/lattice_nizk.rs` (new file). RED phase: real impl absent → tests fail by `unimplemented!()` adapter.
  **Must NOT do**: Test the surrogate; commit GREEN tests; allow tests to pass via surrogate feature flag.
  **Recommended Agent Profile**: `quick`. Skills: [].
  **Parallelization**: Wave B.I; depends on B.D.4.
  **References**: B.D.1 trait sketch, AGENTS.md TDD policy.
  **Acceptance Criteria**:
  - [ ] New test file added; `cargo test -p pvthfhe-fhe lattice_nizk` shows ≥5 failing tests with `unimplemented!`.
  - [ ] No surrogate path activated.
  **QA Scenarios**:
  ```
  Scenario: RED phase confirmed
    Tool: Bash
    Steps:
      1. cargo test -p pvthfhe-fhe --no-default-features --features=real-nizk lattice_nizk 2>&1 | tee evidence.txt
    Expected: ≥5 tests, all FAILED, none passed via surrogate.
    Evidence: .sisyphus/evidence/p1-impl/red-tests.txt
  ```
  **Commit**: YES — `test(p1): RED tests for real lattice NIZK [skip-green]`

- [ ] B.I.2. GREEN: implement chosen primary lattice NIZK + adapter

  **What to do**: Implement primary stack from B.D.2 behind `real-nizk` Cargo feature; replace surrogate IN PLACE per stub protocol. Adapter routes between surrogate (default OFF in CI prod) and real impl. Move RED tests to GREEN. Keep proof artifacts deterministic.
  **Must NOT do**: Delete-and-recreate surrogate file; let real and surrogate paths diverge in interface; weaken interface to make impl easier.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave B.I; depends on B.I.1.
  **References**: B.D.1, B.D.2, B.I.1 tests, AGENTS.md stub protocol.
  **Acceptance Criteria**:
  - [ ] Real impl committed; surrogate file annotated and feature-flagged (not deleted).
  - [ ] `cargo test -p pvthfhe-fhe --features=real-nizk lattice_nizk` PASS.
  - [ ] CI default flips to `real-nizk`; surrogate path remains as regression baseline only.
  **QA Scenarios**:
  ```
  Scenario: GREEN phase confirmed
    Tool: Bash
    Steps:
      1. cargo test -p pvthfhe-fhe --features=real-nizk lattice_nizk
    Expected: all RED tests now PASS; surrogate test still passes under `surrogate-decrypt-share` feature.
    Evidence: .sisyphus/evidence/p1-impl/green-tests.txt
  ```
  **Commit**: YES — `feat(p1): real lattice NIZK primary impl behind real-nizk feature`

- [x] B.I.3. Adversarial tests + simulation-extractability harness

  **What to do**: Add adversarial tests: malformed transcripts, replay across sessions, share-substitution, wrong-q parameters, FS challenge tampering. If T4 (simulation-extractability) was required at B.R.4, add a property-test harness that exercises the extractor on rewinding traces.
  **Must NOT do**: Mock the verifier; rely on `assert!(true)` placeholders.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave B.I; depends on B.I.2.
  **References**: B.R.3 threat model, B.D.3 proof skeletons.
  **Acceptance Criteria**:
  - [ ] ≥8 adversarial test cases pass.
  - [ ] If T4 required: extractor harness runs and confirms extraction on ≥100 simulated rewinds.
  **QA Scenarios**:
  ```
  Scenario: adversarial suite
    Tool: Bash
    Steps:
      1. cargo test -p pvthfhe-fhe --features=real-nizk lattice_nizk_adversarial
    Expected: all PASS; coverage report shows ≥8 distinct attack vectors.
    Evidence: .sisyphus/evidence/p1-impl/adversarial.txt
  ```
  **Commit**: YES — `test(p1): adversarial + simulation-extractability harness`

- [x] B.I.4. Full security proofs (paper-ready)

  **What to do**: Expand B.D.3 skeletons into full proofs in `docs/security-proofs/p1/`. Theorems T1–T5 with complete reductions, parameter constraints, tightness analysis. External advisor review required.
  **Must NOT do**: Cite "by inspection" for non-trivial steps; leave parameter constraints implicit.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave B.I; depends on B.I.2 (real impl informs concrete params).
  **References**: B.D.3 skeletons, B.I.2 impl parameters.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p1/{T1,T2,T3,T4,T5}.md` complete.
  - [ ] External advisor memo VERDICT: APPROVE.
  - [ ] `docs/security-proofs/obligations.md` rows marked PROVED.
  **QA Scenarios**:
  ```
  Scenario: proofs completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p1-impl-gate.py --check proofs
    Expected: all theorems PROVED; advisor APPROVE present.
    Evidence: .sisyphus/evidence/p1-impl/proofs-check.txt
  ```
  **Commit**: YES — `proof(p1): full security proofs T1–T5`

- [x] B.I.5. Benchmarks at n=128, n=512, n=1024 + paper figures

  **What to do**: Run benchmark matrix from B.D.4 on representative hardware. Generate paper-ready figures (TikZ or matplotlib→PDF). Compare against prior-art datapoints from B.R.1.
  **Must NOT do**: Cherry-pick favorable params; omit memory peak.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave B.I; depends on B.I.2.
  **References**: B.D.4 bench plan, `bench/`, A.I.5 bench format for consistency.
  **Acceptance Criteria**:
  - [ ] `bench/p1/results-{128,512,1024}.json` present.
  - [ ] `paper/figures/p1-bench.{pdf,tex}` generated.
  - [ ] Comparison row vs. ≥3 prior-art schemes.
  **QA Scenarios**:
  ```
  Scenario: bench reproduction
    Tool: Bash
    Steps:
      1. just p1-bench
    Expected: exits 0; results-*.json present; figures regenerated deterministically.
    Evidence: .sisyphus/evidence/p1-impl/bench.txt
  ```
  **Commit**: YES — `bench(p1): n=128/512/1024 results and paper figures`

- [x] B.I.6. P1 Implementation Gate (IG-P1) + downstream contract bundle for P2

  **What to do**: Run `just p1-impl-gate`. Publish `.sisyphus/contracts/p1-to-p2-bundle.md` with all 7 sections from the Phase 0 template (frozen API, public params, security caveats, perf envelope, recursion-friendliness for P2 folding, deserializer spec, regression baseline). Surrogate retirement check: surrogate path remains under feature flag, real path is default.
  **Must NOT do**: Pass IG-P1 with surrogate still in default CI; ship a bundle missing recursion details that P2 needs.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave B.I FINAL; depends on B.I.1–B.I.5.
  **References**: Phase 0 contract bundle template, `.sisyphus/contracts/p4-to-p1-bundle.md` for format.
  **Acceptance Criteria**:
  - [ ] `just p1-impl-gate` exits 0.
  - [ ] `.sisyphus/contracts/p1-to-p2-bundle.md` published with all 7 sections.
  - [ ] External advisor VERDICT: APPROVE.
  **QA Scenarios**:
  ```
  Scenario: IG-P1 + bundle
    Tool: Bash
    Steps:
      1. just p1-impl-gate
      2. python .sisyphus/scripts/p1-impl-gate.py --check downstream-bundle
    Expected: both exit 0; bundle present and validated.
    Evidence: .sisyphus/evidence/p1-impl/ig-output.txt
  ```
  **Commit**: YES — `gate(p1): IG-P1 passed, P1→P2 bundle published`


### Phase C — P2: LatticeFold+ over RLWE for Aggregator Folding

> **Surrogate to replace**: `circuits/aggregator_final/src/main.nr` (Noir circuit that hash-chains share commitments via SHA-256 — NOT actual lattice folding). Real construction must implement a folding scheme over RLWE/Module-LWE relations consuming P1 NIZKs as inner statements, producing a single folded statement that P3 can verify on-chain (or recursively).
> **Carry forward**: P1→P2 downstream contract bundle (recursion-friendliness, public-input layout, simulation-extractability if claimed).
> **Stack freedom**: native LatticeFold+ (ePrint 2025/247), Nova/SuperNova-style folding adapted to lattice relations, MicroNova lattice variant, custom IOP-of-folding, or Rust-in-zkVM proving the folding step. Decision deferred to C.D.2.
> **CRITICAL DECISION POINT**: end of C.D — unified-paper-vs-split-paper decision recorded.

#### Phase C Research Wave (C.R.*)

- [x] C.R.1. P2 prior-art matrix

  **What to do**: Survey folding schemes over lattices and RLWE-friendly accumulation. Required entries: Nova, SuperNova, HyperNova, ProtoStar, ProtoGalaxy, LatticeFold (2024), LatticeFold+ (2025/247), Mova, NeutronNova, MicroNova, Origami, lattice IVC constructions, and Rust-in-zkVM IVC (SP1 recursion, RISC0 recursion). Add column "RLWE-native?" and "verifier-cost-on-chain".
  **Must NOT do**: Treat LatticeFold and LatticeFold+ as interchangeable; ignore prover-memory blowup at high arity.
  **Recommended Agent Profile**: `deep`. Skills: [`paperclip`].
  **Parallelization**: Wave C.R; can start immediately after B.I.6 publishes P1→P2 bundle. Blocked by: B.I.6.
  **References**: ePrint 2025/247, ePrint 2024/2099 (MicroNova), `circuits/aggregator_final/src/main.nr` (surrogate to replace), `.sisyphus/contracts/p1-to-p2-bundle.md`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p2/prior-art.md` with ≥8 entries; columns include RLWE-native, verifier-on-chain feasibility, recursion depth tested, license, audit status.
  - [ ] At least 2 candidates marked "viable primary"; at least 2 "viable fallback".
  - [ ] Reviewer memo with VERDICT.
  **QA Scenarios**:
  ```
  Scenario: prior-art matrix completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-research-gate.py --check prior-art-matrix
    Expected: ≥8 entries; required columns populated; Rust-in-zkVM row present.
    Evidence: .sisyphus/evidence/p2-research/prior-art-check.txt
  ```
  **Commit**: YES — `research(p2): prior-art matrix for lattice folding schemes`

- [x] C.R.2. P2 novelty gap memo

  **What to do**: Identify what is missing for our setting: (a) folding over RLWE relations consuming P1's specific NIZK as inner proof; (b) accumulator structure compatible with on-chain (P3) verification; (c) handling FHE-parameter consistency across folded steps; (d) batched share aggregation up to t=⌊n/2⌋+1 with n=1024. Aggressive bets: novel folding-over-NTT, lattice-native accumulator with constant-size verifier, hybrid lattice→Plonk projection.
  **Must NOT do**: Treat folding as a commodity; ignore that LF+ is brand-new and unaudited.
  **Recommended Agent Profile**: `artistry`. Skills: [].
  **Parallelization**: Wave C.R; depends on C.R.1.
  **References**: C.R.1, P1→P2 bundle, P3 surrogate `contracts/src/generated/HonkVerifier.sol`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p2/novelty-memo.md` with Required Novelty, Aggressive Bets, Risk Register, Pivot Triggers.
  - [ ] ≥1 aggressive bet documented.
  - [ ] External advisor VERDICT.
  **QA Scenarios**:
  ```
  Scenario: novelty memo schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-research-gate.py --check novelty-memo
    Expected: required sections present; aggressive bet documented; pivot triggers measurable.
    Evidence: .sisyphus/evidence/p2-research/novelty-memo-check.txt
  ```
  **Commit**: YES — `research(p2): novelty gap memo and aggressive-bet candidates`

- [x] C.R.3. P2 threat model + adversary model

  **What to do**: Define folding-specific threats: malicious prover injecting invalid inner P1 proof, accumulator binding break, FS challenge grinding across folds, soundness amplification analysis (per-fold soundness × depth). Lock down knowledge-soundness model (extractor recursion budget). Reconcile with P1 simulation-extractability (must match).
  **Must NOT do**: Allow assumption drift from P1; treat soundness amplification heuristically.
  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave C.R; depends on C.R.1, P1→P2 bundle.
  **References**: P1 threat model (B.R.3), `.sisyphus/contracts/p1-to-p2-bundle.md`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p2/threat-model.md` complete.
  - [ ] Consistency check vs. P1 threat model PASS.
  - [ ] Reviewer VERDICT.
  **QA Scenarios**:
  ```
  Scenario: threat model schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-research-gate.py --check threat-model
    Expected: required fields set; P1 consistency PASS.
    Evidence: .sisyphus/evidence/p2-research/threat-model-check.txt
  ```
  **Commit**: YES — `research(p2): threat and adversary model`

- [x] C.R.4. P2 theorem inventory + proof obligations

  **What to do**: Enumerate REQUIRED theorems: (T1) folding completeness, (T2) folding knowledge soundness via extraction tree, (T3) ZK preservation (if relevant), (T4) accumulator binding under M-SIS/RingSIS, (T5) compatibility with on-chain verifier (size and op-count bounds). Add to `docs/security-proofs/obligations.md`.
  **Must NOT do**: Defer T2 extraction tree analysis; assume LF+ proofs transfer without re-statement.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave C.R; depends on C.R.3.
  **References**: `docs/security-proofs/obligations.md`, ePrint 2025/247.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p2/theorem-inventory.md` with T1–T5.
  - [ ] Obligations tracker updated.
  - [ ] Oracle review VERDICT.
  **QA Scenarios**:
  ```
  Scenario: theorem inventory tracker update
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-research-gate.py --check theorem-inventory
    Expected: ≥5 theorem rows for P2.
    Evidence: .sisyphus/evidence/p2-research/theorem-inventory-check.txt
  ```
  **Commit**: YES — `research(p2): theorem inventory and proof obligations`

- [x] C.R.5. P2 candidate scorecard + primary/fallback freeze + Research Gate (RG-P2)

  **What to do**: Score candidates against scale (folding depth at t=513, n=1024), prover memory at fold-step, on-chain verifier cost (P3 dependency), recursion-into-zkVM cost (Rust-in-zkVM fallback), novelty cost. Freeze primary + fallback. Run `just p2-research-gate`. External advisor REQUIRED.
  **Must NOT do**: Pick LatticeFold+ as primary without explicit fallback (LF+ is new, may have undiscovered issues).
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave C.R FINAL; depends on C.R.1–C.R.4.
  **References**: C.R.1–C.R.4, justfile target `p2-research-gate`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p2/scorecard.md` with weighted scores; primary + fallback declared.
  - [ ] `.sisyphus/research/p2/RG-P2-decision.md` signed.
  - [ ] `just p2-research-gate` exits 0; advisor APPROVE.
  **QA Scenarios**:
  ```
  Scenario: research gate full check
    Tool: Bash
    Steps:
      1. just p2-research-gate
    Expected: exit 0; primary + fallback frozen.
    Evidence: .sisyphus/evidence/p2-research/gate-output.txt
  ```
  **Commit**: YES — `research(p2): RG-P2 passed, primary+fallback frozen`

#### Phase C Design Wave (C.D.*)

- [x] C.D.1. P2 frozen interface spec (folding API)

  **What to do**: Define folding prover/verifier API: `fold(acc, p1_nizk, statement) -> acc'`, `verify_acc(acc) -> bool`, plus public-input layout that P3 will consume. Specify accumulator serialization (recursion- and on-chain-friendly), commitment to FHE params, and termination/finalization step. Adapter behind `surrogate-folding` Cargo feature.
  **Must NOT do**: Bake LF+-specific gadgets into the public API.
  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave C.D; depends on C.R.5. Blocks C.D.2–C.D.5.
  **References**: C.R.5, `circuits/aggregator_final/src/main.nr`, `.sisyphus/contracts/p1-to-p2-bundle.md`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p2/interface-spec.md` complete with statement/witness/accumulator schemas.
  - [ ] Adapter strategy section explicit.
  - [ ] Surrogate-shape contamination check PASS.
  **QA Scenarios**:
  ```
  Scenario: interface spec schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-design-gate.py --check interface-spec
    Expected: schemas valid; no contamination.
    Evidence: .sisyphus/evidence/p2-design/interface-check.txt
  ```
  **Commit**: YES — `design(p2): frozen folding interface and accumulator schema`

- [x] C.D.2. P2 stack decision memo

  **What to do**: Pick primary + fallback. Quantitative comparison: prover time at fold-depth 513, prover memory peak, accumulator size, verifier cost (on-chain via P3), recursion fit, PQ posture, license, audit surface. Rust-in-zkVM (SP1/RISC0/Jolt running a Rust LF+ verifier) is an EXPLICIT fallback option per user mandate.
  **Must NOT do**: Pick a stack incompatible with the eventual P3 on-chain target.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave C.D; depends on C.D.1.
  **References**: C.R.5 scorecard, `bench/`, P3 surrogate for on-chain target shape.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p2/stack-decision.md` with primary + fallback + bench projections.
  - [ ] Reviewer VERDICT.
  **QA Scenarios**:
  ```
  Scenario: stack memo schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-design-gate.py --check stack-decision
    Expected: primary + fallback declared; bench projections present.
    Evidence: .sisyphus/evidence/p2-design/stack-check.txt
  ```
  **Commit**: YES — `design(p2): stack decision (primary + fallback)`

- [x] C.D.3. P2 theorem statements + full proof skeletons

  **What to do**: Write formal statements for T1–T5 from C.R.4 against chosen stack. Skeletons must include recursion-budget analysis (extraction tree depth × per-fold extractor cost). External advisor review required at DG.
  **Must NOT do**: Cite LF+ paper proofs without restating in our setting.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave C.D; depends on C.D.2.
  **References**: C.R.4, `docs/security-proofs/obligations.md`.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p2/proof-skeletons.md` covering T1–T5.
  - [ ] External advisor VERDICT.
  **QA Scenarios**:
  ```
  Scenario: proof skeletons completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-design-gate.py --check proof-skeletons
    Expected: all T1–T5 present; advisor APPROVE.
    Evidence: .sisyphus/evidence/p2-design/proof-skeletons-check.txt
  ```
  **Commit**: YES — `design(p2): theorem statements and proof skeletons`

- [x] C.D.4. P2 benchmark plan + migration plan

  **What to do**: Benchmark matrix (n × fold-depth × stack), migration from surrogate (adapter rollout, feature-flag flip, surrogate retirement schedule), rollback criteria.
  **Must NOT do**: Skip rollback; leave surrogate retirement open.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave C.D; depends on C.D.1–C.D.3.
  **References**: B.D.4 template, `bench/`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p2/{bench-plan,migration-plan}.md` complete.
  **QA Scenarios**:
  ```
  Scenario: bench/migration plan present
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-design-gate.py --check bench-migration
    Expected: both files schema-valid.
    Evidence: .sisyphus/evidence/p2-design/bench-migration-check.txt
  ```
  **Commit**: YES — `design(p2): benchmark and migration plan`

- [x] C.D.5. **Unified-paper-vs-split-paper decision + Design Gate (DG-P2)**

  **What to do**: At end of P2 Design — per Metis directive — decide whether the program produces ONE unified paper (default) or splits into multiple targeted papers (e.g., "Hermine-PVSS for thresh-FHE", "Lattice NIZK for share correctness", "LF+-over-RLWE for aggregation", "MicroNova-lattice on-chain"). Decision memo must reach the program lead. Update Phase E scaffold accordingly. Run `just p2-design-gate`.
  **Must NOT do**: Defer the decision again; allow Phase E to start without this resolved.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave C.D FINAL; depends on C.D.1–C.D.4.
  **References**: A.R.5/B.R.5/C.R.5 scorecards, `paper/main.tex` scaffold from Phase 0.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p2/paper-strategy-decision.md` with: chosen strategy (UNIFIED or SPLIT-N), rationale, paper-by-paper claims allocation if SPLIT, target venues per paper, timeline impact.
  - [ ] Decision signed by program lead + external advisor.
  - [ ] `paper/main.tex` updated to reflect decision (or split into `paper/p4.tex`, `paper/p1.tex`, `paper/p2.tex`, `paper/p3.tex` if SPLIT).
  - [ ] `just p2-design-gate` exits 0.
  **QA Scenarios**:
  ```
  Scenario: paper strategy decision recorded
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-design-gate.py --check paper-strategy
      2. just p2-design-gate
    Expected: both exit 0; decision file present and signed; paper scaffold reflects decision.
    Evidence: .sisyphus/evidence/p2-design/paper-strategy.txt
  ```
  **Commit**: YES — `design(p2): DG-P2 passed; paper strategy decision recorded`

#### Phase C Implementation Wave (C.I.*)

- [x] C.I.1. RED tests for real folding scheme

  **What to do**: Write failing tests against the C.D.1 interface: (a) fold of two valid P1 NIZKs verifies; (b) fold-of-fold verifies (depth ≥3); (c) tampered inner P1 proof → reject; (d) wrong FHE param across folds → reject; (e) accumulator binding test; (f) determinism. New file `crates/pvthfhe-aggregator/tests/folding.rs`. RED via `unimplemented!()`.
  **Must NOT do**: Test surrogate; skip depth ≥3.
  **Recommended Agent Profile**: `quick`. Skills: [].
  **Parallelization**: Wave C.I; depends on C.D.5.
  **References**: C.D.1 trait sketch, AGENTS.md TDD policy.
  **Acceptance Criteria**:
  - [ ] ≥6 failing tests with `unimplemented!`.
  **QA Scenarios**:
  ```
  Scenario: RED phase confirmed
    Tool: Bash
    Steps:
      1. cargo test -p pvthfhe-aggregator --features=real-folding folding 2>&1 | tee evidence.txt
    Expected: ≥6 tests, all FAILED.
    Evidence: .sisyphus/evidence/p2-impl/red-tests.txt
  ```
  **Commit**: YES — `test(p2): RED tests for real folding scheme [skip-green]`

- [x] C.I.2. GREEN: implement chosen folding stack + adapter

  **What to do**: Implement primary stack from C.D.2 behind `real-folding` feature; replace surrogate IN PLACE per stub protocol. Adapter routes between surrogate (default OFF in CI prod) and real impl. Move RED tests to GREEN.
  **Must NOT do**: Delete-and-recreate surrogate; let interfaces diverge.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave C.I; depends on C.I.1.
  **References**: C.D.1, C.D.2, AGENTS.md.
  **Acceptance Criteria**:
  - [ ] Real impl committed; surrogate feature-flagged.
  - [ ] All C.I.1 tests PASS under `real-folding`.
  - [ ] CI default flips to `real-folding`.
  **QA Scenarios**:
  ```
  Scenario: GREEN phase confirmed
    Tool: Bash
    Steps:
      1. cargo test -p pvthfhe-aggregator --features=real-folding folding
    Expected: all PASS; surrogate baseline still passes under its own feature.
    Evidence: .sisyphus/evidence/p2-impl/green-tests.txt
  ```
  **Commit**: YES — `feat(p2): real folding scheme primary impl behind real-folding feature`

- [x] C.I.3. Adversarial tests + soundness amplification harness

  **What to do**: Adversarial: malformed inner proof, accumulator forgery attempt, FS challenge grinding, depth-bomb (very deep folds), parameter mismatch. Add property tests for soundness amplification (per-fold error × depth) matching the C.R.3 / C.D.3 analysis.
  **Must NOT do**: Mock the verifier; rely on placeholders.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave C.I; depends on C.I.2.
  **References**: C.R.3, C.D.3.
  **Acceptance Criteria**:
  - [ ] ≥10 adversarial cases pass.
  - [ ] Soundness amplification harness produces report matching theoretical bound within tolerance.
  **QA Scenarios**:
  ```
  Scenario: adversarial suite
    Tool: Bash
    Steps:
      1. cargo test -p pvthfhe-aggregator --features=real-folding folding_adversarial
    Expected: all PASS; ≥10 distinct attack vectors; amplification report present.
    Evidence: .sisyphus/evidence/p2-impl/adversarial.txt
  ```
  **Commit**: YES — `test(p2): adversarial + soundness amplification harness`

- [x] C.I.4. Full security proofs (paper-ready)

  **What to do**: Expand C.D.3 skeletons into full proofs in `docs/security-proofs/p2/`. T1–T5 with reductions, parameter constraints, recursion budget. External advisor review.
  **Must NOT do**: Cite "by inspection" for non-trivial steps.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave C.I; depends on C.I.2.
  **References**: C.D.3, C.I.2 params.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p2/{T1..T5}.md` complete.
  - [ ] Advisor VERDICT: APPROVE.
  - [ ] Obligations tracker rows PROVED.
  **QA Scenarios**:
  ```
  Scenario: proofs completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p2-impl-gate.py --check proofs
    Expected: all PROVED; advisor APPROVE.
    Evidence: .sisyphus/evidence/p2-impl/proofs-check.txt
  ```
  **Commit**: YES — `proof(p2): full security proofs T1–T5`

- [x] C.I.5. Benchmarks at n=128, n=512, n=1024 + paper figures

  **What to do**: Run C.D.4 matrix on representative hardware. Generate paper-ready figures. Compare against prior-art (LF+ paper claims, Nova benchmarks).
  **Must NOT do**: Cherry-pick.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave C.I; depends on C.I.2.
  **References**: C.D.4, `bench/`.
  **Acceptance Criteria**:
  - [ ] `bench/p2/results-{128,512,1024}.json`.
  - [ ] `paper/figures/p2-bench.{pdf,tex}`.
  - [ ] Comparison vs. ≥3 prior-art.
  **QA Scenarios**:
  ```
  Scenario: bench reproduction
    Tool: Bash
    Steps:
      1. just p2-bench
    Expected: exits 0; figures regenerated deterministically.
    Evidence: .sisyphus/evidence/p2-impl/bench.txt
  ```
  **Commit**: YES — `bench(p2): n=128/512/1024 results and paper figures`

- [x] C.I.6. P2 Implementation Gate (IG-P2) + downstream contract bundle for P3

  **What to do**: Run `just p2-impl-gate`. Publish `.sisyphus/contracts/p2-to-p3-bundle.md` with all 7 sections (frozen accumulator format, on-chain-verifier op-budget, public-input encoding, security caveats, regression baseline, gas projections, recursion path). Surrogate retirement check.
  **Must NOT do**: Pass IG-P2 with surrogate still default; ship a bundle missing on-chain budget P3 needs.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave C.I FINAL; depends on C.I.1–C.I.5.
  **References**: Phase 0 contract bundle template.
  **Acceptance Criteria**:
  - [ ] `just p2-impl-gate` exits 0.
  - [ ] `.sisyphus/contracts/p2-to-p3-bundle.md` published.
  - [ ] Advisor VERDICT: APPROVE.
  **QA Scenarios**:
  ```
  Scenario: IG-P2 + bundle
    Tool: Bash
    Steps:
      1. just p2-impl-gate
      2. python .sisyphus/scripts/p2-impl-gate.py --check downstream-bundle
    Expected: both exit 0; bundle present and validated.
    Evidence: .sisyphus/evidence/p2-impl/ig-output.txt
  ```
  **Commit**: YES — `gate(p2): IG-P2 passed, P2→P3 bundle published`


### Phase D — P3: MicroNova-Lattice On-Chain (or Recursive Wrapper) Verifier

> **Surrogate to replace**: `contracts/src/generated/HonkVerifier.sol` (auto-generated UltraHonk verifier — verifies the surrogate Noir circuits, NOT the real folded P2 statement). Real construction must verify the P2 final accumulator on-chain (EVM Solidity) within reasonable gas, OR via a recursive wrapper that produces an EVM-cheap final proof (e.g., MicroNova-style accumulation followed by a SNARK-of-SNARK over a pairing-friendly curve, or Rust-in-zkVM final-step proof verified on-chain).
> **Carry forward**: P2→P3 downstream contract bundle (accumulator format, op-budget projections, public-input encoding).
> **Stack freedom**: Direct EVM verifier (Solidity), Halo2-on-EVM (Solidity verifier), Plonky3 wrapped to Groth16-on-EVM, MicroNova lattice variant + EVM final, SP1/RISC0 Groth16 wrap, Jolt EVM wrap, custom EVM precompile proposal. Decision deferred to D.D.2.

#### Phase D Research Wave (D.R.*)

- [x] D.R.1. P3 prior-art matrix

  **What to do**: Survey on-chain proof verification options for lattice-style proofs. Required entries: Halo2/PSE EVM verifier, Plonky3+Groth16-wrap, RISC0+Groth16, SP1+Groth16/Plonk-EVM, Jolt EVM target, MicroNova on-chain variant, Nebra-style accumulation, lattice-precompile EIP proposals, recursion-to-pairing-curve via Reckle Trees / Origami / cycle-of-curves, and "Rust-in-zkVM with EVM final wrap" variants (the explicit user-mandated worst-case fallback).
  **Must NOT do**: Treat all SNARK→EVM wraps as equivalent; ignore calldata costs.
  **Recommended Agent Profile**: `deep`. Skills: [`paperclip`].
  **Parallelization**: Wave D.R; can start immediately after C.I.6 publishes P2→P3 bundle. Blocked by: C.I.6.
  **References**: ePrint 2024/2099 (MicroNova), `contracts/src/generated/HonkVerifier.sol`, `.sisyphus/contracts/p2-to-p3-bundle.md`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p3/prior-art.md` with ≥8 entries; columns: stack, gas estimate, calldata bytes, proof size, prover time, audit status, license, EIP/precompile dependence.
  - [ ] At least 2 viable primary; at least 2 viable fallback.
  - [ ] Reviewer VERDICT.
  **QA Scenarios**:
  ```
  Scenario: prior-art matrix completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-research-gate.py --check prior-art-matrix
    Expected: ≥8 entries; required columns populated; Rust-in-zkVM-EVM-wrap row present.
    Evidence: .sisyphus/evidence/p3-research/prior-art-check.txt
  ```
  **Commit**: YES — `research(p3): prior-art matrix for on-chain verifier candidates`

 - [x] D.R.2. P3 novelty gap memo

  **What to do**: Identify what is missing: (a) verifying P2's specific folded accumulator on EVM within an acceptable gas budget; (b) handling lattice-native ops in EVM (no native large-modulus arithmetic) — either via wrapping into a SNARK-friendly outer proof or via a custom EVM strategy; (c) batched verification across multiple FHE sessions; (d) avoiding trusted setup per protocol. Aggressive bets: novel pairing-curve cycle for lattice proofs, EVM precompile proposal (EIP), cheap recursion via STIR/WHIR final-step.
  **Must NOT do**: Defer to "Rust-in-zkVM" reflexively without evaluating direct EVM paths.
  **Recommended Agent Profile**: `artistry`. Skills: [].
  **Parallelization**: Wave D.R; depends on D.R.1.
  **References**: D.R.1, P2→P3 bundle.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p3/novelty-memo.md` complete.
  - [ ] ≥1 aggressive bet documented.
  - [ ] External advisor VERDICT.
  **QA Scenarios**:
  ```
  Scenario: novelty memo schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-research-gate.py --check novelty-memo
    Expected: required sections present; aggressive bet documented.
    Evidence: .sisyphus/evidence/p3-research/novelty-memo-check.txt
  ```
  **Commit**: YES — `research(p3): novelty gap memo and aggressive-bet candidates`

 - [x] D.R.3. P3 threat model + adversary model

  **What to do**: Define on-chain-specific threats: malicious prover with chosen ciphertexts, MEV/reorg interaction with proof submission, calldata manipulation, on-chain verifier-bug exploitation (audit posture), trusted-setup ceremony assumptions if unavoidable. Reconcile with P2 threat model.
  **Must NOT do**: Allow assumption drift from P2; ignore EVM-specific attack vectors (front-running, calldata griefing).
  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave D.R; depends on D.R.1.
  **References**: P2 threat model (C.R.3), P2→P3 bundle.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p3/threat-model.md` complete.
  - [ ] P2 consistency check PASS.
  - [ ] Reviewer VERDICT.
  **QA Scenarios**:
  ```
  Scenario: threat model schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-research-gate.py --check threat-model
    Expected: required fields set; P2 consistency PASS.
    Evidence: .sisyphus/evidence/p3-research/threat-model-check.txt
  ```
  **Commit**: YES — `research(p3): threat and adversary model`

 - [x] D.R.4. P3 theorem inventory + proof obligations

  **What to do**: Theorems: (T1) on-chain verifier soundness (relative to P2 statement), (T2) wrap-preserves-soundness if recursive wrap used, (T3) trusted-setup security if any, (T4) gas-bound theorem (op-count ≤ budget), (T5) liveness/abort-with-public-blame on-chain. Update obligations tracker.
  **Must NOT do**: Skip T4 (gas budget is a security-relevant DoS surface).
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave D.R; depends on D.R.3.
  **References**: `docs/security-proofs/obligations.md`.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p3/theorem-inventory.md` complete.
  - [ ] Obligations updated.
  - [ ] Oracle VERDICT.
  **QA Scenarios**:
  ```
  Scenario: theorem inventory tracker update
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-research-gate.py --check theorem-inventory
    Expected: ≥5 theorem rows for P3.
    Evidence: .sisyphus/evidence/p3-research/theorem-inventory-check.txt
  ```
  **Commit**: YES — `research(p3): theorem inventory and proof obligations`

 - [x] D.R.5. P3 candidate scorecard + primary/fallback freeze + Research Gate (RG-P3)

  **What to do**: Score candidates against gas budget, prover wall-time end-to-end, proof size on-chain, trusted-setup posture, novelty cost, audit ecosystem maturity. Freeze primary + fallback (Rust-in-zkVM-with-Groth16-EVM-wrap is a defensible fallback). External advisor REQUIRED. Run `just p3-research-gate`.
  **Must NOT do**: Pick a stack requiring an EIP we cannot land in time as primary without a non-EIP fallback.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave D.R FINAL; depends on D.R.1–D.R.4.
  **References**: D.R.1–D.R.4.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/research/p3/scorecard.md` with primary + fallback.
  - [ ] `.sisyphus/research/p3/RG-P3-decision.md` signed.
  - [ ] `just p3-research-gate` exits 0; advisor APPROVE.
  **QA Scenarios**:
  ```
  Scenario: research gate full check
    Tool: Bash
    Steps:
      1. just p3-research-gate
    Expected: exit 0; primary + fallback frozen.
    Evidence: .sisyphus/evidence/p3-research/gate-output.txt
  ```
  **Commit**: YES — `research(p3): RG-P3 passed, primary+fallback frozen`

#### Phase D Design Wave (D.D.*)

 - [x] D.D.1. P3 frozen interface spec (on-chain verifier API)

  **What to do**: Define Solidity verifier interface: `function verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool)` plus event schema for failure attribution and abort-with-public-blame routing. Specify calldata layout, public-input encoding (must match P2→P3 bundle), and integration with the existing Foundry project layout. Adapter behind feature flag at the off-chain prover side.
  **Must NOT do**: Bake HonkVerifier-isms into the interface; rely on circuits/aggregator_final shape.
  **Recommended Agent Profile**: `deep`. Skills: [].
  **Parallelization**: Wave D.D; depends on D.R.5. Blocks D.D.2–D.D.4.
  **References**: D.R.5, `contracts/src/generated/HonkVerifier.sol`, P2→P3 bundle, AGENTS.md Foundry root convention.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p3/interface-spec.md` complete.
  - [ ] Solidity ABI sketch in `.sisyphus/design/p3/iface.sol.md` (markdown excerpt only).
  - [ ] Surrogate-shape contamination check PASS.
  **QA Scenarios**:
  ```
  Scenario: interface spec schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-design-gate.py --check interface-spec
    Expected: schemas valid; no contamination.
    Evidence: .sisyphus/evidence/p3-design/interface-check.txt
  ```
  **Commit**: YES — `design(p3): frozen on-chain verifier interface`

 - [x] D.D.2. P3 stack decision memo

  **What to do**: Pick primary + fallback. Quantitative: end-to-end gas at submission, calldata size, prover wall-time on commodity hardware, audit surface, trusted-setup posture, license. Rust-in-zkVM + Groth16 EVM wrap is the explicit user-mandated worst-case fallback.
  **Must NOT do**: Pick primary without a non-EIP fallback.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave D.D; depends on D.D.1.
  **References**: D.R.5 scorecard, `bench/`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p3/stack-decision.md` with primary + fallback + gas projections.
  - [ ] Reviewer VERDICT.
  **QA Scenarios**:
  ```
  Scenario: stack memo schema
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-design-gate.py --check stack-decision
    Expected: primary + fallback declared; gas projections present.
    Evidence: .sisyphus/evidence/p3-design/stack-check.txt
  ```
  **Commit**: YES — `design(p3): stack decision (primary + fallback)`

 - [x] D.D.3. P3 theorem statements + full proof skeletons

  **What to do**: Formal statements for T1–T5 from D.R.4 against chosen stack. Skeletons must include gas-bound argument (T4) and wrap-preserves-soundness if applicable (T2).
  **Must NOT do**: Treat T4 as engineering-only.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave D.D; depends on D.D.2.
  **References**: D.R.4, `docs/security-proofs/obligations.md`.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p3/proof-skeletons.md` covering T1–T5.
  - [ ] External advisor VERDICT.
  **QA Scenarios**:
  ```
  Scenario: proof skeletons completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-design-gate.py --check proof-skeletons
    Expected: all T1–T5 present; advisor APPROVE.
    Evidence: .sisyphus/evidence/p3-design/proof-skeletons-check.txt
  ```
  **Commit**: YES — `design(p3): theorem statements and proof skeletons`

 - [x] D.D.4. P3 benchmark + migration plan + Design Gate (DG-P3)

  **What to do**: Benchmark matrix (n × stack × network: local-anvil, sepolia-fork, mainnet-fork), migration from surrogate HonkVerifier (adapter rollout, deployment script changes, surrogate retirement), rollback criteria. Run `just p3-design-gate`.
  **Must NOT do**: Skip rollback; leave surrogate retirement open.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave D.D FINAL; depends on D.D.1–D.D.3.
  **References**: B.D.4/C.D.4 templates, `bench/`, `contracts/`.
  **Acceptance Criteria**:
  - [ ] `.sisyphus/design/p3/{bench-plan,migration-plan}.md` complete.
  - [ ] `just p3-design-gate` exits 0.
  - [ ] Advisor VERDICT: APPROVE.
  **QA Scenarios**:
  ```
  Scenario: design gate full check
    Tool: Bash
    Steps:
      1. just p3-design-gate
    Expected: exit 0; gate report enumerates D.D.1–D.D.3 PASS.
    Evidence: .sisyphus/evidence/p3-design/gate-output.txt
  ```
  **Commit**: YES — `design(p3): DG-P3 passed`

#### Phase D Implementation Wave (D.I.*)

- [x] D.I.1. RED tests for real on-chain verifier

  **What to do**: Write failing Foundry tests against the D.D.1 interface: (a) honest P2 final proof verifies; (b) tampered proof rejects; (c) wrong public-input rejects; (d) gas usage within budget; (e) abort-with-public-blame event emitted on rejection; (f) determinism across re-submissions. New file `contracts/test/RealVerifier.t.sol`. RED via verifier returning `revert("unimplemented")`.
  **Must NOT do**: Test surrogate; rely on `nargo prove` (forbidden per AGENTS.md).
  **Recommended Agent Profile**: `quick`. Skills: [].
  **Parallelization**: Wave D.I; depends on D.D.4.
  **References**: D.D.1, AGENTS.md (Foundry root convention, canonical Noir+BB flow only if Noir is part of stack).
  **Acceptance Criteria**:
  - [ ] ≥6 failing Foundry tests via `forge test --root contracts`.
  **QA Scenarios**:
  ```
  Scenario: RED phase confirmed
    Tool: Bash
    Steps:
      1. forge test --root contracts --match-contract RealVerifier 2>&1 | tee evidence.txt
    Expected: ≥6 tests, all FAILED.
    Evidence: .sisyphus/evidence/p3-impl/red-tests.txt
  ```
  **Commit**: YES — `test(p3): RED tests for real on-chain verifier [skip-green]`

- [x] D.I.2. GREEN: implement chosen on-chain verifier + adapter

  **What to do**: Implement primary stack from D.D.2. Replace surrogate `contracts/src/generated/HonkVerifier.sol` IN PLACE per stub protocol — keep the file, replace its contents with the real generated/written verifier (or a thin facade routing to the real one) and add a feature flag at the off-chain prover side. CI deployment scripts updated.
  **Must NOT do**: Delete-and-recreate the surrogate file; let off-chain prover and on-chain verifier diverge in public-input encoding.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave D.I; depends on D.I.1.
  **References**: D.D.1, D.D.2, AGENTS.md stub protocol.
  **Acceptance Criteria**:
  - [ ] Real verifier deployed in tests; surrogate annotated and feature-flagged.
  - [ ] All D.I.1 tests PASS via `forge test --root contracts`.
  - [ ] Gas usage report within DG-P3 budget.
  **QA Scenarios**:
  ```
  Scenario: GREEN phase confirmed
    Tool: Bash
    Steps:
      1. forge test --root contracts --match-contract RealVerifier --gas-report
    Expected: all PASS; gas within budget; surrogate baseline still passes under its own profile.
    Evidence: .sisyphus/evidence/p3-impl/green-tests.txt
  ```
  **Commit**: YES — `feat(p3): real on-chain verifier primary impl`

- [x] D.I.3. Adversarial tests + integration with P4→P1→P2→P3 full pipeline

  **What to do**: Adversarial: malformed calldata, gas-griefing patterns, replay across sessions, MEV/reorg simulation. End-to-end pipeline test: run real P4 PVSS → real P1 NIZKs → real P2 folding → real P3 on-chain verification, all under `real-*` feature flags. Confirm zero surrogate paths active.
  **Must NOT do**: Mock cross-phase boundaries.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave D.I; depends on D.I.2.
  **References**: D.R.3 threat model, all prior gates.
  **Acceptance Criteria**:
  - [ ] ≥10 adversarial Foundry test cases pass.
  - [ ] End-to-end integration test passes with `real-pvss + real-nizk + real-folding + real-verifier` features.
  **QA Scenarios**:
  ```
  Scenario: adversarial + e2e pipeline
    Tool: Bash
    Steps:
      1. forge test --root contracts --match-contract RealVerifierAdversarial
      2. just e2e-real
    Expected: both PASS; surrogate paths confirmed dormant via runtime assertion.
    Evidence: .sisyphus/evidence/p3-impl/adversarial-e2e.txt
  ```
  **Commit**: YES — `test(p3): adversarial + full real-stack e2e integration`

- [x] D.I.4. Full security proofs (paper-ready)

  **What to do**: Expand D.D.3 skeletons in `docs/security-proofs/p3/`. T1–T5 with reductions, gas-bound proof, trusted-setup analysis if applicable. External advisor review.
  **Must NOT do**: Hand-wave gas bound.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave D.I; depends on D.I.2.
  **References**: D.D.3, D.I.2 deployed verifier params.
  **Acceptance Criteria**:
  - [ ] `docs/security-proofs/p3/{T1..T5}.md` complete.
  - [ ] Advisor VERDICT: APPROVE.
  - [ ] Obligations rows PROVED.
  **QA Scenarios**:
  ```
  Scenario: proofs completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/p3-impl-gate.py --check proofs
    Expected: all PROVED; advisor APPROVE.
    Evidence: .sisyphus/evidence/p3-impl/proofs-check.txt
  ```
  **Commit**: YES — `proof(p3): full security proofs T1–T5`

- [x] D.I.5. Benchmarks at n=128, n=512, n=1024 + gas reports + paper figures

  **What to do**: Run D.D.4 matrix. Generate gas reports per network (local/sepolia-fork/mainnet-fork). Paper-ready figures. Compare against prior-art on-chain verifiers.
  **Must NOT do**: Cherry-pick networks; omit calldata cost.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Wave D.I; depends on D.I.2.
  **References**: D.D.4, `bench/`.
  **Acceptance Criteria**:
  - [ ] `bench/p3/results-{128,512,1024}-{local,sepolia,mainnet}.json`.
  - [ ] `paper/figures/p3-bench.{pdf,tex}`.
  - [ ] Comparison vs. ≥3 prior-art.
  **QA Scenarios**:
  ```
  Scenario: bench reproduction
    Tool: Bash
    Steps:
      1. just p3-bench
    Expected: exits 0; figures regenerated deterministically; gas reports per network present.
    Evidence: .sisyphus/evidence/p3-impl/bench.txt
  ```
  **Commit**: YES — `bench(p3): n=128/512/1024 gas results and paper figures`

- [x] D.I.6. P3 Implementation Gate (IG-P3) + final surrogate retirement

  **What to do**: Run `just p3-impl-gate`. Confirm ALL FOUR surrogates (`keygen/protocol.rs`, `circuits/decrypt_share`, `circuits/aggregator_final`, `contracts/src/generated/HonkVerifier.sol`) are now feature-flagged regression baselines only — production CI uses real-* features by default. No downstream contract bundle (P3 is terminal).
  **Must NOT do**: Pass IG-P3 with any surrogate still on the default CI path; retire surrogates by deleting the files (violates stub protocol).
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Wave D.I FINAL; depends on D.I.1–D.I.5.
  **References**: AGENTS.md stub protocol, all prior IGs.
  **Acceptance Criteria**:
  - [ ] `just p3-impl-gate` exits 0.
  - [ ] Surrogate-retirement check report shows: 4/4 surrogates feature-flagged; 0 active in default CI; all 4 files still present (not deleted).
  - [ ] External advisor VERDICT: APPROVE.
  **QA Scenarios**:
  ```
  Scenario: IG-P3 + surrogate retirement
    Tool: Bash
    Steps:
      1. just p3-impl-gate
      2. python .sisyphus/scripts/surrogate-retirement-check.py
    Expected: both exit 0; 4/4 retired-but-present.
    Evidence: .sisyphus/evidence/p3-impl/ig-output.txt
  ```
  **Commit**: YES — `gate(p3): IG-P3 passed, all surrogates retired (feature-flagged)`


### Phase E — Unified Paper Assembly + Reproducible Artifact

> **Strategy**: per C.D.5 decision (UNIFIED default; SPLIT-N if program lead chose splitting at end of P2 Design). All claim integration, theorem cross-referencing, benchmark figures, and artifact appendix.
> **Shadow writing track**: paper sections were drafted continuously since Phase 0 task 0.2; Phase E is assembly + finalization, NOT first draft.

- [x] E.1. Cross-paper claims-table audit

  **What to do**: Walk every Required Theorem from `docs/security-proofs/obligations.md` and confirm it appears in `paper/claims-table.md` with: file path of full proof, statement, assumption, model (ROM/QROM), tightness, paper section reference. If SPLIT strategy: claims allocated correctly across `paper/p{4,1,2,3}.tex` with no double-counting.
  **Must NOT do**: Allow any obligation row in PROVED state without a corresponding claims-table row.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Phase E START; depends on D.I.6 (last IG).
  **References**: `docs/security-proofs/obligations.md`, `paper/claims-table.md`, C.D.5 decision.
  **Acceptance Criteria**:
  - [ ] 1:1 mapping from obligations.md PROVED rows to claims-table.md rows.
  - [ ] No orphan claims; no orphan obligations.
  **QA Scenarios**:
  ```
  Scenario: claims-table audit
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/paper-gate.py --check claims-table
    Expected: 1:1 mapping verified.
    Evidence: .sisyphus/evidence/paper/claims-table-check.txt
  ```
  **Commit**: YES — `paper: claims-table audit complete`

- [x] E.2. Theorem-statement consolidation in paper body

  **What to do**: Pull theorem statements from `docs/security-proofs/{p4,p1,p2,p3}/T*.md` into the paper body. Maintain 1:1 wording (paper statement === proof file statement). Cross-reference theorem labels.
  **Must NOT do**: Restate theorems with subtle wording drift.
  **Recommended Agent Profile**: `writing`. Skills: [].
  **Parallelization**: Phase E; depends on E.1.
  **References**: `docs/security-proofs/`, `paper/main.tex` (or split papers).
  **Acceptance Criteria**:
  - [ ] All theorems present in paper body with exact wording.
  - [ ] LaTeX compiles cleanly.
  **QA Scenarios**:
  ```
  Scenario: theorem statement consistency
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/paper-gate.py --check theorem-consistency
      2. just paper-build
    Expected: both exit 0; PDF generated.
    Evidence: .sisyphus/evidence/paper/theorem-consistency.txt
  ```
  **Commit**: YES — `paper: theorem statements consolidated`

- [x] E.3. Benchmark figures + comparison tables

  **What to do**: Pull `paper/figures/p{4,1,2,3}-bench.{pdf,tex}` into paper. Build cross-problem summary table (n=128/512/1024 across all four problems). Comparison rows vs. prior art per problem.
  **Must NOT do**: Re-run benchmarks here; cherry-pick.
  **Recommended Agent Profile**: `writing`. Skills: [].
  **Parallelization**: Phase E; depends on E.1.
  **References**: `bench/p{4,1,2,3}/`, `paper/figures/`.
  **Acceptance Criteria**:
  - [ ] All four bench figures referenced; cross-problem summary table present.
  - [ ] Source data hashes recorded for reproducibility.
  **QA Scenarios**:
  ```
  Scenario: figure inclusion + reproducibility
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/paper-gate.py --check figures
    Expected: all four figures present; data-hash audit PASS.
    Evidence: .sisyphus/evidence/paper/figures-check.txt
  ```
  **Commit**: YES — `paper: benchmark figures and comparison tables`

- [x] E.4. Artifact appendix + reproducibility script

  **What to do**: Author `paper/artifact-appendix.md` per Crypto/Eurocrypt/CCS artifact-evaluation guidelines. Provide single command (`just artifact-reproduce`) that, from a clean clone, produces: built crates, real-stack tests passing, all four benchmark JSONs, all four paper figures, and on-chain verifier deployment + verification on local anvil. Pin exact toolchain versions (continues T44 from prior plan).
  **Must NOT do**: Depend on non-public infrastructure; require external API keys for reproduction.
  **Recommended Agent Profile**: `unspecified-high`. Skills: [].
  **Parallelization**: Phase E; depends on E.3.
  **References**: AGENTS.md toolchain protocol, REPRODUCING.md (T44 continued), all bench directories.
  **Acceptance Criteria**:
  - [ ] `paper/artifact-appendix.md` complete with hardware reqs, time budget, reproduction steps.
  - [ ] `just artifact-reproduce` exits 0 from clean clone in CI.
  - [ ] Toolchain versions pinned in `REPRODUCING.md`.
  **QA Scenarios**:
  ```
  Scenario: artifact reproduction in CI
    Tool: Bash
    Steps:
      1. ./.sisyphus/scripts/clean-clone-reproduce.sh
    Expected: full reproduction succeeds in time budget; all evidence regenerates.
    Evidence: .sisyphus/evidence/paper/artifact-reproduce.txt
  ```
  **Commit**: YES — `paper: artifact appendix and reproducibility script`

- [x] E.5. Internal review pass

  **What to do**: In-house reviewer roster (Phase 0 task 0.5) reviews the assembled paper(s). Each reviewer files a memo at `.sisyphus/reviews/internal-{name}-final.md` with VERDICT line. Reviewers cover: theorem completeness, novelty articulation, benchmark fairness, related-work coverage, narrative clarity.
  **Must NOT do**: Combine reviews; allow VERDICT-less memos.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Phase E; depends on E.4.
  **References**: `docs/governance/reviewer-roster.md` (Phase 0 task 0.5), `.sisyphus/reviews/`.
  **Acceptance Criteria**:
  - [ ] ≥3 internal reviewer memos with VERDICT lines.
  - [ ] All blocker-level issues addressed (revision tracked) before E.6.
  **QA Scenarios**:
  ```
  Scenario: internal review completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/paper-gate.py --check internal-reviews
    Expected: ≥3 memos; all blockers resolved.
    Evidence: .sisyphus/evidence/paper/internal-reviews.txt
  ```
  **Commit**: YES — `paper: internal review pass complete`

- [x] E.6. External cryptographer review pass

  **What to do**: Send paper(s) to ≥1 external cryptographer (per advisory model). Memo filed at `.sisyphus/reviews/external-{name}-final.md` with VERDICT. Address all blocker-level feedback before E.7.
  **Must NOT do**: Treat external advisory as optional; ship without external sign-off.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Phase E; depends on E.5.
  **References**: Phase 0 reviewer-roster, `.sisyphus/reviews/`.
  **Acceptance Criteria**:
  - [ ] ≥1 external memo with VERDICT.
  - [ ] All blocker-level external issues resolved.
  **QA Scenarios**:
  ```
  Scenario: external review completeness
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/paper-gate.py --check external-reviews
    Expected: ≥1 memo; blockers resolved.
    Evidence: .sisyphus/evidence/paper/external-reviews.txt
  ```
  **Commit**: YES — `paper: external cryptographer review pass complete`

- [x] E.7. Submission-readiness checklist + Paper Gate

  **What to do**: Run `just paper-gate`. Verify: PDF builds clean, ≤ venue page limit, claims-table audit PASS, theorem-consistency PASS, figures embedded, artifact appendix builds, internal+external reviews APPROVE, anonymization audit (single- vs double-blind per chosen venue) PASS.
  **Must NOT do**: Pass paper gate while any review verdict is REJECT or REVISE.
  **Recommended Agent Profile**: `oracle`. Skills: [].
  **Parallelization**: Phase E FINAL; depends on E.1–E.6.
  **References**: All E.* outputs, target venue submission instructions.
  **Acceptance Criteria**:
  - [ ] `just paper-gate` exits 0.
  - [ ] All venue-specific submission requirements satisfied (page limit, anonymization, artifact link).
  **QA Scenarios**:
  ```
  Scenario: paper gate full check
    Tool: Bash
    Steps:
      1. just paper-gate
    Expected: exit 0; submission-ready bundle produced.
    Evidence: .sisyphus/evidence/paper/paper-gate-output.txt
  ```
  **Commit**: YES — `paper: paper-gate passed, submission-ready`

- [x] E.8. Submission bundle + program closeout memo

  **What to do**: Produce final submission bundle (anonymized PDF + supplementary + artifact link) at `paper/submission/`. Author `.sisyphus/research/program-closeout.md` summarizing: which aggressive bets paid off, which pivoted (and to what fallback), residual open problems, follow-on research directions, and lessons learned. Notify program lead.
  **Must NOT do**: Mark program complete before user explicitly oks at Final Verification Wave.
  **Recommended Agent Profile**: `writing`. Skills: [].
  **Parallelization**: Phase E FINAL; depends on E.7.
  **References**: All program artifacts.
  **Acceptance Criteria**:
  - [ ] `paper/submission/` bundle complete and reproducible.
  - [ ] `.sisyphus/research/program-closeout.md` complete.
  - [ ] Program lead notified.
  **QA Scenarios**:
  ```
  Scenario: submission bundle integrity
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/paper-gate.py --check submission-bundle
    Expected: bundle present; closeout memo present; bundle hash recorded.
    Evidence: .sisyphus/evidence/paper/submission-bundle.txt
  ```
  **Commit**: YES — `paper: submission bundle + program closeout memo`


## Final Verification Wave (MANDATORY — after Phase E)

> 5 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.
>
> **Do NOT auto-proceed after verification. Wait for user's explicit approval before marking work complete.**
> **Never mark F1–F5 as checked before getting user's okay.** Rejection or user feedback → fix → re-run → present again → wait for okay.

- [x] F1. **Plan Compliance Audit** — `oracle`
  Read this plan end-to-end. For each "Must Have": verify implementation exists (read file, run command, check artifact). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Verify all four surrogates have been replaced (not just annotated). Verify all gate evidence files exist. Verify downstream contract bundles exist for P4→P1, P1→P2, P2→P3. Verify shadow writing track artifacts exist from Phase 0 onward.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Surrogates Replaced [4/4] | Gates [12/12] | Bundles [3/3] | VERDICT: APPROVE/REJECT`

  **QA Scenarios**:
  ```
  Scenario: f1-plan-compliance-gate (agent-executable)
    Tool: Bash
    Steps:
      1. just final-verification-gate --check f1-plan-compliance
         (invokes python .sisyphus/scripts/final-verification-gate.py --check f1-plan-compliance,
          which: parses Must Have / Must NOT Have lists from this plan, greps codebase for forbidden
          patterns, verifies surrogate-retirement-check.py reports 4/4, verifies all 12 problem-gate
          evidence directories exist under .sisyphus/evidence/ (one per gate-script subcheck),
          verifies 3 downstream contract bundles exist at .sisyphus/contracts/p4-to-p1-bundle.md,
          .sisyphus/contracts/p1-to-p2-bundle.md, .sisyphus/contracts/p2-to-p3-bundle.md, and
          verifies shadow-writing artifacts paper/main.tex, paper/bib.bib, paper/claims-table.md,
          paper/figures/ exist and have grown beyond the Phase-0 skeleton).
    Expected: exit code 0; stdout final line matches `VERDICT: APPROVE`; JSON report written.
    Evidence: .sisyphus/evidence/final-qa/f1-plan-compliance.json
              .sisyphus/evidence/final-qa/f1-plan-compliance.log

  Scenario: f1-oracle-signoff (human-dependent)
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/validate-reviewer-memo.py \
           --memo .sisyphus/reviews/final-f1-oracle.md \
           --required-fields reviewer,date,verdict,findings
      2. grep -E '^VERDICT:\s*APPROVE\s*$' .sisyphus/reviews/final-f1-oracle.md
    Expected: validator exits 0; grep matches exactly one line.
    Evidence: .sisyphus/reviews/final-f1-oracle.md
  ```

- [x] F2. **Code Quality + Proof Quality Review** — `oracle` (proofs) + `unspecified-high` (code in parallel)
  **Code track**: Run `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `forge test --root contracts`, all `just` gate targets. Review changed files for AI slop (excessive comments, over-abstraction, generic names), `as any` / `unwrap` / `panic!` in non-test code, commented-out code, unused imports, surrogate-shaped APIs leaking into final design.
  **Proof track**: Read all theorems in `docs/security-proofs/`. For each: verify theorem statement is precise, reduction is explicit, all lemmas resolved, proof skeleton matches full proof, no hidden assumptions. Cross-check theorem inventory from each Research Gate against final proven theorems.
  Output: `Build [PASS/FAIL] | Lint [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | Theorems [N proven/N stated] | VERDICT`

  **QA Scenarios**:
  ```
  Scenario: f2-code-quality-gate (agent-executable)
    Tool: Bash
    Steps:
      1. just final-verification-gate --check f2-code-quality
         (runs: cargo clippy --all-targets --all-features -- -D warnings ;
                cargo test --workspace ;
                forge test --root contracts ;
                (cd circuits && nargo test) ;
                python .sisyphus/scripts/ai-slop-scan.py --paths crates/ contracts/src/ circuits/ ;
                python .sisyphus/scripts/surrogate-retirement-check.py --strict)
    Expected: exit code 0; report shows Build PASS, Lint PASS, Tests all-pass, surrogate
              retirement 4/4, AI-slop scan zero findings.
    Evidence: .sisyphus/evidence/final-qa/f2-code-quality.json
              .sisyphus/evidence/final-qa/f2-code-quality.log

  Scenario: f2-proof-quality-gate (agent-executable structural check)
    Tool: Bash
    Steps:
      1. just final-verification-gate --check f2-proof-quality
         (runs: python .sisyphus/scripts/validate-proof-skeletons.py \
                  --dir docs/security-proofs/ --require-fields theorem,reduction,lemmas,assumptions ;
                python .sisyphus/scripts/validate-obligations-schema.py \
                  --inventory docs/security-proofs/obligations.md \
                  --theorems docs/security-proofs/p4/theorem-inventory.md \
                             docs/security-proofs/p1/theorem-inventory.md \
                             docs/security-proofs/p2/theorem-inventory.md \
                             docs/security-proofs/p3/theorem-inventory.md \
                  --gates .sisyphus/evidence/)
    Expected: structural validators exit 0; theorem inventory cross-check shows N proven == N stated.
    Evidence: .sisyphus/evidence/final-qa/f2-proof-quality.json

  Scenario: f2-oracle-signoff (human-dependent — proof semantic review)
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/validate-reviewer-memo.py \
           --memo .sisyphus/reviews/final-f2-oracle-proofs.md \
           --required-fields reviewer,date,verdict,theorems-reviewed,findings
      2. python .sisyphus/scripts/validate-reviewer-memo.py \
           --memo .sisyphus/reviews/final-f2-codequality.md \
           --required-fields reviewer,date,verdict,findings
      3. grep -E '^VERDICT:\s*APPROVE\s*$' .sisyphus/reviews/final-f2-oracle-proofs.md
      4. grep -E '^VERDICT:\s*APPROVE\s*$' .sisyphus/reviews/final-f2-codequality.md
    Expected: both validators exit 0; both greps match exactly once.
    Evidence: .sisyphus/reviews/final-f2-oracle-proofs.md
              .sisyphus/reviews/final-f2-codequality.md
  ```

- [x] F3. **End-to-End QA + Artifact Reproduction** — `unspecified-high`
  Start from clean checkout. Run `just reproduce-bench` and `just paper-build`. Execute every QA scenario from every implementation task. Run end-to-end demo at n=128. Run scaling benchmarks at n=512 and n=1024. Verify on-chain verifier works against real folded-proof output (not surrogate hash-chain). Save evidence to `.sisyphus/evidence/final-qa/`.
  Output: `Reproduction [PASS/FAIL] | Scenarios [N/N pass] | E2E n=128 [PASS/FAIL] | Scaling n=1024 [PASS/FAIL] | On-chain verify [PASS/FAIL] | VERDICT`

  **QA Scenarios**:
  ```
  Scenario: f3-clean-clone-reproduce (agent-executable)
    Tool: Bash
    Steps:
      1. bash .sisyphus/scripts/clean-clone-reproduce.sh \
           --target-dir /tmp/pvthfhe-f3-reproduce \
           --evidence-dir .sisyphus/evidence/final-qa/f3-reproduce/
         (script clones repo to clean dir, installs pinned toolchain via REPRODUCING.md,
          runs: just reproduce-bench, just paper-build, just demo-e2e --seed 1,
          just bench-scaling --n 512, just bench-scaling --n 1024, just verify-onchain)
    Expected: script exits 0; produces report f3-reproduce.json with all stages PASS;
              folded-proof artifact at target/folded-proof.bin verified on-chain
              (NOT the surrogate hash-chain — verified by surrogate-retirement-check.py).
    Evidence: .sisyphus/evidence/final-qa/f3-reproduce/f3-reproduce.json
              .sisyphus/evidence/final-qa/f3-reproduce/bench-n128.json
              .sisyphus/evidence/final-qa/f3-reproduce/bench-n512.json
              .sisyphus/evidence/final-qa/f3-reproduce/bench-n1024.json
              .sisyphus/evidence/final-qa/f3-reproduce/onchain-verify.log

  Scenario: f3-task-qa-replay (agent-executable)
    Tool: Bash
    Steps:
      1. just final-verification-gate --check f3-task-qa-replay
         (replays every per-task QA scenario from Phase A–D implementation tasks by reading
          the plan, extracting Scenario blocks, executing each, and aggregating results)
    Expected: exit 0; aggregate report shows N/N scenarios pass with zero failures.
    Evidence: .sisyphus/evidence/final-qa/f3-task-qa-replay.json

  Scenario: f3-onchain-real-folded-proof (agent-executable, contamination guard)
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/surrogate-retirement-check.py \
           --check on-chain-verifier \
           --reject-pattern 'SHA256.*hash.?chain' \
           --reject-pattern 'HonkVerifier.*surrogate' \
           --target contracts/src/
      2. forge test --root contracts --match-test test_verify_real_folded_proof -vvv
    Expected: surrogate scan exits 0 with zero forbidden-pattern hits; forge test passes.
    Evidence: .sisyphus/evidence/final-qa/f3-onchain-realproof.log
  ```

- [x] F4. **Scope Fidelity + Contamination Check** — `deep`
  For each task: read "What to do", read actual diff (git log/diff between Phase 0 start and Phase E end). Verify 1:1 — everything in spec was built, nothing beyond spec. Check "Must NOT Have" compliance globally. Detect cross-task contamination (Task N touching Task M's files). Detect surrogate API contamination (final design semantic interfaces match Design-phase frozen interfaces, not surrogate shapes). Flag unaccounted changes. Verify FHE backend not replaced, threshold model not changed beyond charter justifications.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Surrogate-API leakage [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

  **QA Scenarios**:
  ```
  Scenario: f4-scope-fidelity (agent-executable)
    Tool: Bash
    Steps:
      1. just final-verification-gate --check f4-contamination
         (runs: python .sisyphus/scripts/scope-fidelity-check.py \
                  --plan .sisyphus/plans/pvthfhe-followon.md \
                  --base-ref $(git merge-base HEAD origin/main) \
                  --head-ref HEAD \
                  --output .sisyphus/evidence/final-qa/f4-scope.json
          which: parses each task's "What to do" + "Must NOT do", maps tasks to file
          ownership, checks every file in git diff is owned by exactly one task, flags
          unaccounted files and cross-task contamination)
    Expected: exit 0; report shows Tasks N/N compliant, Contamination CLEAN, Unaccounted CLEAN.
    Evidence: .sisyphus/evidence/final-qa/f4-scope.json

  Scenario: f4-surrogate-api-leakage (agent-executable)
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/surrogate-retirement-check.py \
           --check api-leakage \
           --frozen-interfaces .sisyphus/design/ \
           --target crates/ contracts/src/ circuits/
         (frozen-interface specs were committed by A.D, B.D, C.D, D.D under
          .sisyphus/design/p{4,1,2,3}/frozen-interface.md; this scan confirms semantic
          interfaces in source match those specs and not surrogate shapes)
    Expected: exit 0; zero forbidden surrogate-shape API patterns detected.
    Evidence: .sisyphus/evidence/final-qa/f4-surrogate-leakage.json

  Scenario: f4-charter-invariants (agent-executable)
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/validate-bundle.py \
           --check charter-invariants \
           --charters docs/governance/program-charter.md \
           --target crates/pvthfhe-fhe/ crates/pvthfhe-aggregator/
         (verifies ONLY program-level invariants declared in program-charter.md:
          FHE backend choice frozen at T4 unchanged; threshold model t=⌊n/2⌋+1 unchanged;
          ≥120-bit security unchanged; abort-with-public-blame intact. Per-problem
          Goal/Non-Goals fidelity is enforced by F1 plan-compliance, not here.)
    Expected: exit 0.
    Evidence: .sisyphus/evidence/final-qa/f4-charter-invariants.json
  ```

- [x] F5. **Paper Readiness Review** — `oracle`
  Read paper draft end-to-end. Verify: claims table is frozen and matches proven theorems; theorem/proof references resolve; figures/tables regenerate from scripts (`just paper-build`); related work refreshed against latest ePrint (within 30 days of review); novelty claims honest (cross-check against P1–P4 novelty memos); artifact appendix complete and reproducible; submission package (PDF + supplementary + artifact) builds clean.
  Output: `Claims [N frozen/N proven] | Refs [N/N resolve] | Figures [PASS/FAIL] | Lit refresh [≤30d] | Artifact appendix [PASS/FAIL] | Submission build [PASS/FAIL] | VERDICT`

  **QA Scenarios**:
  ```
  Scenario: f5-paper-build-and-structure (agent-executable)
    Tool: Bash
    Steps:
      1. just paper-gate
         (invokes: just paper-build → produces paper/main.pdf and supplementary.pdf ;
          python .sisyphus/scripts/validate-pins.py --paper paper/main.tex
            --required-pins claims-table,theorem-inventory,figures,artifact-appendix ;
          python .sisyphus/scripts/validate-prior-art.py --bib paper/bib.bib
            --max-age-days 30 --eprint-check ;
          python .sisyphus/scripts/validate-bundle.py --bundle paper/artifact-appendix.md
            --required-fields reproduce-cmd,toolchain-pins,evidence-paths)
    Expected: exit 0; PDFs exist and are non-empty; pins validator reports zero missing;
              prior-art validator reports max age ≤ 30 days; artifact bundle complete.
    Evidence: .sisyphus/evidence/final-qa/f5-paper-build.log
              paper/main.pdf
              paper/supplementary.pdf
              .sisyphus/evidence/final-qa/f5-pins.json
              .sisyphus/evidence/final-qa/f5-prior-art.json

  Scenario: f5-claims-theorem-crosscheck (agent-executable)
    Tool: Bash
    Steps:
      1. just final-verification-gate --check f5-paper-readiness
         (runs: python .sisyphus/scripts/validate-obligations-schema.py \
                  --claims paper/claims-table.md \
                  --inventory docs/security-proofs/obligations.md \
                  --theorems docs/security-proofs/p4/theorem-inventory.md \
                             docs/security-proofs/p1/theorem-inventory.md \
                             docs/security-proofs/p2/theorem-inventory.md \
                             docs/security-proofs/p3/theorem-inventory.md \
                  --novelty-memos .sisyphus/research/p4/novelty-gap-memo.md \
                                  .sisyphus/research/p1/novelty-memo.md \
                                  .sisyphus/research/p2/novelty-memo.md \
                                  .sisyphus/research/p3/novelty-memo.md \
                  --require-bijection)
    Expected: exit 0; every paper claim maps to exactly one proven theorem and one
              novelty memo; zero orphan claims; zero unproven claims.
    Evidence: .sisyphus/evidence/final-qa/f5-claims-crosscheck.json

  Scenario: f5-internal-and-external-signoffs (human-dependent)
    Tool: Bash
    Steps:
      1. python .sisyphus/scripts/validate-reviewer-memo.py \
           --memos-dir .sisyphus/reviews/paper/internal/ \
           --min-count 3 \
           --required-fields reviewer,date,verdict,sections-reviewed,findings
      2. python .sisyphus/scripts/validate-reviewer-memo.py \
           --memos-dir .sisyphus/reviews/paper/external/ \
           --min-count 1 \
           --required-fields reviewer,affiliation,date,verdict,findings
      3. python .sisyphus/scripts/validate-reviewer-memo.py \
           --memo .sisyphus/reviews/final-f5-oracle.md \
           --required-fields reviewer,date,verdict,findings
      4. for f in .sisyphus/reviews/paper/internal/*.md \
                  .sisyphus/reviews/paper/external/*.md \
                  .sisyphus/reviews/final-f5-oracle.md ; do
           grep -E '^VERDICT:\s*APPROVE\s*$' "$f" || exit 1 ;
         done
    Expected: ≥3 internal memos, ≥1 external memo, F5 oracle memo, all APPROVE.
    Evidence: .sisyphus/reviews/paper/internal/*.md
              .sisyphus/reviews/paper/external/*.md
              .sisyphus/reviews/final-f5-oracle.md
  ```

---

## Commit Strategy

Each task commits independently with conventional-commit messages:
- `research(p4): ...` `design(p4): ...` `impl(p4): ...`
- `research(p1): ...` etc.
- `paper: ...` for shadow writing track
- `gov: ...` for Phase 0 governance
- `gate(p4-rg): ...` for gate evidence captures

Pre-commit hooks: per-task `cargo test`, `cargo clippy`, `forge test --root contracts` (for contracts changes), `just <relevant-gate>` (for gate-evidence commits).

---

## Success Criteria

### Verification Commands
```bash
just phase0-gate          # Governance preamble + shadow writing scaffold
just p4-research-gate     # P4 Research Gate evidence
just p4-design-gate       # P4 Design Gate evidence
just p4-impl-gate         # P4 Implementation Gate evidence (real Hermine PVSS)
just p1-research-gate     # P1 Research Gate
just p1-design-gate       # P1 Design Gate
just p1-impl-gate         # P1 Implementation Gate (real lattice NIZK)
just p2-research-gate     # P2 Research Gate
just p2-design-gate       # P2 Design Gate (incl. unified-paper decision)
just p2-impl-gate         # P2 Implementation Gate (real folding scheme)
just p3-research-gate     # P3 Research Gate
just p3-design-gate       # P3 Design Gate
just p3-impl-gate         # P3 Implementation Gate (real on-chain verifier)
just paper-gate           # Phase E paper readiness
just final-verification-gate  # F1–F5 evidence + user-okay capture
```

### Final Checklist
- [x] Phase 0 governance preamble + shadow writing track scaffold committed
- [x] All 12 problem gates passed (4 problems × 3 gates each)
- [x] All 3 downstream contract bundles published
- [x] All four surrogates replaced with real constructions
- [x] Unified paper (or explicit split-paper decision recorded at end of P2 Design) submitted-ready
- [x] All security theorems stated, proven, externally reviewed
- [x] F1–F5 all APPROVE
- [x] User explicitly oks completion
