# Publicly Verifiable Threshold FHE with Sub-Quadratic Scaling (PVTHFHE)

## TL;DR

> **Quick Summary**: Greenfield Rust + Noir research project to design and implement a publicly verifiable threshold FHE scheme that scales to committees of n=1024 with O(n) per-party work and **O(polylog n)** on-chain verification — orders of magnitude better than the O(n²) state of the art (eprint 2024/1285).
>
> **Three gated phases**: (1) Research → 2-3 candidate architectures with formal pseudocode, security games, and micro-benchmarks; (2) Design → select winner, freeze parameters/proof boundary/API, close noise budget, theorems + assumption mapping; (3) Implementation → end-to-end demo at n=128, scaling benchmarks to n=1024, BB-generated Solidity on-chain verifier deployed to local EVM.
>
> **Deliverables**:
> - Phase 1: lit survey, threat model + assumptions ledger, 3 candidate architecture memos with pseudocode + security games + cost tables, micro-benchmarks of building blocks (RLWE-in-Noir, recursive folding, KZG batches), bootstrapping-PV go/no-go memo, backend (Poulpy vs fhe.rs) selection memo, gated `just phase1-gate` report
> - Phase 2: architecture selection, full protocol spec for keygen + threshold decrypt, RLWE parameter set with estimator artifact, noise-budget closure proof, security theorems with assumption mapping, frozen proof boundary, Enclave-compatible API spec, reference-model worked example, Oracle security review, gated `just phase2-gate` report
> - Phase 3: Cargo workspace, FHE backend abstraction + chosen impl, distributed keygen, threshold decryption, Noir circuits, recursive aggregation, Solidity verifier deployed to local Anvil, CLI, n=128 e2e demo, scaling benchmarks to n=1024, adversarial test suite, Enclave adapter interface, gated `just phase3-gate` report
>
> **Estimated Effort**: XL (open-ended; multi-month). Gated milestones; user can pause between phases.
> **Parallel Execution**: YES — 12 waves (R0, R1, R2, R3, D1, D2, D3, I1, I2, I3, I4, FINAL)
> **Critical Path**: T1 → R1 → R2 → T15/T16 (Phase 1 gate) → T17 → D2 → D3 (Phase 2 gate) → I1 → I2 → I3 (Phase 3 gate) → FINAL → user okay

---

## Context

### Original Request
Develop a research plan, then design, and ultimately implement, a publicly verifiable threshold FHE scheme with dramatically better scaling properties than O(n²). Must be maliciously secure, publicly verifiable, no trusted hardware/dealer. Practical for committees in the thousands. Resources: paperclip MCP, eprint 2024/1285 (PV threshold BFV baseline), gnosisguild/enclave/circuits (reference impl), eprint 2024/263 (silent-setup BLS as scaling lodestar). Eventually used with The Interfold (gnosisguild/enclave).

### Interview Summary
**Confirmed**:
- Plan structure: ONE plan, three gated phases (Research → Design → Implementation)
- Scaling: O(n) per-party work, O(polylog n) public verifier
- n = 1024 benchmark target
- Adversary: malicious; **threshold/corruption inconsistency flagged — see Decisions Needed**
- FHE post-quantum (lattice); verifier need not be PQ (Noir + Barretenberg, BN254/Grumpkin)
- Setup: transparent preferred; KZG-style universal acceptable
- Stack: Rust + (Poulpy ‖ Gnosis-Guild fhe.rs fork) + Noir + BB → Solidity
- PV scope: keygen + threshold decryption mandatory; bootstrapping/eval-keys gated stretch (Phase 1 go/no-go)
- Strict TDD across all layers (incl. circuits)
- 2-3 candidate architectures compared in Phase 1; Phase 2 selects
- Time horizon: open-ended

### Research Findings (Background Librarian Survey)
**Building blocks confirmed in literature**:
- Lattice ThFHE from MLWE: eprint 2025/409 (poly-short shares, Shamir-compatible)
- First non-interactive lattice PVSS: eprint 2025/901 (VC + lin-enc framework)
- Lattice polynomial commitments: SLAP (2023/1469), Greyhound (2024/1293, O(√n) verifier)
- Lattice folding: LatticeFold (2024/257), LatticeFold+ (2025/247), Lova (2024/1964)
- Multi-folding aggregation: HyperNova (2023/573)
- Compressed on-chain verification: MicroNova (2024/2099)
- Linear-RLK BFV: ℓ-BFV (2024/1285)
- Noise control: BGG+18 binary LSSS, BS23 Rényi smudging, knLWE caveats (PS25 = 2024/1984)

**Open problems we may need to attack**:
- Lattice NIZK for hint well-formedness (a hinTS analog over RLWE is open)
- Efficient Noir-circuit encoding of RLWE statements
- Malicious-secure noise control at n=1024

**Three architecture candidates surfaced**:
- (A) Silent-setup paradigm port to lattice — biggest payoff, biggest risk
- (B) Lattice PVSS + tree-of-folded-SNARKs (LatticeFold+ / HyperNova) + MicroNova on-chain compression — most de-risked
- (C) Hybrid: lattice-native proofs recursively wrapped in a Noir/BB outer proof for cheap EVM verification

### Metis Review (Gaps Addressed)
Metis flagged: corruption-model inconsistency (**RESOLVED by user pre-T2: honest-majority threshold, t = ⌊n/2⌋+1, secrecy against any coalition <t, abort-with-public-blame** — locked across all downstream tasks); silent-claim-weakening risk (mitigated by explicit "no downgrade" guardrails); missing assumptions ledger (added); missing noise-budget closure gate (added); missing machine-readable gate artifacts (added: `just phaseN-gate`); scope-creep list (codified below); negative-result acceptable as gated outcome (codified); literature refresh discipline (added at end-Phase-1 and pre-Design); Oracle architecture review (added before Design freeze); disposable Phase-1 prototypes rule (added).

---

## Work Objectives

### Core Objective
Produce — at publication-grade rigor — a novel publicly verifiable threshold FHE scheme that achieves **O(n) per-party work and O(polylog n) on-chain public verification** under malicious adversaries, with a working Rust/Noir prototype at n=1024 and a deployed Solidity verifier on local EVM.

### Concrete Deliverables
- `.sisyphus/research/` — annotated bibliography, threat model, assumptions ledger, 3 candidate architecture memos with formal pseudocode + security games, cost-model table (n ∈ {128, 256, 512, 1024}), bootstrapping-PV go/no-go memo, backend selection memo, micro-benchmark harness + reports, Phase-1 gate report
- `.sisyphus/design/` — winning architecture selection memo, full protocol spec, RLWE parameter file (estimator-backed), noise-budget closure document, security theorems + assumption mapping, frozen proof boundary, Enclave-compatible API spec, reference-model worked example, Oracle review record, Phase-2 gate report
- `crates/` — Rust workspace: `pvthfhe-core` (protocol), `pvthfhe-fhe` (backend trait + concrete impl), `pvthfhe-circuits` (Noir circuit interface), `pvthfhe-aggregator` (recursive aggregation), `pvthfhe-cli` (binary), `pvthfhe-bench` (benchmarks)
- `circuits/` — Noir circuit sources for share well-formedness and decryption-share correctness, with `nargo test` golden vectors
- `contracts/` — BB-generated Solidity verifier, deployment scripts, on-chain integration tests (Foundry)
- `examples/` — runnable n=128 e2e demo, scaling benchmark scripts
- `docs/` — README, ARCHITECTURE.md, SECURITY.md, REPRODUCING.md
- `Justfile` — `just phase1-gate`, `just phase2-gate`, `just phase3-gate`, `just bench-scaling`, `just demo-e2e`, `just verify-onchain`

### Definition of Done
- [ ] `just phase1-gate` exits 0 with a Phase-1 gate report (markdown + JSON) certifying ≥2 viable candidates
- [ ] `just phase2-gate` exits 0 with a Phase-2 gate report (markdown + JSON) certifying noise budget closed, parameter set frozen, theorems + assumptions mapped, proof boundary frozen
- [ ] `just phase3-gate` exits 0 with a Phase-3 gate report verifying e2e demo at n=128, scaling benchmarks up to n=1024, on-chain verifier success on local Anvil, all malicious/negative tests passing
- [ ] All code in workspace passes `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `nargo test` (where applicable), `forge test` (Solidity)
- [ ] All claims in security memos map to assumptions in `assumptions-ledger.md`
- [ ] Reproducibility verified: `just reproduce-bench` runs on a clean machine and reproduces the published numbers within ±15%

### Must Have
- ONE concrete protocol with O(n) per-party work AND O(polylog n) on-chain verification, OR a publication-quality negative-result report explaining why the candidates fail (this is an acceptable Phase-1 termination)
- Malicious security under **honest-majority threshold** corruption model: t = ⌊n/2⌋+1, secrecy holds against any coalition of strictly fewer than t parties, reconstruction requires ≥t honest parties; abort-with-public-blame on cheating
- Public verifiability of (a) threshold-public-key generation transcript, (b) threshold decryption (every partial decryption + aggregation) — both verifiable by any external observer with no committee membership
- Lattice-based FHE (post-quantum confidentiality)
- BB-generated Solidity verifier deployed to local EVM, and the verifier must accept a valid threshold-decryption proof and reject every adversarial proof in the test suite
- Noise-budget closure document showing the FHE remains correct for the targeted minimum workload (see "Min FHE bar" default below)
- Assumptions ledger that every theorem reduces to (MLWE / SIS / KZG / ROM-or-QROM / AGM / Fiat-Shamir)
- Strict TDD: every algorithmic component has a RED test before implementation
- Agent-executed QA scenarios for every implementation task

### Must NOT Have (Guardrails)
**Scope guardrails (out of scope for this plan; explicit non-goals):**
- Adaptive corruption (static malicious only — see resolved model)
- Proactive key refresh / resharing
- Dynamic committee membership / churn
- CCA transforms or full active ciphertext robustness beyond what mandatory PV gives us
- Accountability / on-chain slashing logic
- Production-grade distributed networking layer (we'll simulate in-process or use a thin point-to-point harness)
- Multiple proving backends (Noir+BB only; LatticeFold+ etc. are micro-benchmarked, not productized)
- Multiple FHE backends in production (one chosen in Phase 1; the trait abstraction is a thin adapter, NOT a "framework")
- Formal machine-checked proofs (paper-style proof sketches only)
- GPU/SIMD/distributed prover optimization (CPU baseline is sufficient)
- Bootstrapping PV in implementation phase **unless** Phase-1 go/no-go memo greenlights it AND it does not delay mandatory scope

**Anti-claim-weakening guardrails (silent downgrade is FORBIDDEN):**
- "Publicly verifiable" must mean "any external observer can verify with no committee credentials" — never silently weakened to "committee-verifiable"
- "FHE" must mean at minimum the Min-FHE-bar default below — never silently weakened to threshold PKE labeled "FHE"
- "Polylog on-chain verification" includes calldata, gas, and proof size — never measured in only one dimension
- "Malicious security" means static malicious with rushing adversary against authenticated broadcast — never silently weakened to semi-honest in any subprotocol

**Implementation guardrails:**
- No hand-rolled crypto primitives (NTT, transcript hash, hash-to-field, RNG, serialization) where standard implementations exist
- No parameter choices without an estimator-backed rationale committed to `parameters.toml`
- No benchmark claims without fixed environment metadata (CPU model, RAM, threads, compiler flags, backend version, fixed seeds) committed alongside results
- No security theorem claims without explicit assumption mapping
- No recursive proof work until base statement cost is benchmarked
- No Enclave integration code beyond an interface adapter; no PRs to gnosisguild/enclave under this plan
- No "frameworkization" — exactly one chosen architecture is implemented after Phase 2
- No "general threshold cryptography library" — we are building a research artifact for one scheme
- No premature optimization — correctness + asymptotic correctness first, constants later
- No `as any`/`unwrap`-as-error-handling/empty catches/console-prints in production paths
- No proc-macros that hide cryptographic logic
- No commented-out code, dead code, or generic name pollution (`data`, `result`, `tmp`, `Manager`, `Helper`)

### Defaults Applied (override at any time before Phase 1 gate)
- **Min-FHE bar**: BFV/CKKS supporting at minimum **1 multiplicative depth** + arbitrary additions over packed ciphertexts, parameters chosen for plaintext modulus suitable for typical Enclave workloads (booleans/small ints). Confirms at noise-budget closure.
- **On-chain verifier budget**: target ≤ 5,000,000 gas on Ethereum mainnet for a single threshold-decryption verification (typical Groth16/PLONK ceiling); hard ceiling 10,000,000.
- **Adversary model**: static malicious with rushing, authenticated point-to-point + authenticated echo-broadcast (Bracha or equivalent) emulated in-process for the prototype.
- **Liveness/robustness**: abort-with-public-blame; no mandatory robustness; honest re-run after blame attribution.
- **Benchmark methodology**: single-machine simulation with parties as in-process tasks; per-party network cost measured in bytes-on-the-wire and reported separately; n=1024 distributed-cluster benchmark is a stretch goal.
- **Publication target**: ePrint preprint + engineering artifact; not committing to top-tier venue submission within this plan.

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** — every acceptance criterion is agent-executable. No "manually confirm".

### Test Decision
- **Infrastructure exists**: NO — greenfield repo. Test infrastructure setup is part of T1 / I1.
- **Automated tests**: STRICT TDD across all layers. Every implementation task is RED → GREEN → REFACTOR.
- **Frameworks**:
  - Rust: `cargo test` + `cargo nextest` for parallelism + `proptest` for property tests + `criterion` for benchmarks
  - Circuits: `nargo test` (Noir's native test framework) + golden vectors from a reference Rust implementation
  - Solidity: `forge test` (Foundry) + on-chain integration tests against local Anvil
  - Cross-system: `just` recipes orchestrate cross-language tests
- **TDD pattern**: each task includes a RED test commit (failing) before the GREEN implementation commit

### QA Policy
Every implementation task includes **agent-executed QA scenarios** with concrete tools + selectors + data + assertions + evidence paths. Evidence written to `.sisyphus/evidence/task-{N}-{slug}.{ext}`.
- **Rust library/CLI**: `Bash` runs `cargo test ... -- --nocapture`, REPL-style `cargo run --bin pvthfhe-cli ...`, asserts exact output
- **Noir circuits**: `Bash` runs `nargo test` (in-Noir tests) and the **canonical proving flow**: `nargo execute --package <pkg>` to produce `target/<pkg>.gz` witness + `target/<pkg>.json` ACIR, then `bb prove --scheme ultra_honk -b target/<pkg>.json -w target/<pkg>.gz -o target` to produce `target/proof` + `target/public_inputs`, then `bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs` (vk pre-computed via `bb write_vk --scheme ultra_honk -b target/<pkg>.json -o target`). Asserts (a) `nargo execute` exit 0, (b) `bb verify` exit 0 for honest witness, (c) `bb verify` exit ≠ 0 (or `nargo execute` exit ≠ 0) for tampered witness, (d) proof bytes match committed golden where applicable. **NEVER use `nargo prove` or `nargo verify`** — those subcommands were removed from Noir; the canonical post-removal flow is `nargo execute` + `bb {prove,verify,write_vk}`. `bb` CLI is installed via `bbup` in T1's bootstrap and pinned in `AGENTS.md`/`Dockerfile.quickstart`.
- **Solidity verifier**: `Bash` runs `anvil` + `forge script`/`cast call`, asserts on-chain return values and emitted events
- **Benchmarks**: `Bash` runs `cargo bench` and `just bench-scaling`, asserts numbers within ±15% of recorded baselines and produces `bench-{n}.json` artifacts
- **Negative/adversarial tests**: malformed shares, tampered proofs, wrong randomness, out-of-range secrets — must FAIL verification

### Phase Gate Commands (machine-readable)
- `just phase1-gate` — runs all Phase-1 checks; emits `.sisyphus/research/phase1-gate.json` and `.sisyphus/research/phase1-gate.md`; exits non-zero if any criterion fails
- `just phase2-gate` — runs all Phase-2 checks; emits `.sisyphus/design/phase2-gate.json` and `.sisyphus/design/phase2-gate.md`
- `just phase3-gate` — runs all Phase-3 checks; emits `.sisyphus/evidence/phase3-gate.json` and `.sisyphus/evidence/phase3-gate.md`

---

## Execution Strategy

### Parallel Execution Waves

```
Wave R0 (Phase 1 prep — sequential, BLOCKS everything):
└── T1: Repo bootstrap + Justfile + CI skeleton + AGENTS.md [quick]

Wave R1 (Phase 1 fan-out — after T1):
├── T2: Threat model + assumptions ledger [writing]
├── T3: Deep literature survey memo [writing]
├── T4: Backend selection memo (Poulpy vs fhe.rs Gnosis fork) [deep]
├── T5: Micro-bench harness scaffold [unspecified-high]
├── T6: Bootstrapping-PV feasibility scan + go/no-go memo [deep]
└── T7: Cost-model template (asymptotic + concrete tables) [writing]

Wave R2 (Phase 1 architecture work — after R1):
├── T8: Candidate Architecture A (silent-setup port) — pseudocode + security game + cost analysis [ultrabrain]
├── T9: Candidate Architecture B (lattice PVSS + folding + MicroNova) — pseudocode + security game + cost analysis [ultrabrain]
├── T10: Candidate Architecture C (hybrid Noir wrapper) — pseudocode + security game + cost analysis [ultrabrain]
├── T11: Micro-bench RLWE-relation in Noir/BB [deep]
├── T12: Micro-bench recursive folding (HyperNova-style) [deep]
├── T13: Micro-bench KZG batched verification on EVM [deep]
└── T14: Literature refresh #1 (subagent: librarian, end-Phase-1) [unspecified-low]

Wave R3 (Phase 1 close):
├── T15: Compiled cost table + comparison matrix across A/B/C [writing]
└── T16: Phase 1 gate report — `just phase1-gate` produces JSON + markdown [unspecified-high]

>>> GATE: Phase 1 must pass before Phase 2 starts. Acceptable termination: ≥2 viable candidates, OR negative-result publication path. <<<

Wave D1 (Phase 2 selection — sequential, BLOCKS Phase 2):
└── T17: Architecture selection memo (chooses ONE winner) [ultrabrain]

Wave D2 (Phase 2 spec fan-out — after T17):
├── T18: Full protocol spec — distributed keygen [ultrabrain]
├── T19: Full protocol spec — threshold decryption [ultrabrain]
├── T20: Concrete RLWE parameter selection (estimator-backed) [deep]
├── T21: Noise budget closure analysis [deep]
├── T22: Enclave-compatible API/interface spec [unspecified-high]
└── T23: Reference-model worked example (toy n=4 walkthrough) [deep]

Wave D3 (Phase 2 close):
├── T24: Security theorems + assumption mapping [ultrabrain]
├── T25: Proof boundary freeze (what is in SNARK, what is not) [deep]
├── T26: Oracle architecture & security review (subagent: oracle) [unspecified-high]
├── T27: Literature refresh #2 (subagent: librarian, pre-Implementation) [unspecified-low]
└── T28: Phase 2 gate report — `just phase2-gate` produces JSON + markdown [unspecified-high]

>>> GATE: Phase 2 must pass before Phase 3 starts. Closed noise budget, frozen params, mapped theorems, frozen proof boundary. <<<

Wave I1 (Phase 3 foundation — after D3):
├── T29: Cargo workspace + crate layout + lints + deny.toml + CI matrix [quick]
├── T30: FHE backend trait + chosen-impl wrapper (TDD: RED tests first) [unspecified-high]
├── T31: Cryptographic test-vector harness (golden vectors, property tests) [unspecified-high]
└── T32: Noir + Foundry test harnesses (nargo test runner, forge skeleton) [unspecified-high]

Wave I2 (Phase 3 core — parallel after I1):
├── T33: Distributed keygen impl (TDD, in-process simulator) [ultrabrain]
├── T34: Threshold decryption impl (TDD) [ultrabrain]
├── T35: Noir circuit — share well-formedness (TDD with golden vectors) [ultrabrain]
├── T36: Noir circuit — decryption-share correctness (TDD with golden vectors) [ultrabrain]
├── T37: Recursive aggregation harness (folding tree) [ultrabrain]
└── T38: Solidity verifier scaffold + Foundry tests (TDD) [unspecified-high]

Wave I3 (Phase 3 integration — after I2):
├── T39: BB → Solidity verifier generation + on-chain verification test on local Anvil [unspecified-high]
├── T40: CLI binary + n=128 e2e demo [unspecified-high]
├── T41: Adversarial test suite (malformed shares, tampered proofs, rogue keys) [deep]
├── T42: Enclave-style adapter interface (no upstream PR) [unspecified-high]
├── T43: Scaling benchmark suite up to n=1024 + reproducibility scripts [unspecified-high]
└── T44: Documentation (README, ARCHITECTURE, SECURITY, REPRODUCING) [writing]

Wave I4 (Phase 3 close):
└── T45: Phase 3 gate report — `just phase3-gate` produces JSON + markdown [unspecified-high]

Wave FINAL (after ALL implementation — 4 parallel reviews + user okay):
├── F1: Plan compliance audit [oracle]
├── F2: Code quality + crypto-slop review [unspecified-high]
├── F3: Real manual QA — run every QA scenario from every task, capture evidence [unspecified-high]
└── F4: Scope fidelity check — every diff maps to a task; no creep [deep]
→ Present consolidated results → wait for user explicit "okay"

Critical Path: T1 → T2 → T8/T9/T10 → T15 → T16 → T17 → T18/T19 → T21 → T24 → T28 → T29 → T33/T34 → T37 → T39 → T40 → T43 → T45 → F1-F4 → user okay
Parallel Speedup: very high — most tasks within a wave run concurrently
Max Concurrent: 7 (Wave R2 and I2)
```

### Dependency Matrix (high-level)

| Task | Depends On | Blocks |
|---|---|---|
| T1 | — | All |
| T2-T7 | T1 | R2 |
| T8-T13 | R1 | T15 |
| T14 | T8-T13 | T16 |
| T15-T16 | R2, T14 | T17 (Phase 1 gate) |
| T17 | T16 | D2 |
| T18-T23 | T17 | D3 |
| T24-T27 | D2 | T28 |
| T28 | D3 | I1 (Phase 2 gate) |
| T29-T32 | T28 | I2 |
| T33-T38 | I1 | I3 |
| T39-T44 | I2 | T45 |
| T45 | I3 | FINAL (Phase 3 gate) |
| F1-F4 | T45 | user okay |

### Agent Dispatch Summary

| Wave | Tasks | Categories used |
|---|---|---|
| R0 | T1 | quick |
| R1 | T2-T7 | writing × 2, deep × 2, unspecified-high × 1, writing × 1 |
| R2 | T8-T14 | ultrabrain × 3, deep × 3, unspecified-low × 1 (librarian) |
| R3 | T15-T16 | writing × 1, unspecified-high × 1 |
| D1 | T17 | ultrabrain |
| D2 | T18-T23 | ultrabrain × 2, deep × 3, unspecified-high × 1 |
| D3 | T24-T28 | ultrabrain × 1, deep × 1, unspecified-high × 2 (oracle subagent), unspecified-low × 1 (librarian) |
| I1 | T29-T32 | quick × 1, unspecified-high × 3 |
| I2 | T33-T38 | ultrabrain × 4, unspecified-high × 2 |
| I3 | T39-T44 | unspecified-high × 4, deep × 1, writing × 1 |
| I4 | T45 | unspecified-high |
| FINAL | F1-F4 | oracle, unspecified-high × 2, deep |

---

## TODOs

- [x] 1. **T1: Repo bootstrap + Justfile + CI skeleton + AGENTS.md**

  **What to do**:
  - Initialize Cargo workspace with **all 8 crates as placeholder members from day 1** (root `Cargo.toml`: `resolver = "2"`, `[workspace] members = ["crates/pvthfhe-core", "crates/pvthfhe-fhe", "crates/pvthfhe-circuits", "crates/pvthfhe-aggregator", "crates/pvthfhe-cli", "crates/pvthfhe-bench", "crates/pvthfhe-api", "crates/pvthfhe-enclave-adapter"]`). Each placeholder ships `Cargo.toml` (name + version + edition) + `src/lib.rs` containing one trivial `#[test] fn placeholder() {}` so `cargo test --workspace` is green and `cargo -p <name>` works for every later task. Later tasks (T20, T21, T22, T23, T30, T42, etc.) **add code to the existing crate without creating it**.
  - Create top-level dirs: `crates/`, `circuits/`, `contracts/`, `bench/`, `bench/scripts/`, `bench/results/`, `bench/figures/`, `docs/`, `.sisyphus/research/`, `.sisyphus/research/scripts/`, `.sisyphus/design/`, `.sisyphus/design/scripts/`, `.sisyphus/scripts/`, `.sisyphus/evidence/`, `.sisyphus/evidence/integration/`, `.sisyphus/evidence/final-qa/`.
  - **Scaffold the Noir workspace at `circuits/`**: minimal `circuits/Nargo.toml` workspace declaring **four** placeholder packages — three production circuits (`circuits/share_wf/`, `circuits/decrypt_share/`, `circuits/aggregator_final/`) plus one benchmark-only package (`circuits/bench/rlwe_relation/`) — each with a trivial `main.nr` (`fn main(x: Field) { assert(x == x); }`) and `Nargo.toml` whose `[package].name` matches the leaf directory (snake_case — Noir's idiomatic package naming, which T11/T35/T36/T37 implementations require unchanged). The bench package is structurally identical to the others (Noir doesn't distinguish bench vs production packages); it lives under `circuits/bench/` purely as a directory convention so T11's `Prover_valid.toml`/`Prover_tampered.toml` and bench harness have a home from T1 onward. This lets `nargo test --workspace` (run from `circuits/`) succeed with zero real tests from T1. T11/T32/T35/T36/T37 later replace these placeholders with real circuit code in-place — they MUST NOT rename or recreate the directories or packages. **No further `nargo new` invocations are permitted by any task** (T1 has scaffolded every Noir package the plan ever needs).
  - **Scaffold the Foundry project at `contracts/`**: `contracts/foundry.toml`, `contracts/lib/.gitkeep` (forge-std added in T32), `contracts/src/Placeholder.sol` (`contract Placeholder {}`), `contracts/test/Placeholder.t.sol` (`function test_placeholder() public {}`). This lets `forge test --root contracts` succeed with one trivial test from T1 onward. T32 later adds `forge-std` and replaces placeholders.
  - Add `Justfile` with **stub recipes** for the COMPLETE command surface used anywhere in this plan. Every recipe initially prints `not implemented` and exits 2; the task that needs each one is responsible for replacing the stub with a real implementation (each such task explicitly says "implements (replacing stub from T1)" in its What-to-do):
    * `phase1-gate` (real impl: T16) · `phase2-gate` (T28) · `phase3-gate` (T45)
    * `demo-e2e` (T40) · `bench-scaling` (T43) · `verify-onchain` (T39 — wraps Foundry e2e)
    * `bench-backend-compare` (T4) · `bench-smoke` (T5) · `bench-folding` (T12) · `bench-noir-rlwe` (T11) · `bench-kzg-evm` (T13)
    * `test-all` (T29 — runs `cargo test --workspace` + `nargo test --workspace` from `circuits/` + `forge test --root contracts`) · `test-circuits` (T32) · `test-contracts` (T32)
    * `adversarial-suite` (T41) · `reproduce-bench` (T43 — wraps `bench/scripts/reproduce.sh`)
  - **EXCEPTION**: From T1, three recipes are NOT stubs but trivially-real: `test-all` invokes `cargo test --workspace && (cd circuits && nargo test --workspace) && forge test --root contracts` — this works because T1 ships placeholder crates, placeholder Noir packages, and a placeholder Foundry test. This guarantees T29's CI matrix can pass without depending on T32. T32's job becomes upgrading these placeholders, not introducing them.
  - Add **helper-script stubs** under their canonical directories. Each stub is a Python or Bash file that prints `not implemented` and exits 2; the task that first uses each helper is responsible for replacing the stub. These create the file paths so that QA scenarios in later tasks can reference them, and so that no task has to scaffold directory creation in addition to its own substantive work:
    * `.sisyphus/research/scripts/check-provenance.py` (real impl: T15)
    * `.sisyphus/scripts/check-rubric.py` (T17) · `.sisyphus/scripts/check-wire-format.py` (T18) · `.sisyphus/scripts/check-no-sk-in-verifier.py` (T19) · `.sisyphus/scripts/check-theorem-mapping.py` (T24) · `.sisyphus/scripts/check-boundary-coverage.py` (T25) · `.sisyphus/scripts/check-oracle-dispositions.py` (T26) · `.sisyphus/scripts/check-abi.py` (T38) · `.sisyphus/scripts/phase1-gate.py` (T16) · `.sisyphus/scripts/phase2-gate.py` (T28) · `.sisyphus/scripts/phase3-gate.py` (T45)
    * `.sisyphus/design/scripts/rerun-estimator.sh` (T20)
    * `bench/scripts/fit-loglog.py` (T12) · `bench/scripts/check-tolerance.py` (T43) · `bench/scripts/compare-predictions.py` (T43) · `bench/scripts/reproduce.sh` (T43) · `.sisyphus/scripts/check-bench-variance.py` (real impl: T4; T5 also consumes it)
  - Add a `.sisyphus/scripts/_stub.py` helper that writes a no-op stub matching the spec above; T1 calls it once per script to materialize all stubs in one shot.
  - Add `.github/workflows/ci.yml`: matrix runs `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `nargo test --workspace` (from `circuits/`), `forge test --root contracts`, markdown lint. All jobs pass on the placeholder content; T29 only adds beta toolchain + macOS lane + `cargo deny`.
  - Add `AGENTS.md` documenting: project intent, where research/design/code/evidence go, gate commands, TDD policy, draft-vs-plan distinction, allowed FHE backends, **the stub-replacement protocol** (later tasks must replace stubs, never delete-and-recreate, so git history is preserved), **the working-directory protocol for QA scenarios** (Foundry commands always use `--root contracts` from repo root; Nargo commands always run from `circuits/` via `(cd circuits && nargo ...)`; cargo commands run from repo root with `-p <crate>`), **and the toolchain install protocol**: Rust via `rustup` (channel from `rust-toolchain.toml`), Foundry via `foundryup`, Noir via `noirup`, Barretenberg `bb` CLI via `bbup` — with all four versions pinned in `REPRODUCING.md` (authored by T44) and re-installed identically inside `Dockerfile.quickstart` (T44). Document the canonical Noir+BB proving flow (`nargo execute` → `bb write_vk` → `bb prove` → `bb verify`, all `--scheme ultra_honk`) and explicitly forbid `nargo prove`/`nargo verify` (removed from Noir).
  - Add `rust-toolchain.toml` (pin stable + components rustfmt, clippy), `.gitignore`, `LICENSE` placeholder, `cargo deny` config stub.
  - RED commit: workspace + placeholders compile and all three test runners exit 0.

  **Must NOT do**: ship any cryptographic code; pin a single FHE backend (decision deferred to T4); modify upstream Enclave repo; implement any helper or recipe with real logic in T1 EXCEPT the trivially-real `test-all` recipe described above; have any later task re-create a crate, Noir package, or Foundry project from scratch (they all only ADD files to T1's scaffolding).

  **Recommended Agent Profile**:
  - **Category**: `quick` — pure scaffolding, no design judgement.
  - **Skills**: `git-master` (atomic commits per file group).
  - **Skills Evaluated but Omitted**: `frontend-ui-ux` (no UI), `playwright` (no browser), `ai-slop-remover` (no code yet).

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave R0 (sequential, BLOCKS everything)
  - **Blocks**: T2-T45
  - **Blocked By**: None — can start immediately

  **References**:
  - Pattern: `https://github.com/casey/just` — Justfile syntax.
  - Pattern: `https://github.com/EmbarkStudios/cargo-deny` — deny.toml example.
  - External: `https://github.com/gnosisguild/enclave/blob/main/AGENTS.md` (if present) — house style for AGENTS.md.

  **Acceptance Criteria**:
  - [ ] `cargo check --workspace` exits 0 with all 8 placeholder crates listed in `cargo metadata`
  - [ ] `cargo test --workspace` exits 0 (8 placeholder tests pass)
  - [ ] `(cd circuits && nargo test --workspace)` exits 0 (4 placeholder Noir packages: share_wf, decrypt_share, aggregator_final, bench/rlwe_relation; zero failing tests)
  - [ ] `forge test --root contracts` exits 0 (1 placeholder test passes)
  - [ ] `just --list` enumerates all 16 recipes specified in What-to-do
  - [ ] `just test-all` exits 0 (runs the trivially-real composite recipe described in What-to-do)
  - [ ] `cargo pkgid -p pvthfhe-core` succeeds (proves crate is workspace-resolvable from day 1; same for pvthfhe-bench, pvthfhe-api, pvthfhe-fhe, pvthfhe-circuits, pvthfhe-aggregator, pvthfhe-cli, pvthfhe-enclave-adapter — all 8 must resolve)
  - [ ] `cargo fmt --check` exits 0
  - [ ] `cargo clippy --workspace -- -D warnings` exits 0
  - [ ] CI green on first push

  **QA Scenarios**:
  ```
  Scenario: Fresh clone bootstraps cleanly with all three test runners
    Tool: Bash
    Preconditions: clean shell, Rust stable + Foundry + Noir + Barretenberg `bb` CLI installed (T1's `AGENTS.md` documents `bbup` install + pinned version; `bb` is required for any task touching Noir proving — T11/T35/T36/T37/T39 — but the T1 bootstrap scenario only needs `nargo test --workspace` against the placeholder packages, which does NOT invoke `bb`)
    Steps:
      1. `git clone . /tmp/pvthfhe-bootstrap-test`
      2. `cargo check --workspace --manifest-path /tmp/pvthfhe-bootstrap-test/Cargo.toml 2>&1 | tee /tmp/bootstrap-cargo.log`
      3. `cargo test --workspace --manifest-path /tmp/pvthfhe-bootstrap-test/Cargo.toml 2>&1 | tee -a /tmp/bootstrap-cargo.log`
      4. `(cd /tmp/pvthfhe-bootstrap-test/circuits && nargo test --workspace) 2>&1 | tee /tmp/bootstrap-nargo.log`
      5. `forge test --root /tmp/pvthfhe-bootstrap-test/contracts 2>&1 | tee /tmp/bootstrap-forge.log`
      6. `just --justfile /tmp/pvthfhe-bootstrap-test/Justfile --list 2>&1 | tee /tmp/bootstrap-just.log`
    Expected Result: every command exits 0; `just --list` shows all 16 recipes from the What-to-do (phase1-gate, phase2-gate, phase3-gate, demo-e2e, bench-scaling, verify-onchain, bench-backend-compare, bench-smoke, bench-folding, bench-noir-rlwe, bench-kzg-evm, test-all, test-circuits, test-contracts, adversarial-suite, reproduce-bench)
    Failure Indicators: missing recipe; compile error; `cargo pkgid -p <crate>` rejects any of the 8 crates; nargo or forge cannot find Nargo.toml/foundry.toml
    Evidence: .sisyphus/evidence/task-1-bootstrap-cargo.log, .sisyphus/evidence/task-1-bootstrap-nargo.log, .sisyphus/evidence/task-1-bootstrap-forge.log, .sisyphus/evidence/task-1-bootstrap-just.log

  Scenario: Every crate is `cargo -p` reachable from day 1
    Tool: Bash
    Steps:
      1. `for c in pvthfhe-core pvthfhe-fhe pvthfhe-circuits pvthfhe-aggregator pvthfhe-cli pvthfhe-bench pvthfhe-api pvthfhe-enclave-adapter; do cargo metadata --format-version=1 --no-deps | jq -e --arg n "$c" '.packages | map(.name) | index($n)' || exit 1; done`
    Expected Result: exit 0 (every crate name found by jq)
    Evidence: .sisyphus/evidence/task-1-crates.log

  Scenario: just test-all is trivially-real (NOT a stub)
    Tool: Bash
    Steps:
      1. `just test-all 2>&1 | tee /tmp/test-all.log`
      2. `! grep -E 'not implemented' /tmp/test-all.log`
    Expected Result: exit 0; "not implemented" not found
    Evidence: .sisyphus/evidence/task-1-test-all.log

  Scenario: Stub recipes correctly fail when not yet implemented
    Tool: Bash
    Preconditions: T1 complete, no later task implementation yet
    Steps:
      1. `for r in phase1-gate phase2-gate phase3-gate demo-e2e bench-scaling verify-onchain bench-backend-compare bench-smoke bench-folding bench-noir-rlwe bench-kzg-evm test-circuits test-contracts adversarial-suite reproduce-bench; do (just "$r" 2>&1; echo "::exit=$?::") | tee -a /tmp/stubs.log; done`
      2. `[ "$(grep -c '::exit=2::' /tmp/stubs.log)" = "15" ]`
    Expected Result: every stub recipe prints "not implemented" and exits 2; total of 15 stubs (excludes test-all)
    Evidence: .sisyphus/evidence/task-1-gate-stub.log
  ```

  **Commit**: YES (groups alone)
  - Message: `chore(repo): bootstrap workspace, 8 crate placeholders, 4 noir packages, foundry scaffold, justfile, CI, AGENTS.md`
  - Files: `Cargo.toml`, `Justfile`, `.github/workflows/ci.yml`, `AGENTS.md`, `rust-toolchain.toml`, `.gitignore`, `deny.toml`, `LICENSE`, `crates/**`, `circuits/Nargo.toml`, `circuits/share_wf/**`, `circuits/decrypt_share/**`, `circuits/aggregator_final/**`, `circuits/bench/rlwe_relation/**`, `contracts/foundry.toml`, `contracts/src/Placeholder.sol`, `contracts/test/Placeholder.t.sol`, `contracts/lib/.gitkeep`, `.sisyphus/scripts/_stub.py`, `.sisyphus/scripts/check-*.py`, `.sisyphus/research/scripts/check-provenance.py`, `.sisyphus/design/scripts/rerun-estimator.sh`, `bench/scripts/*`
  - Pre-commit: `cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace && (cd circuits && nargo test --workspace) && forge test --root contracts`

- [x] 2. **T2: Threat model + assumptions ledger**

  **What to do**:
  - Author `.sisyphus/research/threat-model.md`: adversary class (static malicious, rushing, authenticated echo-broadcast, abort-with-public-blame), corruption budget **(LOCKED: honest-majority threshold, t = ⌊n/2⌋+1, secrecy against any coalition of strictly fewer than t parties, reconstruction requires ≥t honest parties)**, network model, identity assumption (PKI), liveness/safety split.
  - Author `.sisyphus/research/assumptions-ledger.md` enumerating every cryptographic assumption with: name, formal statement, parameter regime, what breaks if violated, replacement candidates. Cover: RLWE (decision/search), Module-LWE/SIS, knLWE (PS25), DDH-on-Grumpkin (verifier), KZG (if used), random oracle / standard model boundary, NIZK soundness, FS transcript hygiene.
  - Cross-link every assumption to which task/architecture relies on it.
  - **Corruption model is LOCKED** (resolved by user pre-T2): all downstream tasks (T8/T9/T10/T17/T18/T19/T24) MUST assume honest-majority threshold semantics. Any architecture proposing a different model in T8/T9/T10 must explicitly justify and seek user re-approval.

  **Must NOT do**: invent new assumptions; weaken or strengthen the locked corruption model without user re-approval; use vague phrasing like "standard assumptions".

  **Recommended Agent Profile**:
  - **Category**: `writing` — formal prose with cryptographic precision.
  - **Skills**: none required.
  - **Skills Evaluated but Omitted**: `git-master` (single doc commit).

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R1 with T3, T4, T5, T6, T7
  - **Blocks**: T8, T9, T10, T15, T16, T24
  - **Blocked By**: T1

  **References**:
  - Pattern: ePrint 2024/1285 §2 (threat model section style).
  - Pattern: ePrint 2024/263 §3 (assumption enumeration).
  - External: Canetti UC framework primer; Lindell tutorial on simulation-based proofs.

  **Acceptance Criteria**:
  - [ ] `threat-model.md` covers all 6 axes (adversary, corruption, network, identity, liveness, abort)
  - [ ] Threat-model corruption section explicitly states honest-majority threshold (t = ⌊n/2⌋+1) with formal secrecy/reconstruction predicates
  - [ ] `assumptions-ledger.md` lists ≥8 assumptions, each with all 5 fields
  - [ ] Every assumption tagged with task/architecture references
  - [ ] No `[DECISION NEEDED]` blocks remain in either file

  **QA Scenarios**:
  ```
  Scenario: Ledger completeness + corruption-model lock
    Tool: Bash
    Preconditions: T2 complete
    Steps:
      1. `grep -c '^## ' .sisyphus/research/assumptions-ledger.md`
      2. `grep -c 'Formal statement:' .sisyphus/research/assumptions-ledger.md`
      3. `grep -n 'DECISION NEEDED' .sisyphus/research/threat-model.md .sisyphus/research/assumptions-ledger.md || echo "OK: no decisions pending"`
      4. `grep -E 'honest-majority|t = .n/2.+1|⌊n/2⌋\\+1' .sisyphus/research/threat-model.md`
    Expected Result: ≥8 assumption sections, ≥8 formal-statement lines, "OK: no decisions pending", at least one honest-majority match
    Evidence: .sisyphus/evidence/task-2-ledger-check.log
  ```

  **Commit**: YES (alone)
  - Message: `docs(research): threat model + assumptions ledger`
  - Files: `.sisyphus/research/threat-model.md`, `.sisyphus/research/assumptions-ledger.md`
  - Pre-commit: markdown-lint

- [x] 3. **T3: Deep literature survey memo**

  **What to do**:
  - Author `.sisyphus/research/lit-survey.md` covering ≥15 papers grouped by theme. **Citation-verification protocol**: for every ePrint ID below, BEFORE writing any survey entry, fetch `https://eprint.iacr.org/<id>` and confirm the title/abstract matches the claimed topic; record the verified `(id, title, year, authors, topic-bucket)` tuple in `.sisyphus/research/citations.bib` with field `verified: true`. If a candidate ID does not match its claimed topic, mark `verified: false`, leave it out of the survey, and search ePrint by topic keywords to find the correct ID; record that as the replacement. The candidate IDs below are starting points from the requirements interview, NOT pre-verified facts.
    - Themes and candidate IDs to verify:
      (a) **PV / silent-setup / publicly-verifiable threshold FHE**: `2024/1285`, `2024/263`, `2025/409`, `2025/901` — verify each; if any is mis-bucketed (e.g., `2024/1285` is actually robust-RLWE-threshold-MPC rather than silent-setup ThFHE), demote to its true bucket and find the correct PV-ThFHE ID.
      (b) **PVSS / NIDKG**: `BGG+18`, `BS23`, plus T14-discovered IDs. **Do NOT include `2023/1469` here** — SLAP is a lattice PCS, not a PVSS scheme.
      (c) **Lattice PCS**: SLAP `2023/1469`, Greyhound `2024/1293`.
      (d) **Folding/recursion**: LatticeFold `2024/257`, LatticeFold+ `2025/247`, Lova `2024/1964`, HyperNova `2023/573`, MicroNova `2024/2099`.
      (e) **Noise-aware threshold variants**: knLWE PS25 `2024/1984`. (`ℓ-BFV from 2024/1285` is dropped pending verification — if the verified topic of `2024/1285` is not ℓ-BFV, find the correct source.)
  - Per paper record: scaling profile (per-party + verifier), assumptions, malicious-secure?, transparent-setup?, PQ?, on-chain feasibility, known limitations, open problems we could attack.
  - Synthesize: comparison table; identify 3 candidate-architecture seeds (A/B/C) explicitly tied to clusters.
  - Use `paperclip` MCP / librarian agent to fetch & verify abstracts; cite ePrint IDs verbatim.

  **Must NOT do**: paraphrase abstracts as fact; cite without ePrint ID; conflate "publicly verifiable" with "publicly auditable"; skip negative results.

  **Recommended Agent Profile**:
  - **Category**: `writing` — synthesis-heavy prose.
  - **Skills**: none.
  - **Subagent dispatch**: `librarian` for fact-checking citations.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R1
  - **Blocks**: T8, T9, T10, T15
  - **Blocked By**: T1

  **References**:
  - Background results from session `ses_219cc8829ffeU6rKzA0OdZ5vEI` (librarian survey).
  - All ePrint IDs listed in Active Working Context.

  **Acceptance Criteria**:
  - [ ] ≥15 papers covered with full metadata table
  - [ ] Comparison table at end (rows=papers, columns=8 axes)
  - [ ] 3 architecture seeds documented with rationale
  - [ ] Every claim cites specific paper §
  - [ ] Bibliography section with stable ePrint URLs

  **QA Scenarios**:
  ```
  Scenario: Citation integrity
    Tool: Bash
    Preconditions: T3 complete
    Steps:
      1. `grep -oE 'eprint\.iacr\.org/[0-9]{4}/[0-9]+' .sisyphus/research/lit-survey.md | sort -u | wc -l`
      2. `grep -c '^| ' .sisyphus/research/lit-survey.md` (table rows)
    Expected Result: ≥15 unique ePrint URLs; comparison table rows ≥15
    Evidence: .sisyphus/evidence/task-3-citations.log

  Scenario: All cited papers resolve
    Tool: Bash (curl)
    Preconditions: T3 complete, network access
    Steps:
      1. `for url in $(grep -oE 'https://eprint.iacr.org/[0-9]{4}/[0-9]+' .sisyphus/research/lit-survey.md | sort -u); do curl -sI "$url" | head -1; done`
    Expected Result: every URL returns HTTP 200 or 301
    Evidence: .sisyphus/evidence/task-3-resolve.log
  ```

  **Commit**: YES (alone)
  - Message: `docs(research): deep literature survey memo`
  - Files: `.sisyphus/research/lit-survey.md`
  - Pre-commit: markdown-lint, link-check

- [x] 4. **T4: Backend selection memo (Poulpy vs fhe.rs Gnosis fork)**

  **What to do**:
  - Author `.sisyphus/research/backend-selection.md` with side-by-side evaluation of `phantomzone-org/poulpy` vs `gnosisguild/fhe.rs` on axes: schemes supported (BFV/BGV/CKKS/TFHE), API stability, NTT/RNS quality, PRNG hygiene, serialization, no_std/wasm potential, license, maturity (commits, contributors, last release), test coverage, benchmark numbers, threshold-friendliness (does it expose secret-share-friendly key gen?), audit history.
  - **Common-primitive layer for the apples-to-apples benchmark (LOCKED to the lowest common denominator both backends actually expose)**: bench at the **`Rq` polynomial-arithmetic layer** — specifically, NTT forward+inverse, point-wise multiplication, and Number-Theoretic-Transform-based polynomial multiplication, on a fixed degree-`N=4096` ring with a fixed RNS basis (4 × 60-bit moduli, total ~240 bits) at λ=128. Both libraries expose this layer regardless of which higher-level scheme (BFV vs CKKS) they prioritize. Do **NOT** attempt to bench a higher-level scheme that only one backend supports — if one backend lacks BFV `Encrypt`/`Decrypt` and the other lacks CKKS `Encode`, those are recorded as "feature gap" entries on the comparison axes, not as benchmark numbers.
  - **Bench cases (each library implements all 4)**:
    1. `ntt_forward(N=4096, q=q_0)` over 1 RNS limb
    2. `ntt_inverse(N=4096, q=q_0)` over 1 RNS limb
    3. `poly_mul_ntt_domain(N=4096, RNS={q_0..q_3})` — full pointwise + NTT round-trip
    4. `sample_uniform_rq(N=4096, RNS={q_0..q_3})` — RNG + reduction throughput
  - **Adapter contract**: write a thin Rust harness `crates/pvthfhe-bench/src/backends/{poulpy,fhe_rs}.rs` exposing trait `RqOps { fn ntt_fwd(&self, x: &mut [u64]); fn ntt_inv(&self, x: &mut [u64]); fn poly_mul(&self, a: &[u64], b: &[u64], out: &mut [u64]); fn sample_uniform(&self, out: &mut [u64], rng: &mut Rng); }`. If a backend cannot implement one method (e.g., its public API doesn't expose raw NTT), record that as a feature gap and benchmark only the methods both support — the comparison degrades gracefully.
  - **Backend version pinning**: pin Poulpy and `gnosisguild/fhe.rs` by exact commit SHA in `Cargo.toml` (`rev = "..."`). Record both SHAs in the memo. If the resolved adapter trait surface is empty for one backend (zero methods both can implement), declare T4 result = "Poulpy primary by default; fhe.rs fallback at the protocol layer rather than primitive layer" and document that decision rather than emitting empty bench numbers.
  - Run reproducible micro-benchmarks against the pinned commits, on the same hardware; report variance over ≥10 runs.
  - Recommendation: choose one as **primary**, one as **fallback**. Define an `FheBackend` trait (in design phase, T30) so we can swap.
  - Risk register: what would force a switch?

  **Must NOT do**: pick a backend before benchmarks are run; ignore license terms; benchmark on different hardware between backends.

  **Recommended Agent Profile**:
  - **Category**: `deep` — research + measurement + judgement.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R1
  - **Blocks**: T17, T29, T30
  - **Blocked By**: T1, T5 (uses bench harness)

  **References**:
  - github.com/phantomzone-org/poulpy
  - github.com/gnosisguild/fhe.rs
  - SEAL benchmark methodology (`SEAL/native/bench`).

  **Acceptance Criteria**:
  - [ ] Both backends benchmarked at identical security/params
  - [ ] Recommendation justified by ≥3 axes
  - [ ] Fallback plan documented
  - [ ] Pinned commit SHAs recorded

  **QA Scenarios**:
  ```
  Scenario: Reproducibility of bench numbers
    Tool: Bash
    Preconditions: T4 complete, T5 harness available
    Steps:
      1. `just bench-backend-compare > /tmp/run1.log`
      2. `just bench-backend-compare > /tmp/run2.log`
      3. `python3 .sisyphus/scripts/check-bench-variance.py /tmp/run1.log /tmp/run2.log --tolerance 0.15` (helper added by T1 stub-inventory; concrete impl owned by T4: parse JSON-line records `{"case": <str>, "median_ns": <float>}` from each log, compute `abs(m1 - m2) / max(m1, m2)` per case, exit 0 iff every case ≤0.15, else exit 1 listing offending cases)
    Expected Result: median variance ≤15% across runs
    Evidence: .sisyphus/evidence/task-4-bench-repro.log

  Scenario: Memo answers all required axes
    Tool: Bash
    Steps:
      1. `for axis in "schemes" "API" "NTT" "PRNG" "serialization" "license" "threshold" "benchmark"; do grep -qi "$axis" .sisyphus/research/backend-selection.md || echo "MISSING: $axis"; done`
    Expected Result: no MISSING output
    Evidence: .sisyphus/evidence/task-4-axes.log
  ```

  **Commit**: YES
  - Message: `docs(research): backend selection memo (Poulpy vs fhe.rs)`
  - Files: `.sisyphus/research/backend-selection.md`, `bench/backend-compare/**`
  - Pre-commit: bench reproducibility check

- [x] 5. **T5: Micro-bench harness scaffold**

  **What to do**:
  - Create `crates/pvthfhe-bench/` with Criterion-based harness.
  - Define BenchSpec struct: name, n (parties), params, repetitions, warmup, hardware-fingerprint capture (CPU, RAM, kernel via `/proc/cpuinfo`).
  - Implement `bench-runner` binary that produces JSON results to `bench/results/{date}-{git-sha}-{name}.json` with full envelope (mean, median, p99, stddev, n-runs, env).
  - Add `just bench` recipe; integrate with CI on tagged commits only.
  - RED first: failing test that asserts result JSON has all envelope fields.

  **Must NOT do**: hide variance; bench in `--release` without LTO; mix hardware in one report.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high` — Rust + Criterion + JSON schema work.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R1
  - **Blocks**: T4, T11, T12, T13, T43
  - **Blocked By**: T1

  **References**:
  - Pattern: `criterion.rs` book, `criterion::BenchmarkGroup`.
  - External: Rust performance book on benchmark stability.

  **Acceptance Criteria**:
  - [ ] `just bench --dry-run` lists registered benches
  - [ ] JSON envelope contains all 11 fields (validated by schema)
  - [ ] Harness records ≥10 reps and reports stddev

  **QA Scenarios**:
  ```
  Scenario: Bench produces valid JSON envelope
    Tool: Bash
    Preconditions: T5 complete
    Steps:
      1. `just bench-smoke > /tmp/bench.json`
      2. `jq -e '.mean and .median and .p99 and .stddev and .n_runs and .env.cpu' /tmp/bench.json`
    Expected Result: jq exits 0 (all fields present)
    Evidence: .sisyphus/evidence/task-5-envelope.json

  Scenario: Reproducibility within ±15%
    Tool: Bash
    Steps:
      1. `just bench-smoke > /tmp/r1.json && just bench-smoke > /tmp/r2.json`
      2. `python3 .sisyphus/scripts/check-bench-variance.py /tmp/r1.json /tmp/r2.json --tolerance 0.15` (same helper as T4; reads `median_ns` field from each JSON envelope, exits 0 iff every case's `abs(m1-m2)/max(m1,m2) ≤ 0.15`)
    Expected Result: ratio < 0.15
    Evidence: .sisyphus/evidence/task-5-repro.log
  ```

  **Commit**: YES
  - Message: `feat(bench): micro-bench harness scaffold with JSON envelope`
  - Files: `crates/pvthfhe-bench/**`, `Justfile`
  - Pre-commit: `cargo test -p pvthfhe-bench && cargo clippy -p pvthfhe-bench -- -D warnings`

- [x] 6. **T6: Bootstrapping-PV feasibility scan + go/no-go memo**

  **What to do**:
  - Author `.sisyphus/research/bootstrapping-pv-memo.md`.
  - Survey: what does "publicly verifiable bootstrapping" mean (correctness of refresh? noise reduction? key-switch correctness?). Cover BFV/CKKS bootstrapping cost in Noir, TFHE programmable bootstrap cost, Greyhound-style commitments to bootstrap keys, recursive folding of bootstrap proofs.
  - Estimate proof size and prover time for one bootstrap operation at our params; compare to threshold-decryption proof cost.
  - Decision: GO / NO-GO / DEFER. If NO-GO, document why and explicitly mark bootstrapping as "out of scope" guardrail in plan; if GO, add tasks to D2/I2 in a follow-up plan amendment; if DEFER, put it behind a feature flag.
  - Includes Phase-1 gate item: `bootstrapping_pv_decision: {go|no-go|defer}` in `phase1-gate.json`.

  **Must NOT do**: handwave costs; pretend bootstrapping in Noir is cheap; commit to bootstrapping without a cost ceiling.

  **Recommended Agent Profile**:
  - **Category**: `deep` — heavy literature integration + cost reasoning.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R1
  - **Blocks**: T16, T17
  - **Blocked By**: T1, T3 (depends on lit survey baseline)

  **References**:
  - CKKS bootstrap: ePrint 2018/153, 2020/1118.
  - TFHE bootstrap: ePrint 2018/421.
  - Greyhound 2024/1293 for committing to bootstrap keys.

  **Acceptance Criteria**:
  - [ ] Cost estimates for ≥2 bootstrap variants (BFV, CKKS or TFHE)
  - [ ] Comparison vs decryption-share proof cost
  - [ ] Explicit go/no-go/defer decision with rationale
  - [ ] Decision propagates to Phase-1 gate JSON

  **QA Scenarios**:
  ```
  Scenario: Decision is unambiguous and machine-readable
    Tool: Bash
    Preconditions: T6 complete
    Steps:
      1. `grep -E '^(GO|NO-GO|DEFER):' .sisyphus/research/bootstrapping-pv-memo.md`
    Expected Result: exactly one match, on a line of the form "GO: <rationale>" or "NO-GO: <rationale>" or "DEFER: <rationale>"
    Evidence: .sisyphus/evidence/task-6-decision.log
  ```

  **Commit**: YES
  - Message: `docs(research): bootstrapping-PV feasibility memo`
  - Files: `.sisyphus/research/bootstrapping-pv-memo.md`

- [x] 7. **T7: Cost-model template (asymptotic + concrete tables)**

  **What to do**:
  - Author `.sisyphus/research/cost-model-template.md` with two parts: (1) asymptotic — per-party communication, per-party computation, aggregator computation, verifier computation, on-chain calldata, on-chain gas; (2) concrete table at n ∈ {64, 128, 256, 512, 1024} with placeholder cells.
  - Define the Big-O class for each cell (O(1), O(log n), O(polylog n), O(n), etc.) and the constants to be filled at T15.
  - Add `costs.schema.json` (JSON Schema) so that T15/T16 can produce machine-checked cost reports.

  **Must NOT do**: confuse comm/compute/verify rows; omit gas as a separate column; use vague "small" / "fast" descriptors.

  **Recommended Agent Profile**:
  - **Category**: `writing` — schema + tabular design.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R1
  - **Blocks**: T15
  - **Blocked By**: T1

  **References**:
  - Pattern: ePrint 2024/1285 §6 cost tables.
  - External: JSON Schema 2020-12 spec.

  **Acceptance Criteria**:
  - [ ] Template covers all 6 cost axes
  - [ ] Concrete table has 5 rows (n values) and 6 cost columns
  - [ ] `costs.schema.json` validates against a sample filled instance

  **QA Scenarios**:
  ```
  Scenario: Schema validates a sample
    Tool: Bash
    Preconditions: T7 complete, sample at .sisyphus/research/sample-costs.json
    Steps:
      1. `npx ajv-cli validate -s .sisyphus/research/costs.schema.json -d .sisyphus/research/sample-costs.json`
    Expected Result: "valid" output, exit 0
    Evidence: .sisyphus/evidence/task-7-schema.log
  ```

  **Commit**: YES
  - Message: `docs(research): cost-model template + JSON schema`
  - Files: `.sisyphus/research/cost-model-template.md`, `.sisyphus/research/costs.schema.json`, `.sisyphus/research/sample-costs.json`

- [x] 8. **T8: Candidate Architecture A (silent-setup port) — pseudocode + security game + cost analysis**

  **What to do**:
  - Author `.sisyphus/research/arch-A-silent-setup.md`.
  - Adapt the silent-setup PV-ThFHE construction (closest to ePrint 2024/1285 line) to our parameter regime: identify the dealer-replacement (NIDKG/PVSS), commitment scheme (KZG or transparent), proof system (Groth16/Plonk/Halo2 → Noir+BB), key-aggregation step.
  - Provide formal pseudocode (Algorithms: Setup, KeyGen, Encrypt, PartialDecrypt, Aggregate, Verify) using consistent notation declared at top.
  - State security game (IND-CPA + decryption-soundness + public-verifiability) as a precise experiment.
  - Fill the cost table from T7 for this architecture.
  - List open problems & risk register specific to A.

  **Must NOT do**: copy pseudocode verbatim from any paper without re-deriving with our notation; assume a trusted dealer; use bilinear pairings on a non-PQ chain when an alternative exists.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain` — heavy crypto reasoning, novel adaptation.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R2 (with T9, T10, T11, T12, T13, T14)
  - **Blocks**: T15, T17
  - **Blocked By**: T2, T3, T7

  **References**:
  - **Citation-discipline note**: Specific ePrint IDs below are *candidate starting points* surfaced during requirements gathering and have NOT yet been verified against the official ePrint metadata. T8 MUST begin by running the citation-verification protocol from T14 (open the eprint.iacr.org/<id> abstract, confirm title and topic match, replace any miscatalogued ID, and record final IDs in `.sisyphus/research/citations.bib` with the `verified: true` flag). Do NOT design Architecture A on top of an unverified citation.
  - Topic: silent-setup / publicly-verifiable threshold FHE — verify candidate IDs (initially `2024/1285`, `2024/263`) and use whichever survives verification; if both fail, T14's lit-survey output supplies the corrected IDs.
  - Topic: PVSS / NIDKG aggregation (separate from PCS) — candidate `2023/1469` was previously labeled "SLAP/PVSS"; SLAP is in fact a lattice polynomial commitment scheme and belongs under PCS only. T14 supplies the correct PVSS/NIDKG sources (e.g., BGG+18, BS23, or whatever T14 surfaces).
  - hinTS-style threshold-signature aggregation literature (T14 supplies exact IDs).

  **Acceptance Criteria**:
  - [ ] All 6 algorithms in pseudocode with consistent notation
  - [ ] Security game written as 5-step experiment
  - [ ] Cost table fully populated from T7 schema
  - [ ] ≥3 open problems + risk register entries

  **QA Scenarios**:
  ```
  Scenario: Pseudocode completeness
    Tool: Bash
    Steps:
      1. `for algo in Setup KeyGen Encrypt PartialDecrypt Aggregate Verify; do grep -q "Algorithm $algo" .sisyphus/research/arch-A-silent-setup.md || echo "MISSING: $algo"; done`
    Expected Result: no MISSING output
    Evidence: .sisyphus/evidence/task-8-algos.log

  Scenario: Cost table validates against schema
    Tool: Bash
    Steps:
      1. `npx ajv-cli validate -s .sisyphus/research/costs.schema.json -d .sisyphus/research/arch-A-costs.json`
    Expected Result: valid
    Evidence: .sisyphus/evidence/task-8-costs.log
  ```

  **Commit**: YES
  - Message: `docs(research): architecture A — silent-setup port`
  - Files: `.sisyphus/research/arch-A-silent-setup.md`, `.sisyphus/research/arch-A-costs.json`

- [x] 9. **T9: Candidate Architecture B (lattice PVSS + folding + MicroNova) — pseudocode + security game + cost analysis**

  **What to do**:
  - Author `.sisyphus/research/arch-B-lattice-folding.md`.
  - Construction sketch: lattice-native PVSS for share distribution (no pairings); per-party share-correctness proofs aggregated via folding (LatticeFold+ or Lova); final folded instance compressed by MicroNova into a Noir-verifiable SNARK.
  - Identify which subroutines remain in the lattice IOP world vs which cross to BN254. Justify each crossing with a cost argument.
  - Pseudocode for all 6 algorithms (same notation as T8).
  - Security game; novelty/risk callouts (lattice-NIZK for hint well-formedness is an open subproblem — flag as research).
  - Fill cost table.

  **Must NOT do**: assume folding "just works" over RLWE without a soundness argument; ignore the fold-then-SNARK boundary; conflate Lova with LatticeFold.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R2
  - **Blocks**: T15, T17
  - **Blocked By**: T2, T3, T7

  **References**:
  - LatticeFold 2024/257; LatticeFold+ 2025/247; Lova 2024/1964; HyperNova 2023/573; MicroNova 2024/2099.
  - **PCS bucket (SLAP belongs here, NOT in PVSS)**: SLAP 2023/1469 — lattice polynomial commitment scheme. Use only for the polynomial-commitment role, not as a PVSS/NIDKG source.
  - PVSS / NIDKG sources: T14 supplies verified IDs (initially the candidate set surfaced by interview research: BGG+18, BS23 — verify before use).
  - knLWE PS25 2024/1984 (noise-aware threshold).
  - **Citation-discipline note**: Same protocol as T8 — verify every ePrint ID via the T14 protocol before designing on top of it.

  **Acceptance Criteria**:
  - [ ] All 6 algorithms; consistent notation with T8
  - [ ] Folding-vs-SNARK boundary explicit and cost-justified
  - [ ] Security game; novelty risks listed
  - [ ] Cost table validates against T7 schema

  **QA Scenarios**:
  ```
  Scenario: Notation consistency with arch A
    Tool: Bash
    Steps:
      1. `diff <(grep -oE '\\\\(s|t|n|sk|pk|ct)\\\\b' .sisyphus/research/arch-A-silent-setup.md | sort -u) <(grep -oE '\\\\(s|t|n|sk|pk|ct)\\\\b' .sisyphus/research/arch-B-lattice-folding.md | sort -u)`
    Expected Result: empty diff (same symbol set)
    Evidence: .sisyphus/evidence/task-9-notation.log

  Scenario: Boundary callouts present
    Tool: Bash
    Steps:
      1. `grep -ciE 'fold(ing)?-vs-snark|in-snark|outside-snark' .sisyphus/research/arch-B-lattice-folding.md`
    Expected Result: ≥3
    Evidence: .sisyphus/evidence/task-9-boundary.log
  ```

  **Commit**: YES
  - Message: `docs(research): architecture B — lattice PVSS + folding + MicroNova`
  - Files: `.sisyphus/research/arch-B-lattice-folding.md`, `.sisyphus/research/arch-B-costs.json`

- [x] 10. **T10: Candidate Architecture C (hybrid Noir wrapper) — pseudocode + security game + cost analysis**

  **What to do**:
  - Author `.sisyphus/research/arch-C-hybrid-noir.md`.
  - Construction sketch: keep heavy lattice work native (pure Rust, no SNARK), prove only the *minimal* relation in Noir — typically a Greyhound-style commitment to share+ciphertext + a small algebraic check. Recursive aggregation of N party-proofs into one via a Nova/HyperNova step on BN254, final SNARK verified on-chain.
  - Compare prover time tradeoff vs B (fewer SNARK constraints per party but more native crypto, larger transcript).
  - Pseudocode + game + cost table (same shape as T8/T9).

  **Must NOT do**: stuff full lattice arithmetic into Noir; lose statement of what is proven outside the SNARK; assume Greyhound is a drop-in for our exact relation.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R2
  - **Blocks**: T15, T17
  - **Blocked By**: T2, T3, T7

  **References**:
  - Greyhound 2024/1293; HyperNova 2023/573; ePrint 2024/263.
  - Noir docs: `noir-lang.org/docs`.

  **Acceptance Criteria**:
  - [ ] Algorithms + game + cost table (same as T8/T9)
  - [ ] Explicit "what is proven where" diagram (mermaid or ASCII)
  - [ ] Tradeoff vs B documented

  **QA Scenarios**:
  ```
  Scenario: "What is proven where" diagram present
    Tool: Bash
    Steps:
      1. `grep -cE '```mermaid|```text|```ascii' .sisyphus/research/arch-C-hybrid-noir.md`
    Expected Result: ≥1
    Evidence: .sisyphus/evidence/task-10-diagram.log
  ```

  **Commit**: YES
  - Message: `docs(research): architecture C — hybrid Noir wrapper`
  - Files: `.sisyphus/research/arch-C-hybrid-noir.md`, `.sisyphus/research/arch-C-costs.json`

- [x] 11. **T11: Micro-bench — RLWE-relation in Noir/BB**

  **What to do**:
  - Implement minimal Noir circuit at the **placeholder package T1 already scaffolded at `circuits/bench/rlwe_relation/`** (DO NOT run `nargo new` or rename — replace `main.nr` body in-place) proving the relation: `c0 + c1·s = m + e (mod q)` for fixed-size BFV/RLWE parameters at toy degree (e.g., N=512, then N=2048, N=8192).
  - Add `Prover_valid.toml` and `Prover_tampered.toml` inside `circuits/bench/rlwe_relation/` with concrete witness values (honest assignment + one tamper that violates the relation).
  - Compile with `nargo compile --package rlwe_relation`, execute via `nargo execute --package rlwe_relation --prover-name Prover_valid` to produce `circuits/target/rlwe_relation.{json,gz}`, prove with `bb prove --scheme ultra_honk`, verify with `bb verify --scheme ultra_honk`, time each phase.
  - Record gates, proving time, proof size, BB verifier time at each N.
  - Output JSON to `bench/results/rlwe-relation-{N}.json` per envelope from T5.
  - RED first: failing assertion that proof verifies.

  **Must NOT do**: skip negative tests (tampered witness must fail); compare across hardware; report only one run.

  **Recommended Agent Profile**:
  - **Category**: `deep` — circuit eng + measurement.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R2
  - **Blocks**: T15, T17
  - **Blocked By**: T1, T5

  **References**:
  - Noir stdlib `std::field`, `std::bigint`.
  - Greyhound 2024/1293 RLWE-commitment relations.

  **Acceptance Criteria**:
  - [ ] Bench JSON for at least N ∈ {512, 2048, 8192}
  - [ ] Negative test: tampered witness rejected
  - [ ] Reproducibility ±15% across 10 runs

  **QA Scenarios**:
  ```
  Scenario: Honest proof verifies
    Tool: Bash
    Steps:
      1. `(cd circuits && nargo execute --package rlwe_relation --prover-name Prover_valid)`   # produces circuits/target/rlwe_relation.{json,gz}
      2. `(cd circuits && bb write_vk --scheme ultra_honk -b target/rlwe_relation.json -o target)`
      3. `(cd circuits && bb prove --scheme ultra_honk -b target/rlwe_relation.json -w target/rlwe_relation.gz -o target)`
      4. `(cd circuits && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs); echo "exit=$?"`
    Expected Result: every command exits 0
    Evidence: .sisyphus/evidence/task-11-honest.log

  Scenario: Tampered witness rejected
    Tool: Bash
    Steps:
      1. `(cd circuits && nargo execute --package rlwe_relation --prover-name Prover_tampered) 2>&1; echo "execute_exit=$?"` | tee /tmp/t11-tampered.log
      2. `if grep -q "execute_exit=0" /tmp/t11-tampered.log; then (cd circuits && bb prove --scheme ultra_honk -b target/rlwe_relation.json -w target/rlwe_relation.gz -o target) && (cd circuits && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs); echo "verify_exit=$?" | tee -a /tmp/t11-tampered.log; fi`
    Expected Result: either `execute_exit` ≠ 0 (witness fails Noir's assert at execution) OR `verify_exit` ≠ 0 (proof rejected by bb)
    Evidence: .sisyphus/evidence/task-11-tamper.log

  Scenario: Bench JSON matches envelope
    Tool: Bash
    Steps:
      1. `jq -e '.gates and .prover_ms and .proof_bytes and .verifier_ms' bench/results/rlwe-relation-2048.json`
    Expected Result: jq exits 0
    Evidence: .sisyphus/evidence/task-11-envelope.log
  ```

  **Commit**: YES
  - Message: `bench(circuits): RLWE-relation Noir+BB micro-benchmark`
  - Files: `circuits/bench/rlwe_relation/**`, `bench/results/rlwe-relation-*.json`

- [x] 12. **T12: Micro-bench — recursive folding (HyperNova-style)**

  **What to do**:
  - Build a minimal folding loop using an existing Rust folding library (e.g., `arkworks` Sonobe / Nova, or hand-rolled HyperNova primer if needed) to fold N copies of a fixed-size R1CS instance, N ∈ {16, 64, 256, 1024}.
  - Measure: per-fold time, accumulator size, final-step prover time, final SNARK size, BB-verifier time on the final step.
  - Goal: confirm O(log N) or O(1)-amortized prover claims hold at our scale, surface constants.
  - Output JSON per envelope.

  **Must NOT do**: misrepresent amortized vs worst-case; skip the final-SNARK step ("folding" alone is not verifiable on chain); benchmark with toy R1CS that doesn't match our true per-party relation shape.

  **Recommended Agent Profile**:
  - **Category**: `deep`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R2
  - **Blocks**: T15, T17, T37
  - **Blocked By**: T1, T5

  **References**:
  - HyperNova 2023/573, MicroNova 2024/2099, Nova 2021/370, Sonobe.

  **Acceptance Criteria**:
  - [ ] Bench at all 4 N values
  - [ ] Slope of per-fold time vs N is sub-linear (log fit reported)
  - [ ] Final SNARK proof size in BN254 reported
  - [ ] Reproducibility ±15%

  **QA Scenarios**:
  ```
  Scenario: Sub-linear scaling sanity check
    Tool: Bash
    Steps:
      1. `python3 bench/scripts/fit-loglog.py bench/results/folding-*.json`
    Expected Result: fitted exponent < 0.5 (sub-linear)
    Evidence: .sisyphus/evidence/task-12-fit.log

  Scenario: Final SNARK verifies
    Tool: Bash
    Steps:
      1. `cargo run -p pvthfhe-bench --bin folding-final-verify`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-12-verify.log
  ```

  **Commit**: YES
  - Message: `bench(folding): recursive folding micro-benchmark`
  - Files: `crates/pvthfhe-bench/src/bin/folding*.rs`, `bench/results/folding-*.json`

- [x] 13. **T13: Micro-bench — KZG batched verification on EVM**

  **What to do**:
  - Implement Solidity verifier for a KZG-batched opening (BN254 pairing precompiles) and benchmark gas at batch sizes {1, 8, 32, 128}.
  - Test on Anvil; record gas via `cast estimate` or Foundry gas reports.
  - Output JSON envelope.
  - Note: this is to establish a baseline for "what does on-chain verification cost today" — not commitment to using KZG.

  **Must NOT do**: assume EIP-4844 precompile semantics without testing on Anvil; ignore calldata cost vs verifier cost separation; report wrong gas units.

  **Recommended Agent Profile**:
  - **Category**: `deep`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R2
  - **Blocks**: T15, T17
  - **Blocked By**: T1, T5

  **References**:
  - EIP-197, EIP-198 (BN254 pairing).
  - Foundry `forge test --gas-report`.

  **Acceptance Criteria**:
  - [ ] Gas at all 4 batch sizes
  - [ ] Calldata cost separated from verifier cost
  - [ ] Reproducibility ±5% (gas is deterministic)
  - [ ] Comparison vs ≤5M gas budget noted

  **QA Scenarios**:
  ```
  Scenario: Gas reports complete
    Tool: Bash
    Steps:
      1. `forge test --root contracts --match-path test/KzgBatchVerifier.t.sol --gas-report > /tmp/gas.log`
      2. `grep -E 'verifyBatch_(1|8|32|128)' /tmp/gas.log`
    Expected Result: 4 matches with gas figures
    Evidence: .sisyphus/evidence/task-13-gas.log

  Scenario: Honest batch verifies, tampered batch rejects
    Tool: Bash
    Steps:
      1. `forge test --root contracts --match-test testHonestVerifies && forge test --root contracts --match-test testTamperedRejects`
    Expected Result: both pass
    Evidence: .sisyphus/evidence/task-13-honesty.log
  ```

  **Commit**: YES
  - Message: `bench(onchain): KZG batched verifier gas benchmark`
  - Files: `contracts/bench/KzgBatchVerifier.sol`, `contracts/test/KzgBatchVerifier.t.sol`, `bench/results/kzg-batch-*.json`

- [x] 14. **T14: Literature refresh #1 (subagent: librarian)**

  **What to do**:
  - Re-fire `librarian` subagent at end of Phase 1 to catch any papers published since T3 (eprint posts, ACM CCS / Eurocrypt / Crypto / Asiacrypt acceptances).
  - Author `.sisyphus/research/lit-refresh-1.md` listing only NEW papers (vs T3) and their impact on architectures A/B/C.
  - If any paper materially changes a candidate's cost/security, update the corresponding arch-{A,B,C}.md file with a "Refresh" section.

  **Must NOT do**: re-survey papers already in T3; pad with marginal results.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-low` — directed research, low effort.
  - **Skills**: none.
  - **Subagent**: `librarian`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R2 (runs late, but in parallel with T8-T13)
  - **Blocks**: T16
  - **Blocked By**: T3 (baseline survey)

  **References**:
  - eprint.iacr.org RSS for the prior 90 days.
  - DBLP search by authors of cited works.

  **Acceptance Criteria**:
  - [ ] Memo dated and time-stamped
  - [ ] Each new paper has impact statement
  - [ ] Architecture memos updated where applicable

  **QA Scenarios**:
  ```
  Scenario: Refresh memo is non-trivial
    Tool: Bash
    Steps:
      1. `wc -l .sisyphus/research/lit-refresh-1.md`
      2. `grep -c 'Impact:' .sisyphus/research/lit-refresh-1.md`
    Expected Result: ≥40 lines; ≥1 Impact entry
    Evidence: .sisyphus/evidence/task-14-refresh.log
  ```

  **Commit**: YES
  - Message: `docs(research): literature refresh #1 (Phase-1 close)`
  - Files: `.sisyphus/research/lit-refresh-1.md`, possibly `arch-{A,B,C}.md` refresh sections

- [x] 15. **T15: Compiled cost table + comparison matrix across A/B/C**

  **What to do**:
  - Author `.sisyphus/research/cost-comparison.md`: side-by-side table of arch-{A,B,C} along the 6 axes from T7, at n ∈ {64, 128, 256, 512, 1024}.
  - Pull numbers from arch-{A,B,C}-costs.json plus micro-bench JSONs (T11, T12, T13).
  - Compute combined estimates: per-party prover time, aggregator time, on-chain calldata bytes, on-chain gas, off-chain proof size, end-to-end keygen latency.
  - Visualize: 3 line plots (prover time vs n, gas vs n, proof size vs n) saved as PNG to `.sisyphus/research/figures/`.
  - Decision aid (not the decision itself): qualitative ranking + caveats.

  **Must NOT do**: invent numbers not backed by a JSON file; pick a winner here (T17 does that); hide variance.

  **Recommended Agent Profile**:
  - **Category**: `writing` — synthesis + visualization.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave R3 (with T16)
  - **Blocks**: T16, T17
  - **Blocked By**: T7, T8, T9, T10, T11, T12, T13

  **References**:
  - All arch-*-costs.json and bench/results/*.json from R2.

  **Acceptance Criteria**:
  - [ ] Combined table validates against cost schema
  - [ ] 3 PNG figures present
  - [ ] Every cell traces to a source JSON

  **QA Scenarios**:
  ```
  Scenario: Every cell has provenance
    Tool: Bash
    Steps:
      1. `python3 .sisyphus/research/scripts/check-provenance.py .sisyphus/research/cost-comparison.md`
    Expected Result: 0 unsourced cells
    Evidence: .sisyphus/evidence/task-15-provenance.log

  Scenario: Figures exist and are non-empty
    Tool: Bash
    Steps:
      1. `for f in prover-time gas proof-size; do test -s ".sisyphus/research/figures/$f-vs-n.png" || echo "MISSING: $f"; done`
    Expected Result: no MISSING output
    Evidence: .sisyphus/evidence/task-15-figs.log
  ```

  **Commit**: YES
  - Message: `docs(research): cost comparison matrix across architectures`
  - Files: `.sisyphus/research/cost-comparison.md`, `.sisyphus/research/figures/*.png`

- [x] 16. **T16: Phase 1 gate report — `just phase1-gate` produces JSON + markdown**

  **What to do**:
  - Implement `just phase1-gate` recipe → runs a Rust/Python script that:
    1. Validates presence of all R1/R2/R3 artifacts.
    2. Validates each cost JSON against schema.
    3. Validates micro-bench reproducibility (±15% rule).
    4. Confirms `bootstrapping_pv_decision` is one of {go, no-go, defer}.
    5. Confirms `[DECISION NEEDED]` blocks in T2 are RESOLVED.
    6. Confirms ≥2 viable architectures remain OR a negative-result memo exists.
    7. Writes `phase1-gate.json` with PASS/FAIL + per-check details.
    8. Writes `phase1-gate.md` (human-readable summary).
  - Tag `phase1-gate-pass` on success.

  **Must NOT do**: pass the gate with `[DECISION NEEDED]` unresolved; hide failed sub-checks; allow the script to silently skip checks.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high` — scripting + validation.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: NO (single sink)
  - **Parallel Group**: Wave R3
  - **Blocks**: T17 (Phase 2 entry)
  - **Blocked By**: T2, T6, T14, T15

  **References**:
  - JSON Schema validation; `jq` cookbook.

  **Acceptance Criteria**:
  - [ ] `just phase1-gate` exits 0 on success, nonzero on any failure
  - [ ] `phase1-gate.json` lists every sub-check with status
  - [ ] CI rejects PRs that do not pass gate
  - [ ] Tag `phase1-gate-pass` applied

  **QA Scenarios**:
  ```
  Scenario: Gate passes when all artifacts present
    Tool: Bash
    Preconditions: T1-T15 complete
    Steps:
      1. `just phase1-gate; echo "exit=$?"`
      2. `jq -e '.status == "PASS"' .sisyphus/research/phase1-gate.json`
    Expected Result: exit 0; status == PASS
    Evidence: .sisyphus/evidence/task-16-pass.log

  Scenario: Gate fails when bootstrapping decision missing
    Tool: Bash
    Steps:
      1. `cp .sisyphus/research/bootstrapping-pv-memo.md /tmp/bs-backup.md`
      2. `python3 -c "import re,pathlib; p=pathlib.Path('.sisyphus/research/bootstrapping-pv-memo.md'); s=p.read_text(); s2=re.sub(r'(?m)^(GO|NO-GO|DEFER):.*$', '', s); assert s2 != s, 'no GO/NO-GO/DEFER line found'; p.write_text(s2)"`
      3. `just phase1-gate; echo "exit=$?" | tee /tmp/gate-fail.log`
      4. `cp /tmp/bs-backup.md .sisyphus/research/bootstrapping-pv-memo.md  # restore`
      5. `grep -q "bootstrapping_pv_decision" /tmp/gate-fail.log`
    Expected Result: nonzero exit; failure reason includes "bootstrapping_pv_decision"
    Evidence: .sisyphus/evidence/task-16-fail.log
  ```

  **Commit**: YES
  - Message: `feat(gate): phase 1 gate script + JSON/MD reports`
  - Files: `Justfile`, `.sisyphus/scripts/phase1-gate.{rs|py}`, `.sisyphus/research/phase1-gate.{json,md}`
  - Pre-commit: `just phase1-gate`

- [x] 17. **T17: Architecture selection memo (chooses ONE winner)**

  **What to do**:
  - Author `.sisyphus/design/selection-memo.md`. Input: T15 cost matrix, T8/T9/T10 security games, T6 bootstrap decision, T14 refresh, oracle/Metis flags.
  - Apply explicit decision rubric (weighted): meets O(n)/O(polylog n) target, malicious-secure proof feasibility, no-trusted-dealer, transparent-or-universal-setup preference, on-chain gas ≤5M, backend availability (T4), implementation risk, novelty risk.
  - Pick ONE architecture; document why each loser was rejected; record what triggers a reversal.
  - **Required output for next phase**: chosen architecture name + reference cost cell + assumption set + theorem skeletons to prove.

  **Must NOT do**: pick by gut; merge two architectures into a hand-wavy hybrid; defer the choice to implementation.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: NO — sequential, BLOCKS Phase 2.
  - **Parallel Group**: Wave D1
  - **Blocks**: T18, T19, T20, T21, T22, T23
  - **Blocked By**: T16

  **References**:
  - All Phase-1 artifacts.

  **Acceptance Criteria**:
  - [ ] Decision rubric explicit with weights
  - [ ] Each rejected architecture has a documented rejection reason
  - [ ] Reversal triggers listed
  - [ ] Output handoff fields filled

  **QA Scenarios**:
  ```
  Scenario: Selection is unambiguous
    Tool: Bash
    Steps:
      1. `grep -E '^Selected architecture: (A|B|C)$' .sisyphus/design/selection-memo.md`
    Expected Result: exactly one match
    Evidence: .sisyphus/evidence/task-17-selection.log

  Scenario: Rubric weights sum to 1.0
    Tool: Bash
    Steps:
      1. `python3 .sisyphus/scripts/check-rubric.py .sisyphus/design/selection-memo.md`
    Expected Result: weights sum within 1e-6 of 1.0
    Evidence: .sisyphus/evidence/task-17-rubric.log
  ```

  **Commit**: YES
  - Message: `docs(design): architecture selection memo (winner: {A|B|C})`
  - Files: `.sisyphus/design/selection-memo.md`
  - Tag: `phase2-start`

- [x] 18. **T18: Full protocol spec — distributed keygen**

  **What to do**:
  - Author `.sisyphus/design/spec-keygen.md`. Inputs from T17.
  - For each round: party state, message format (typed), verification step performed by every other party + by the public verifier, abort/blame conditions.
  - Define wire formats (CBOR or SSZ-style) with explicit field tags; cross-link with T22 API spec.
  - Specify NIZK statements proven during keygen (well-formed share, well-formed hint).
  - Failure modes: party crash, equivocation, malformed proof — each with deterministic blame.

  **Must NOT do**: leave wire formats "TBD"; mix correctness and liveness arguments; assume synchronous broadcast.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D2 (with T19, T20, T21, T22, T23)
  - **Blocks**: T19 (decryption shares depend on key shape), T22 (API spec consumes wire formats), T24, T28, T33, T35
  - **Blocked By**: T17

  **References**:
  - Selected architecture's pseudocode (T8/T9/T10).
  - SSZ spec; CBOR RFC 8949.

  **Acceptance Criteria**:
  - [ ] All rounds specified with typed messages
  - [ ] Wire formats fixed and versioned
  - [ ] Every NIZK statement formally written
  - [ ] Blame matrix complete

  **QA Scenarios**:
  ```
  Scenario: Wire formats validate
    Tool: Bash
    Steps:
      1. `python3 .sisyphus/scripts/check-wire-format.py .sisyphus/design/spec-keygen.md`
    Expected Result: every message type has fixed-size or length-prefixed encoding
    Evidence: .sisyphus/evidence/task-18-wire.log

  Scenario: Blame matrix complete
    Tool: Bash
    Steps:
      1. `grep -c '^| Failure' .sisyphus/design/spec-keygen.md`
    Expected Result: ≥4 failure modes listed
    Evidence: .sisyphus/evidence/task-18-blame.log
  ```

  **Commit**: YES
  - Message: `docs(design): keygen protocol spec`
  - Files: `.sisyphus/design/spec-keygen.md`

- [x] 19. **T19: Full protocol spec — threshold decryption**

  **What to do**:
  - Author `.sisyphus/design/spec-decrypt.md`.
  - Specify partial-decryption-share generation (per party): inputs (sk_i, ct), output (share, NIZK of correctness), wire format.
  - Aggregator: receive ≥t shares, run aggregation (linear combination + noise smudging if needed), output plaintext + aggregated proof for the verifier.
  - Verifier (public, on-chain): inputs (ct, plaintext, aggregated proof, pk, public params), checks aggregated proof + computes/decommits as needed.
  - Specify noise-smudging parameters and integrate with T21.
  - Failure modes: missing shares, malformed share, malformed aggregation, replay.

  **Must NOT do**: assume aggregator is honest; skip noise smudging when needed; let verifier require knowledge of any sk_i.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D2
  - **Blocks**: T22, T24, T28, T34, T36
  - **Blocked By**: T17, T18 (key shape)

  **References**:
  - knLWE PS25 2024/1984 (smudging analysis).
  - ePrint 2024/1285 §4.

  **Acceptance Criteria**:
  - [ ] Per-party share spec complete
  - [ ] Aggregator algorithm explicit; aggregator can be malicious
  - [ ] Public verifier algorithm explicit and stateless on-chain
  - [ ] Noise budget for decryption integrated with T21

  **QA Scenarios**:
  ```
  Scenario: Verifier needs no sk
    Tool: Bash
    Steps:
      1. `python3 .sisyphus/scripts/check-no-sk-in-verifier.py .sisyphus/design/spec-decrypt.md`
    Expected Result: 0 references to "sk_i" in the verifier algorithm section
    Evidence: .sisyphus/evidence/task-19-noskleak.log
  ```

  **Commit**: YES
  - Message: `docs(design): threshold decryption protocol spec`
  - Files: `.sisyphus/design/spec-decrypt.md`

- [x] 20. **T20: Concrete RLWE parameter selection (estimator-backed)**

  **What to do**:
  - Choose RLWE parameters (n, q, σ) for ≥128-bit classical and ≥128-bit PQ security at our circuit depth.
  - Use lattice-estimator (`lattice-estimator` Python pkg) to back every choice with an estimator transcript.
  - Document param sets for: (a) keygen shares, (b) ciphertext, (c) NTT/RNS layout for chosen backend.
  - Author `.sisyphus/design/parameters.md` with fully filled tables and `parameters.toml` machine-readable copy.

  **Must NOT do**: copy parameters from a paper without re-running the estimator; ignore PQ security; choose parameters that the chosen backend can't represent.

  **Recommended Agent Profile**:
  - **Category**: `deep`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D2
  - **Blocks**: T21, T28, T30
  - **Blocked By**: T17

  **References**:
  - github.com/malb/lattice-estimator
  - Albrecht et al. concrete-security tables.

  **Acceptance Criteria**:
  - [ ] Estimator transcripts saved verbatim
  - [ ] Both classical and PQ security ≥128 bits
  - [ ] `parameters.toml` parses and validates against schema

  **QA Scenarios**:
  ```
  Scenario: Estimator transcripts reproduce
    Tool: Bash
    Steps:
      1. `bash .sisyphus/design/scripts/rerun-estimator.sh > /tmp/est.log`
      2. `diff /tmp/est.log .sisyphus/design/estimator-baseline.log`
    Expected Result: identical (or only timing-line differences)
    Evidence: .sisyphus/evidence/task-20-estimator.log

  Scenario: parameters.toml validates
    Tool: Bash
    Steps:
      1. `cargo run -p pvthfhe-core --bin validate-params -- .sisyphus/design/parameters.toml`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-20-params.log
  ```

  **Commit**: YES
  - Message: `docs(design): concrete RLWE parameters (estimator-backed)`
  - Files: `.sisyphus/design/parameters.md`, `.sisyphus/design/parameters.toml`, `.sisyphus/design/estimator-baseline.log`

- [x] 21. **T21: Noise budget closure analysis**

  **What to do**:
  - Author `.sisyphus/design/noise-budget.md`.
  - Track noise growth through every algorithm: encryption, share generation, aggregation, smudging, decryption.
  - Show the noise inequality closes: max-noise after aggregation < q/(2·decoding-margin) at chosen params.
  - Cover the malicious case: what if up to t-1 shares are adversarial? Bound their noise contribution and re-prove closure.
  - Provide a Rust prop-test that samples random noise vectors and asserts the inequality empirically.

  **Must NOT do**: drop the malicious-case analysis; use average-case bounds where worst-case is required; pick a smudging parameter that breaks IND-CPA.

  **Recommended Agent Profile**:
  - **Category**: `deep`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D2
  - **Blocks**: T28, T34
  - **Blocked By**: T17, T20

  **References**:
  - knLWE PS25; ePrint 2024/1285 §5; CKKS error analysis.

  **Acceptance Criteria**:
  - [ ] Inequality stated and proved for honest case
  - [ ] Inequality re-stated and proved for malicious case (up to t-1 corrupted)
  - [ ] Empirical prop-test passes 10k iterations

  **QA Scenarios**:
  ```
  Scenario: Empirical noise prop-test
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-core --test noise_budget -- --test-threads=1 --nocapture`
    Expected Result: passes 10000 cases without inequality violation
    Evidence: .sisyphus/evidence/task-21-noise.log
  ```

  **Commit**: YES
  - Message: `docs(design): noise budget closure (honest + malicious)`
  - Files: `.sisyphus/design/noise-budget.md`, `crates/pvthfhe-core/tests/noise_budget.rs`

- [x] 22. **T22: Enclave-compatible API/interface spec**

  **What to do**:
  - Author `.sisyphus/design/api-spec.md`.
  - Define the public Rust API (trait names, method signatures, error types) for: party, aggregator, verifier-client; the on-chain verifier interface (Solidity ABI: function names, calldata layout, revert reasons); the wire encodings from T18/T19.
  - Map to gnosisguild/enclave's `ciphernode` / `aggregator` interfaces (read-only — we do not modify upstream). Document required adapter shape.
  - Provide a trait-only Rust crate sketch (`pvthfhe-api/`) that compiles with empty impls — implementation lives later in T30+.

  **Must NOT do**: bind to a specific Enclave commit; inline business logic in the trait; rely on upstream Enclave changes.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D2
  - **Blocks**: T28, T29, T42
  - **Blocked By**: T17, T18, T19

  **References**:
  - github.com/gnosisguild/enclave/tree/main (ciphernode interfaces).
  - Solidity ABI spec.

  **Acceptance Criteria**:
  - [ ] All four interfaces (party, aggregator, verifier-client, on-chain verifier) specified
  - [ ] Trait-only crate `cargo check --workspace` passes
  - [ ] Adapter requirements vs Enclave documented

  **QA Scenarios**:
  ```
  Scenario: Trait-only crate compiles
    Tool: Bash
    Steps:
      1. `cargo check -p pvthfhe-api`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-22-api.log
  ```

  **Commit**: YES
  - Message: `docs(design): API/interface spec + trait-only crate`
  - Files: `.sisyphus/design/api-spec.md`, `crates/pvthfhe-api/**`

- [x] 23. **T23: Reference-model worked example (toy n=4 walkthrough)**

  **What to do**:
  - Author `.sisyphus/design/worked-example.md` walking through the full protocol at n=4, t=3 (or the resolved corruption-model values).
  - Include concrete numeric values at every step: shares, polynomials, NIZK transcripts, ciphertext, partial decryptions, aggregated proof, verifier acceptance.
  - Provide a pure-Rust binary `crates/pvthfhe-bench/src/bin/worked_example.rs` (Cargo derives bin name `worked_example` from the file stem) that reproduces every number deterministically from a seed. Invocation must use the snake_case bin name throughout: `cargo run -p pvthfhe-bench --bin worked_example`. The earlier draft mentioned a SageMath script alternative — that path is rejected; keep the work in pure Rust to maintain the single-language toolchain.
  - This becomes the seed for golden test vectors in T31.

  **Must NOT do**: use random numbers without a fixed seed; skip the verifier step; use parameters not from T20.

  **Recommended Agent Profile**:
  - **Category**: `deep`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D2
  - **Blocks**: T31 (golden vectors)
  - **Blocked By**: T18, T19, T20

  **References**:
  - SageMath docs; T18, T19 specs.

  **Acceptance Criteria**:
  - [ ] Script reproduces every numeric value bit-exact from a fixed seed
  - [ ] Verifier step accepts in the worked example
  - [ ] At least one negative example also walked through (tampered share → reject)

  **QA Scenarios**:
  ```
  Scenario: Worked example reproduces
    Tool: Bash
    Steps:
      1. `cargo run -p pvthfhe-bench --bin worked_example -- --seed 42 > /tmp/we.log`
      2. `diff /tmp/we.log .sisyphus/design/worked-example-expected.log`
    Expected Result: empty diff
    Evidence: .sisyphus/evidence/task-23-we.log

  Scenario: Negative example rejects
    Tool: Bash
    Steps:
      1. `cargo run -p pvthfhe-bench --bin worked_example -- --seed 42 --tamper-share 1; echo "exit=$?"`
    Expected Result: nonzero exit
    Evidence: .sisyphus/evidence/task-23-tamper.log
  ```

  **Commit**: YES
  - Message: `docs(design): toy worked example with reproducer`
  - Files: `.sisyphus/design/worked-example.md`, `.sisyphus/design/worked-example-expected.log`, `crates/pvthfhe-bench/src/bin/worked_example.rs`

- [x] 24. **T24: Security theorems + assumption mapping**

  **What to do**:
  - Author `.sisyphus/design/security-proofs.md`.
  - State theorems: (T-IND-CPA) confidentiality under static malicious corruption of ≤(t-1) parties, (T-DEC-SOUND) decryption soundness against malicious aggregator, (T-PV-SOUND) public-verifiability soundness, (T-ROBUSTNESS / T-LIVENESS) abort-with-public-blame.
  - Each theorem: assumption set (mapped to T2 ledger), reduction sketch, tightness, RO-vs-standard model.
  - Cross-link to algorithms in T18/T19; note any assumption introduced here back to T2.

  **Must NOT do**: invoke "by standard arguments" without sketch; use assumptions not in the ledger; skip robustness/liveness because "we abort".

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D3 (with T25, T26, T27)
  - **Blocks**: T26, T28
  - **Blocked By**: T2, T18, T19, T20, T21

  **References**:
  - ePrint 2024/1285 §5; ePrint 2024/263 §4.

  **Acceptance Criteria**:
  - [ ] All 4 theorems stated formally
  - [ ] Each maps to ≥1 ledger assumption
  - [ ] Reduction sketches present (≥1 paragraph each)

  **QA Scenarios**:
  ```
  Scenario: Theorem-to-ledger mapping complete
    Tool: Bash
    Steps:
      1. `python3 .sisyphus/scripts/check-theorem-mapping.py .sisyphus/design/security-proofs.md .sisyphus/research/assumptions-ledger.md`
    Expected Result: every theorem maps to ≥1 ledger entry, every ledger entry referenced ≥1 theorem (or marked "background-only")
    Evidence: .sisyphus/evidence/task-24-mapping.log
  ```

  **Commit**: YES
  - Message: `docs(design): security theorems + assumption mapping`
  - Files: `.sisyphus/design/security-proofs.md`

- [x] 25. **T25: Proof boundary freeze (what is in SNARK, what is not)**

  **What to do**:
  - Author `.sisyphus/design/proof-boundary.md`.
  - For each property checked in the protocol, declare its enforcement layer: (a) inside Noir SNARK, (b) outside-SNARK Rust check by aggregator, (c) outside-SNARK on-chain Solidity check, (d) discharged by lattice-NIZK before/after the SNARK.
  - Justify each placement with a cost vs soundness argument.
  - Freeze: any future change to this boundary requires a plan amendment.

  **Must NOT do**: leave any property unassigned; place a property "everywhere"; bury soundness-critical checks in untyped glue code.

  **Recommended Agent Profile**:
  - **Category**: `deep`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D3
  - **Blocks**: T28, T35, T36, T38
  - **Blocked By**: T18, T19, T24

  **References**:
  - T18, T19, T24, T13.

  **Acceptance Criteria**:
  - [ ] Every property has exactly one primary layer + optional belt-and-suspenders layers
  - [ ] Every assignment justified by cost or soundness
  - [ ] Frozen-status banner at top of doc

  **QA Scenarios**:
  ```
  Scenario: Every property mapped
    Tool: Bash
    Steps:
      1. `python3 .sisyphus/scripts/check-boundary-coverage.py .sisyphus/design/proof-boundary.md`
    Expected Result: 0 unmapped properties
    Evidence: .sisyphus/evidence/task-25-coverage.log
  ```

  **Commit**: YES
  - Message: `docs(design): proof boundary freeze`
  - Files: `.sisyphus/design/proof-boundary.md`

- [x] 26. **T26: Oracle architecture & security review (subagent: oracle)**

  **What to do**:
  - Spawn `oracle` subagent with: T17 selection, T18-T25 specs/proofs/boundary, T2 threat model.
  - Oracle returns a report enumerating: incorrect claims, missing reductions, sneaky trust assumptions, scope creep, alternative attack vectors, gas-budget feasibility concerns, fold-vs-SNARK soundness gaps.
  - Address every Oracle finding either by (a) revising the affected design doc, or (b) acknowledging in `.sisyphus/design/oracle-review.md` with rationale + tag for Phase-3 follow-up.
  - Re-fire oracle ≤2× to confirm closure.

  **Must NOT do**: silently dismiss findings; mark "won't fix" without rationale; skip re-firing oracle on substantive doc revisions.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high` — orchestration + revision.
  - **Skills**: none.
  - **Subagent**: `oracle`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D3
  - **Blocks**: T28
  - **Blocked By**: T17-T25

  **References**:
  - All Phase-2 docs.

  **Acceptance Criteria**:
  - [ ] Oracle report saved verbatim
  - [ ] Every finding marked addressed/acknowledged with link
  - [ ] Re-fire confirms ≤0 critical findings remain

  **QA Scenarios**:
  ```
  Scenario: All findings dispositioned
    Tool: Bash
    Steps:
      1. `python3 .sisyphus/scripts/check-oracle-dispositions.py .sisyphus/design/oracle-review.md`
    Expected Result: 0 findings without disposition tag
    Evidence: .sisyphus/evidence/task-26-disp.log
  ```

  **Commit**: YES
  - Message: `docs(design): oracle review + dispositions`
  - Files: `.sisyphus/design/oracle-review.md`, plus any revisions to T18-T25 docs

- [x] 27. **T27: Literature refresh #2 (subagent: librarian, pre-Implementation)**

  **What to do**:
  - Re-fire `librarian` to catch papers since T14.
  - Author `.sisyphus/design/lit-refresh-2.md`.
  - For any paper that materially affects parameters, spec, or proof boundary: open a "blocker" issue and either (a) update the docs and re-run Oracle (T26 re-fire), or (b) document why the new result does not change the design.

  **Must NOT do**: skip if "Phase 2 is almost done"; treat refresh as decorative.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-low`.
  - **Skills**: none.
  - **Subagent**: `librarian`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave D3
  - **Blocks**: T28
  - **Blocked By**: T14

  **References**:
  - eprint.iacr.org last 90 days; conference acceptances since T14.

  **Acceptance Criteria**:
  - [ ] Memo dated; new papers listed
  - [ ] Each "blocker" tagged BLOCKING or NON-BLOCKING with rationale

  **QA Scenarios**:
  ```
  Scenario: No undecided blockers
    Tool: Bash
    Steps:
      1. `grep -E '^Blocker: (BLOCKING|NON-BLOCKING):' .sisyphus/design/lit-refresh-2.md | wc -l`
      2. `grep -E '^Blocker: TBD' .sisyphus/design/lit-refresh-2.md | wc -l`
    Expected Result: first ≥0; second == 0
    Evidence: .sisyphus/evidence/task-27-blockers.log
  ```

  **Commit**: YES
  - Message: `docs(design): literature refresh #2 (Phase-2 close)`
  - Files: `.sisyphus/design/lit-refresh-2.md`

- [x] 28. **T28: Phase 2 gate report — `just phase2-gate` produces JSON + markdown**

  **What to do**:
  - Implement `just phase2-gate` recipe → script that:
    1. Validates presence of T17-T27 artifacts.
    2. Validates `parameters.toml` (T20).
    3. Confirms noise-budget prop-test (T21) passes.
    4. Confirms theorem-to-ledger mapping coverage (T24).
    5. Confirms proof-boundary coverage (T25).
    6. Confirms oracle has 0 critical findings open (T26).
    7. Confirms refresh #2 has 0 BLOCKING undecided (T27).
    8. Writes `phase2-gate.json` and `phase2-gate.md`.
  - Tag `phase2-gate-pass`.

  **Must NOT do**: pass with open BLOCKING items; skip noise-budget rerun; allow stale parameter files.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: NO (single sink)
  - **Parallel Group**: Wave D3
  - **Blocks**: T29 (Phase 3 entry)
  - **Blocked By**: T17-T27

  **References**:
  - T16 phase-1-gate as template.

  **Acceptance Criteria**:
  - [ ] `just phase2-gate` exits 0 only when all checks pass
  - [ ] Per-check status enumerated in JSON
  - [ ] Tag applied on success

  **QA Scenarios**:
  ```
  Scenario: Gate passes when complete
    Tool: Bash
    Steps:
      1. `just phase2-gate; echo "exit=$?"`
      2. `jq -e '.status == "PASS"' .sisyphus/design/phase2-gate.json`
    Expected Result: exit 0; PASS
    Evidence: .sisyphus/evidence/task-28-pass.log

  Scenario: Gate fails when noise-budget test missing
    Tool: Bash
    Steps:
      1. `mv crates/pvthfhe-core/tests/noise_budget.rs /tmp/noise_budget.rs.bak`
      2. `just phase2-gate; echo "exit=$?" | tee /tmp/phase2-fail.log`
      3. `mv /tmp/noise_budget.rs.bak crates/pvthfhe-core/tests/noise_budget.rs   # restore`
      4. `grep -E "noise[-_]budget" /tmp/phase2-fail.log`
    Expected Result: nonzero exit; failure cites noise-budget
    Evidence: .sisyphus/evidence/task-28-fail.log
  ```

  **Commit**: YES
  - Message: `feat(gate): phase 2 gate script + reports`
  - Files: `Justfile`, `.sisyphus/scripts/phase2-gate.{rs|py}`, `.sisyphus/design/phase2-gate.{json,md}`
  - Pre-commit: `just phase2-gate`

- [x] 29. **T29: Cargo workspace + crate layout + lints + deny.toml + CI matrix**

  **What to do**:
  - All 8 crates already exist as workspace members from T1; this task does NOT create or add them. Confirm membership via `cargo metadata --format-version=1 --no-deps | jq '.workspace_members | length'` ≥ 8.
  - Configure shared lints in workspace `[lints.rust]` and `[lints.clippy]`: deny `unwrap_used`, `panic`, `expect_used` outside tests, `as_conversions` selective, `missing_docs`.
  - Update `deny.toml` with allowed licenses + advisory DB.
  - Expand CI matrix from T1's baseline: add **beta toolchain** lane and **macOS** lane; add `cargo deny check` job. The `cargo test --workspace`, `nargo test --workspace` (run from `circuits/`), `forge test --root contracts`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check` jobs already exist from T1 — this task only ADDS the beta+macos+deny dimensions; it does NOT introduce nargo/forge to CI for the first time.
  - Verify the AGENTS.md "working-directory protocol" entry from T1 is honored across all currently-committed QA scenarios (grep test): no `forge` invocation without `--root contracts` or `cd contracts &&`; no `nargo` invocation without `cd circuits` or `--package` from `circuits/`.

  **Must NOT do**: relax clippy globally; let any crate skip lints; permit `unwrap` in non-test code.

  **Recommended Agent Profile**:
  - **Category**: `quick`.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I1 (with T30, T31, T32)
  - **Blocks**: T30, T31, T32, T33-T44
  - **Blocked By**: T22, T28

  **References**:
  - rust-clippy lint groups; cargo-deny book.

  **Acceptance Criteria**:
  - [ ] All 8 crates compile clean (including `pvthfhe-enclave-adapter` placeholder)
  - [ ] `cargo metadata --format-version=1 | jq '.workspace_members | length'` returns ≥ 8
  - [ ] CI matrix runs all 6 jobs green
  - [ ] No `unwrap_used` outside `#[cfg(test)]`

  **QA Scenarios**:
  ```
  Scenario: No unwraps in production code
    Tool: Bash
    Steps:
      1. `cargo clippy --workspace --all-targets -- -D clippy::unwrap_used`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-29-noUnwrap.log

  Scenario: Workspace test suite green
    Tool: Bash
    Steps:
      1. `cargo test --workspace`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-29-tests.log
  ```

  **Commit**: YES
  - Message: `chore(workspace): promote crate layout, lints, deny, CI matrix`
  - Files: `Cargo.toml`, all `crates/*/Cargo.toml`, `deny.toml`, `.github/workflows/ci.yml`
  - Pre-commit: `cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace && cargo deny check`

- [x] 30. **T30: FHE backend trait + chosen-impl wrapper (TDD: RED first)**

  **What to do**:
  - Define `FheBackend` trait in `pvthfhe-fhe`: methods for keygen-share, encrypt, partial-decrypt, aggregate, parameter loading, serialization.
  - RED: write tests against the trait (using a mock impl) before either backend wrapper exists.
  - GREEN: implement primary backend wrapper (per T4 selection — Poulpy or fhe.rs).
  - REFACTOR: extract shared serialization, error types, RNG handling.
  - Provide a `mock` feature flag that supplies a deterministic in-memory impl for unit tests of higher-level crates.

  **Must NOT do**: leak backend types across the trait boundary; implement both backends speculatively (only the selected one is real, the other is a future fallback skeleton); use `unsafe`.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I1
  - **Blocks**: T33, T34, T37, T40, T43
  - **Blocked By**: T20, T22, T28, T29

  **References**:
  - github.com/phantomzone-org/poulpy or github.com/gnosisguild/fhe.rs depending on T4.
  - rust-by-example trait objects.

  **Acceptance Criteria**:
  - [ ] Trait fully documented with rustdoc
  - [ ] Mock impl deterministic; primary impl passes same trait tests
  - [ ] No backend types in public trait signatures

  **QA Scenarios**:
  ```
  Scenario: Trait conformance test runs against both impls
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-fhe --features mock conformance::`
      2. `cargo test -p pvthfhe-fhe conformance::`
    Expected Result: both exit 0
    Evidence: .sisyphus/evidence/task-30-conformance.log

  Scenario: Public API leaks no backend types
    Tool: Bash
    Steps:
      1. `cargo doc -p pvthfhe-fhe --no-deps && grep -rE '(poulpy|fhe_rs)::' target/doc/pvthfhe_fhe/ || echo OK`
    Expected Result: prints OK
    Evidence: .sisyphus/evidence/task-30-leak.log
  ```

  **Commit**: YES (multiple — RED, GREEN, REFACTOR)
  - Message: `feat(fhe): backend trait, mock impl, primary backend wrapper`
  - Files: `crates/pvthfhe-fhe/**`
  - Pre-commit: full workspace test + clippy

- [x] 31. **T31: Cryptographic test-vector harness (golden vectors, property tests)**

  **What to do**:
  - Generate golden vectors from the worked example (T23) for: keygen messages, ciphertexts, partial-decryptions, aggregated proofs.
  - Store as JSON under `crates/pvthfhe-core/tests/vectors/`.
  - Implement test driver that loads vectors, runs implementation, asserts byte-exact match (or canonical-form match for non-deterministic outputs).
  - Add property tests via `proptest`: keygen-decrypt round-trip on random plaintexts; correctness under reordered-but-≥t shares; rejection of (≤t-1)-share or tampered-share inputs.

  **Must NOT do**: regenerate golden vectors silently when implementation diverges; skip negative property tests; let proptest cases be too small to find bugs.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I1
  - **Blocks**: T33, T34, T35, T36, T41
  - **Blocked By**: T23, T29

  **References**:
  - `proptest` book; NIST CAVP-style test-vector format.

  **Acceptance Criteria**:
  - [ ] ≥10 golden vectors loaded
  - [ ] Round-trip prop-test passes 10000 cases
  - [ ] Tampered-share prop-test rejects 100% of cases

  **QA Scenarios**:
  ```
  Scenario: Vectors match worked example
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-core --test vectors`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-31-vectors.log

  Scenario: Tampered shares rejected
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-core --test tamper_props -- --nocapture`
    Expected Result: 0 false acceptances over 10000 iterations
    Evidence: .sisyphus/evidence/task-31-tamper.log
  ```

  **Commit**: YES
  - Message: `test(core): golden vectors + property test harness`
  - Files: `crates/pvthfhe-core/tests/**`

- [x] 32. **T32: Noir + Foundry test harnesses (nargo test runner, forge skeleton)**

  **What to do**:
  - Upgrade the T1 Noir scaffolding: keep all four existing placeholder packages (`share_wf`, `decrypt_share`, `aggregator_final`, `bench/rlwe_relation`) — DO NOT rename or recreate them. Add `nargo fmt` config and ensure `nargo test --workspace` (run from `circuits/`) still passes (T11/T35/T36/T37 will fill the package bodies in their own waves).
  - Set up `contracts/` with Foundry, base test contract `BaseVerifierTest.t.sol` providing common fixtures (params, sample proof bytes).
  - Add `just test-circuits` (runs `nargo test` for every package) and `just test-contracts` (runs `forge test`).
  - Add CI jobs.

  **Must NOT do**: skip `nargo test` in CI; let circuits compile but lack tests; hard-code paths that break across machines.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I1
  - **Blocks**: T35, T36, T38
  - **Blocked By**: T29

  **References**:
  - Noir docs; Foundry book.

  **Acceptance Criteria**:
  - [ ] `just test-circuits` enumerates ≥3 packages
  - [ ] `just test-contracts` runs ≥1 test passing
  - [ ] CI runs both

  **QA Scenarios**:
  ```
  Scenario: Circuit harness runs
    Tool: Bash
    Steps:
      1. `just test-circuits 2>&1 | tee /tmp/c.log`
      2. `grep -E 'tests:.*passed' /tmp/c.log`
    Expected Result: passed line for every package
    Evidence: .sisyphus/evidence/task-32-circuits.log

  Scenario: Contract harness runs
    Tool: Bash
    Steps:
      1. `just test-contracts`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-32-contracts.log
  ```

  **Commit**: YES
  - Message: `chore(circuits,contracts): nargo + foundry harnesses`
  - Files: `circuits/**`, `contracts/**`, `Justfile`, `.github/workflows/ci.yml`

- [x] 33. **T33: Distributed keygen impl (TDD, in-process simulator)**

  **What to do**:
  - Implement keygen per T18 spec in `pvthfhe-aggregator` (or dedicated `pvthfhe-keygen`) using the trait from T30.
  - In-process simulator: spawn N party state machines on async tasks, route messages via a typed in-memory bus that simulates network with configurable delay/drop/duplicate/reorder.
  - RED: tests asserting honest run produces a usable threshold key; tests asserting malicious party (equivocate, malformed proof, withhold) is identified and blamed.
  - GREEN: implementation passes all RED tests.
  - REFACTOR: extract bus/transport for re-use in T34.

  **Must NOT do**: assume synchronous network in the simulator; let blame logic depend on aggregator honesty; commit secret-key material to logs.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I2 (with T34, T35, T36, T37, T38)
  - **Blocks**: T37, T40, T43
  - **Blocked By**: T18, T30, T31

  **References**:
  - T18 spec; tokio test-utils.

  **Acceptance Criteria**:
  - [ ] Honest n=4 run produces threshold key matching golden vector
  - [ ] Each defined adversarial behavior triggers correct blame
  - [ ] No `sk` material in any log line

  **QA Scenarios**:
  ```
  Scenario: Honest n=4 keygen
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-aggregator --test keygen_honest -- --nocapture`
    Expected Result: exit 0; final threshold key matches golden vector
    Evidence: .sisyphus/evidence/task-33-honest.log

  Scenario: Malicious party blamed
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-aggregator --test keygen_malicious -- --nocapture`
    Expected Result: blame report identifies the cheating party id
    Evidence: .sisyphus/evidence/task-33-blame.log

  Scenario: No sk leakage
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-aggregator -- --nocapture 2>&1 | grep -E 'sk_[0-9]+ ?=' || echo OK`
    Expected Result: prints OK
    Evidence: .sisyphus/evidence/task-33-leak.log
  ```

  **Commit**: YES (multiple)
  - Message: `feat(keygen): distributed keygen with in-process simulator + blame`
  - Files: `crates/pvthfhe-aggregator/src/keygen/**`, tests

- [x] 34. **T34: Threshold decryption impl (TDD)**

  **What to do**:
  - Implement partial-decryption per T19 spec: each party produces a decryption share + NIZK; aggregator combines.
  - RED tests first: round-trip on golden vectors; rejection of malformed shares; rejection of (≤t-1)-share aggregation; rejection of tampered ciphertext; correct noise smudging (per T21).
  - GREEN: implementation.
  - REFACTOR.

  **Must NOT do**: skip noise smudging; let aggregator forge a plaintext; trust shares without NIZK verification.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I2
  - **Blocks**: T37, T40, T41, T43
  - **Blocked By**: T19, T21, T30, T31

  **References**:
  - T19 spec; T21 noise budget.

  **Acceptance Criteria**:
  - [ ] Round-trip on goldens
  - [ ] Rejection paths covered (malformed share, t-1 shares, tampered ct)
  - [ ] Noise smudging matches T21 parameters

  **QA Scenarios**:
  ```
  Scenario: Round-trip
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-aggregator --test decrypt_roundtrip`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-34-roundtrip.log

  Scenario: Rejection set
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-aggregator --test decrypt_rejections`
    Expected Result: every defined rejection reason triggers
    Evidence: .sisyphus/evidence/task-34-reject.log
  ```

  **Commit**: YES
  - Message: `feat(decrypt): threshold decryption with verifiable shares`
  - Files: `crates/pvthfhe-aggregator/src/decrypt/**`, tests

- [x] 35. **T35: Noir circuit — share well-formedness (TDD with golden vectors)**

  **What to do**:
  - Implement Noir circuit `circuits/share_wf/` proving the relation declared in T18 NIZK statement.
  - RED: `nargo test` cases — honest witness verifies; tampered witness rejected (≥6 tamper variants).
  - GREEN: implement circuit; verify reproduces golden vector proofs.
  - REFACTOR: extract sub-circuits (poly arithmetic, hash-to-field) into `circuits/lib/`.
  - Generate Solidity verifier via Barretenberg, save bytecode artifact for T38.

  **Must NOT do**: hand-roll hash-to-field if Noir stdlib provides one; expose witness via public inputs; let circuit accept reduced statements (must match T18 exactly).

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I2
  - **Blocks**: T37, T39
  - **Blocked By**: T18, T25, T31, T32

  **References**:
  - Noir stdlib hash + bigint; T18 NIZK statement; T11 micro-bench.

  **Acceptance Criteria**:
  - [ ] Honest proof verifies (`nargo execute` + `bb prove`/`bb verify` flow)
  - [ ] All ≥6 tamper variants rejected
  - [ ] Proof bytes match golden vector
  - [ ] Constraint count within budget set in T15 cost cell

  **QA Scenarios**:
  ```
  Scenario: Honest proof verifies
    Tool: Bash
    Steps:
      1. `(cd circuits && nargo execute --package share_wf --prover-name Prover_honest)`
      2. `(cd circuits && bb write_vk --scheme ultra_honk -b target/share_wf.json -o target)`
      3. `(cd circuits && bb prove --scheme ultra_honk -b target/share_wf.json -w target/share_wf.gz -o target)`
      4. `(cd circuits && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs); echo "exit=$?"`
    Expected Result: every command exits 0
    Evidence: .sisyphus/evidence/task-35-honest.log

  Scenario: Tamper variants rejected
    Tool: Bash
    Steps:
      1. `(cd circuits && for v in tamper_a tamper_b tamper_c tamper_d tamper_e tamper_f; do nargo execute --package share_wf --prover-name "Prover_$v" 2>&1 | tail -1; echo "execute_exit_$v=$?"; done) | tee /tmp/t35-tamper.log`
      2. `grep -cE "execute_exit_tamper_[a-f]=[1-9]" /tmp/t35-tamper.log`   # count failed executions (Noir asserts catch most tampers at witness time)
    Expected Result: count == 6 (all 6 tamper variants either fail at `nargo execute` due to assertion failure, or — if assertions pass — fail at `bb verify`; the test can be extended to fall through to bb when execute succeeds)
    Evidence: .sisyphus/evidence/task-35-tamper.log
    Evidence: .sisyphus/evidence/task-35-tamper.log

  Scenario: Constraint count under budget
    Tool: Bash
    Steps:
      1. `(cd circuits/share_wf && nargo info) | jq -e '.acir_opcodes < 200000'`
    Expected Result: exit 0 (or per T15 cost-cell budget)
    Evidence: .sisyphus/evidence/task-35-constraints.log
  ```

  **Commit**: YES
  - Message: `feat(circuits): share well-formedness Noir circuit + tests`
  - Files: `circuits/share_wf/**`, `circuits/lib/**`

- [x] 36. **T36: Noir circuit — decryption-share correctness (TDD with golden vectors)**

  **What to do**:
  - Implement Noir circuit `circuits/decrypt_share/` proving T19 NIZK statement.
  - RED with honest + tamper cases (≥6 variants).
  - GREEN: implementation; reproduce goldens.
  - REFACTOR: shared lib with T35.
  - Generate Solidity verifier; save artifact for T38.

  **Must NOT do**: prove a weaker statement than T19; share witness representation between T35 and T36 if their algebraic shapes differ; let constraint count blow past T15 cost-cell budget.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I2
  - **Blocks**: T37, T39
  - **Blocked By**: T19, T25, T31, T32

  **References**:
  - T19 NIZK statement; T11 bench.

  **Acceptance Criteria**:
  - [ ] Honest verifies; ≥6 tamper variants rejected
  - [ ] Proof bytes match golden
  - [ ] Constraint count under budget

  **QA Scenarios**:
  ```
  Scenario: Honest + tamper
    Tool: Bash
    Steps:
      1. `(cd circuits && nargo execute --package decrypt_share --prover-name Prover_honest && bb write_vk --scheme ultra_honk -b target/decrypt_share.json -o target && bb prove --scheme ultra_honk -b target/decrypt_share.json -w target/decrypt_share.gz -o target && bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs); echo "honest_exit=$?" | tee /tmp/t36.log`
      2. `(cd circuits && for v in t1 t2 t3 t4 t5 t6; do nargo execute --package decrypt_share --prover-name "Prover_$v" 2>&1 | tail -1; echo "execute_exit_$v=$?"; done) | tee -a /tmp/t36.log`
      3. `grep -q "honest_exit=0" /tmp/t36.log && [ "$(grep -cE 'execute_exit_t[1-6]=[1-9]' /tmp/t36.log)" = "6" ]`
    Expected Result: honest path all exit 0; all 6 tamper variants fail at `nargo execute` (assert failure) or `bb verify` (proof rejection)
    Evidence: .sisyphus/evidence/task-36-cases.log

  Scenario: Constraints under budget
    Tool: Bash
    Steps:
      1. `(cd circuits && nargo info --package decrypt_share) | tee /tmp/t36-info.log`
      2. `python3 -c "import re,sys; t=open('/tmp/t36-info.log').read(); m=re.search(r'(\d[\d,]*)\s+ACIR\s+opcodes|ACIR opcodes[^\d]*(\d[\d,]*)', t); n=int((m.group(1) or m.group(2)).replace(',','')) if m else None; assert n is not None and n < 200000, f'opcodes={n}'"
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-36-constraints.log
  ```

  **Commit**: YES
  - Message: `feat(circuits): decryption-share correctness Noir circuit + tests`
  - Files: `circuits/decrypt_share/**`

- [x] 37. **T37: Recursive aggregation harness (folding tree)**

  **What to do**:
  - Implement folding aggregator per selected architecture (likely HyperNova / MicroNova or LatticeFold+ depending on T17): folds N party-instances into 1 final instance, then a final SNARK is generated for on-chain verification.
  - Use `pvthfhe-aggregator` to drive the fold tree, plumbing through actual party proofs from T35/T36.
  - RED: tests at N ∈ {4, 16, 64, 256} asserting (a) folded final SNARK verifies, (b) tampering any leaf causes rejection.
  - GREEN, REFACTOR.
  - Hook to T12 micro-bench for measurement under real load.

  **Must NOT do**: fold leaf-level trash without per-leaf proof verification; lose soundness across the fold-to-SNARK boundary; skip the tamper test.

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I2
  - **Blocks**: T39, T40, T43
  - **Blocked By**: T12, T25, T30, T33, T34, T35, T36

  **References**:
  - HyperNova / MicroNova / LatticeFold+ refs; T12 bench results.

  **Acceptance Criteria**:
  - [ ] Tests pass at all 4 N values
  - [ ] Tamper-leaf test rejects
  - [ ] Final SNARK size + prover time recorded as bench JSON

  **QA Scenarios**:
  ```
  Scenario: Folded SNARK at N=64
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-aggregator --test folding_n64 -- --nocapture`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-37-n64.log

  Scenario: Leaf tamper rejected
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-aggregator --test folding_tamper -- --nocapture`
    Expected Result: rejected at fold-time AND no final SNARK produced
    Evidence: .sisyphus/evidence/task-37-tamper.log
  ```

  **Commit**: YES
  - Message: `feat(aggregator): recursive folding harness with final SNARK`
  - Files: `crates/pvthfhe-aggregator/src/folding/**`

- [x] 38. **T38: Solidity verifier scaffold + Foundry tests (TDD)**

  **What to do**:
  - Author hand-written `contracts/src/PvtFheVerifier.sol` scaffold (will be replaced by BB-generated in T39, but scaffold tests the integration shape).
  - Write Foundry tests asserting: ABI signature, calldata layout, gas budget, revert on tampered proof, accept on valid proof.
  - RED first; scaffold returns false until T39 plugs in real verifier.

  **Must NOT do**: silently swallow revert reasons; pass dummy data through `verify` without parsing; exceed gas budget set in T15.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I2
  - **Blocks**: T39, T40
  - **Blocked By**: T22, T25, T32

  **References**:
  - Foundry book; T13 KZG bench (reference gas budget).

  **Acceptance Criteria**:
  - [ ] ABI matches T22 spec
  - [ ] All RED tests in place
  - [ ] Gas budget assertion present

  **QA Scenarios**:
  ```
  Scenario: ABI matches spec
    Tool: Bash
    Steps:
      1. `forge inspect --root contracts PvtFheVerifier abi > /tmp/abi.json`
      2. `python3 .sisyphus/scripts/check-abi.py /tmp/abi.json .sisyphus/design/api-spec.md`
    Expected Result: match
    Evidence: .sisyphus/evidence/task-38-abi.log

  Scenario: Gas budget asserted
    Tool: Bash
    Steps:
      1. `forge test --root contracts --match-test testGasBudget`
    Expected Result: passes
    Evidence: .sisyphus/evidence/task-38-gas.log
  ```

  **Commit**: YES
  - Message: `feat(contracts): verifier scaffold + Foundry tests`
  - Files: `contracts/src/PvtFheVerifier.sol`, `contracts/test/**`

- [x] 39. **T39: BB → Solidity verifier generation + on-chain verification test on local Anvil**

  **What to do**:
  - Run Barretenberg's Solidity-verifier generator against the final-SNARK from T37; output replaces scaffold from T38.
  - Wire generated verifier to `PvtFheVerifier.sol` (composition).
  - **Produce golden proof artifacts inside T39** using the T37 prover binary so the Foundry/Anvil tests are self-contained:
    - Add a Rust helper binary `crates/pvthfhe-bench/src/bin/gen_goldens.rs` (Cargo derives bin name `gen_goldens` from the file stem — snake_case throughout to match T23's convention; do NOT use a kebab-case filename) that produces three files committed under `contracts/test/goldens/`: `honest.proof`, `honest.public_inputs.json`, `tampered.proof` (single-bit flip of `honest.proof`). These artifacts are deterministic given a fixed seed (RNG seeded from a constant declared in the helper). Invocation: `cargo run --release -p pvthfhe-bench --bin gen_goldens -- --out <path>`.
    - Files committed: `contracts/test/goldens/honest.proof`, `contracts/test/goldens/honest.public_inputs.json`, `contracts/test/goldens/tampered.proof` (binary blobs are acceptable; they are reproducible via the helper).
  - Implement Foundry tests `contracts/test/PvtFheVerifier.e2e.t.sol` that read these golden files via `vm.readFileBinary` and call the deployed verifier; `forge test` is the primary QA harness (no manual address handling required because Foundry deploys in-test).
  - Implement `contracts/script/DeployVerifier.s.sol` for completeness, but the QA scenario uses `forge test` (which spins up its own EVM) rather than long-running Anvil + manual address copy.
  - Add `just verify-onchain` recipe (replacing the T1 stub) that runs `forge test --match-contract PvtFheVerifier --gas-report` and asserts the gas-report column for `verify` is ≤ 5,000,000 via a small Python helper `.sisyphus/scripts/check-gas.py` (created by T39, not T1, since it is unique to this task — record this addition in the helper inventory).
  - Record concrete gas cost; compare to T15/T13 budget.

  **Must NOT do**: hand-edit BB-generated code (regenerate-only); skip the tampered-proof reverts; exceed 5M gas (or document overrun + plan-amendment for ≤10M ceiling).

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: `playwright` is NOT applicable; pure CLI/EVM.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I3 (with T40, T41, T42, T43, T44)
  - **Blocks**: T40, T45
  - **Blocked By**: T37, T38

  **References**:
  - Barretenberg `bb` CLI; Anvil docs.

  **Acceptance Criteria**:
  - [ ] Generated verifier compiles
  - [ ] Golden artifacts present: `contracts/test/goldens/{honest.proof,honest.public_inputs.json,tampered.proof}`
  - [ ] `forge test --match-contract PvtFheVerifier` passes (honest verifies, tampered reverts)
  - [ ] `just verify-onchain` exits 0 and reports gas ≤5M (hard ceiling 10M)
  - [ ] Goldens are reproducible: re-running the `gen_goldens` helper yields byte-identical files

  **QA Scenarios**:
  ```
  Scenario: Honest proof verifies, tampered proof reverts (Foundry)
    Tool: Bash
    Preconditions: T37 prover available; goldens committed under contracts/test/goldens/
    Steps:
      1. `cd contracts && forge test --match-contract PvtFheVerifier --gas-report -vvv 2>&1 | tee /tmp/t39-forge.log`
      2. `python3 .sisyphus/scripts/check-gas.py /tmp/t39-forge.log --max 5000000 2>&1 | tee /tmp/t39-gas.log`
    Expected Result: forge test reports `[PASS]` for `test_honest_verifies` and `test_tampered_reverts`; gas check exits 0 with `verify gas <= 5,000,000`
    Failure Indicators: any `[FAIL]`; gas exceeds 5M; missing golden file
    Evidence: .sisyphus/evidence/task-39-forge.log, .sisyphus/evidence/task-39-gas.log

  Scenario: just verify-onchain (Anvil deploy round-trip, end-to-end recipe)
    Tool: Bash
    Preconditions: anvil and forge installed; T39 implementation complete
    Steps:
      1. `just verify-onchain 2>&1 | tee /tmp/t39-recipe.log`
    Expected Result: exit 0; log contains "verify_honest PASS" and "verify_tampered PASS"
    Evidence: .sisyphus/evidence/task-39-recipe.log

  Scenario: Goldens are reproducible
    Tool: Bash
    Preconditions: T37 prover binary built
    Steps:
      1. `cargo run --release -p pvthfhe-bench --bin gen_goldens -- --out /tmp/goldens-replay`
      2. `diff -r contracts/test/goldens /tmp/goldens-replay | tee /tmp/t39-diff.log`
    Expected Result: diff is empty (exit 0)
    Evidence: .sisyphus/evidence/task-39-reproducible.log
  ```

  **Commit**: YES
  - Message: `feat(contracts): BB-generated verifier + golden-proof Foundry e2e + just verify-onchain`
  - Files: `contracts/src/generated/**`, `contracts/script/**`, `contracts/test/**` (incl. `contracts/test/goldens/**`), `crates/pvthfhe-bench/src/bin/gen_goldens.rs`, `.sisyphus/scripts/check-gas.py`, `Justfile`

- [x] 40. **T40: CLI binary + n=128 e2e demo**

  **What to do**:
  - Implement `pvthfhe-cli` binary with subcommands: `keygen --n N --t T`, `encrypt --pk PATH --msg MSG`, `partial-decrypt --sk-share PATH --ct PATH`, `aggregate --shares DIR --ct PATH`, `verify --proof PATH --ct PATH --plaintext PATH --rpc URL --addr ADDR`, `demo --n 128`.
  - The `demo --n 128` subcommand runs the full pipeline against the in-process simulator (no Anvil dependency by default; with `--onchain` flag it submits to Anvil).
  - Add `just demo-e2e` recipe.
  - Add a documented walk-through in `.sisyphus/evidence/demo/n128/README.md`.

  **Must NOT do**: leak `sk` material in CLI logs; require interactive prompts (must be scriptable); make demo flaky (must be deterministic given a seed).

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I3
  - **Blocks**: T43, T45
  - **Blocked By**: T30, T33, T34, T37, T39

  **References**:
  - `clap` derive; `tracing` for logs.

  **Acceptance Criteria**:
  - [ ] All subcommands documented in `--help`
  - [ ] `just demo-e2e` runs in <30 min on reference hardware
  - [ ] Demo deterministic across two runs with same seed

  **QA Scenarios**:
  ```
  Scenario: n=128 demo runs end-to-end
    Tool: Bash
    Steps:
      1. `just demo-e2e --seed 1 2>&1 | tee /tmp/demo.log`
      2. `grep -E 'verify: ACCEPT' /tmp/demo.log`
    Expected Result: ACCEPT line present; exit 0
    Evidence: .sisyphus/evidence/task-40-demo.log

  Scenario: Demo deterministic
    Tool: Bash
    Steps:
      1. `just demo-e2e --seed 1 > /tmp/d1.log && just demo-e2e --seed 1 > /tmp/d2.log`
      2. `diff /tmp/d1.log /tmp/d2.log` (modulo timestamps stripped)
    Expected Result: empty diff after timestamp normalization
    Evidence: .sisyphus/evidence/task-40-determ.log
  ```

  **Commit**: YES
  - Message: `feat(cli): CLI binary + n=128 e2e demo`
  - Files: `crates/pvthfhe-cli/**`, `Justfile`

- [x] 41. **T41: Adversarial test suite (malformed shares, tampered proofs, rogue keys)**

  **What to do**:
  - Centralized test crate `crates/pvthfhe-aggregator/tests/adversarial/` exercising every documented threat from T2 + every rejection case from T18/T19. **Canonical layout**: `tests/adversarial/mod.rs` (entry) + one file per case: `rogue_key.rs`, `equivocation.rs`, `withhold_reveal.rs`, `malformed_nizk.rs`, `replay.rs`, `tampered_ciphertext.rs`, `tampered_share.rs`, `threshold_below.rs`, `threshold_above.rs`. T45's negative QA targets `tampered_share.rs` specifically — DO NOT rename without updating T45.
  - Cases: rogue-key attack on keygen, equivocation, withhold-then-reveal, malformed NIZK, replay across sessions, tampered ciphertext, tampered share, t-1 honest parties (must fail to decrypt), >t parties (must still succeed).
  - Each case has a deterministic seed; each asserts both (a) protocol rejects, (b) blame report names the cheater (where applicable).
  - Add `just adversarial-suite` recipe.

  **Must NOT do**: rely on randomized cases without seeds; mark a case "expected to fail" without asserting WHY; couple this suite to backend internals.

  **Recommended Agent Profile**:
  - **Category**: `deep`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I3
  - **Blocks**: T45
  - **Blocked By**: T31, T33, T34, T37

  **References**:
  - T2 threat model; T18/T19 failure modes.

  **Acceptance Criteria**:
  - [ ] All ≥9 cases run and pass
  - [ ] Blame correctly identifies cheater in equivocation/withhold cases
  - [ ] Suite reproducible from seeds

  **QA Scenarios**:
  ```
  Scenario: Adversarial suite green
    Tool: Bash
    Steps:
      1. `just adversarial-suite 2>&1 | tee /tmp/adv.log`
      2. `grep -cE '^test .* \\.\\.\\. ok$' /tmp/adv.log`
    Expected Result: exit 0; test count ≥9
    Evidence: .sisyphus/evidence/task-41-suite.log

  Scenario: Reproducibility
    Tool: Bash
    Steps:
      1. `just adversarial-suite --seed 7 > /tmp/a1.log && just adversarial-suite --seed 7 > /tmp/a2.log && diff /tmp/a1.log /tmp/a2.log`
    Expected Result: empty diff (after timestamp strip)
    Evidence: .sisyphus/evidence/task-41-repro.log
  ```

  **Commit**: YES
  - Message: `test(adversarial): comprehensive malicious-behavior suite`
  - Files: `crates/pvthfhe-aggregator/tests/adversarial/**`, `Justfile`

- [x] 42. **T42: Enclave-style adapter interface (no upstream PR)**

  **What to do**:
  - Implement `crates/pvthfhe-enclave-adapter/` providing the trait-shape declared in T22 that mirrors `gnosisguild/enclave` ciphernode/aggregator boundaries.
  - Provide an integration smoke test using a vendored stub of the Enclave types committed to `crates/pvthfhe-enclave-adapter/vendor-stub/` (a one-time copy of the relevant Enclave type signatures, written explicitly for this plan; NOT a git-submodule, NOT under top-level `vendor/`). Verify our types fit.
  - The vendored stub is created EXACTLY ONCE during T42 execution and is treated as read-only thereafter (locked by `.sisyphus/evidence/integration/enclave-stub-hash.txt` recording its sha256 at creation; subsequent runs verify the hash matches).
  - Document in `.sisyphus/evidence/integration/enclave.md`: how a downstream Enclave-fork would consume our crate, and what changes Enclave would need to make (none required from our side; only adapter glue).

  **Must NOT do**: open an upstream Enclave PR (out of scope); take a runtime dependency on Enclave (vendored stub only); modify the vendor-stub after T42 initial commit (any post-T42 change to `crates/pvthfhe-enclave-adapter/vendor-stub/**` requires explicit plan amendment); place the stub under top-level `vendor/`.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I3
  - **Blocks**: T45
  - **Blocked By**: T22, T30, T33, T34

  **References**:
  - github.com/gnosisguild/enclave (read-only).

  **Acceptance Criteria**:
  - [ ] Adapter crate compiles and tests pass
  - [ ] Smoke test demonstrates trait-shape fit
  - [ ] Vendor-stub committed under `crates/pvthfhe-enclave-adapter/vendor-stub/`; hash file `.sisyphus/evidence/integration/enclave-stub-hash.txt` exists and matches actual stub contents
  - [ ] Doc explains required adapter glue

  **QA Scenarios**:
  ```
  Scenario: Adapter smoke test
    Tool: Bash
    Steps:
      1. `cargo test -p pvthfhe-enclave-adapter --features stub`
    Expected Result: exit 0
    Evidence: .sisyphus/evidence/task-42-smoke.log

  Scenario: Vendor-stub integrity (post-creation lock)
    Tool: Bash
    Steps:
      1. `STUB_HASH=$(find crates/pvthfhe-enclave-adapter/vendor-stub -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)`
      2. `RECORDED=$(cat .sisyphus/evidence/integration/enclave-stub-hash.txt)`
      3. `[ "$STUB_HASH" = "$RECORDED" ]`
    Expected Result: hashes match (exit 0)
    Evidence: .sisyphus/evidence/task-42-stub-hash.log
  ```

  **Commit**: YES
  - Message: `feat(enclave-adapter): trait-shape adapter + vendored stub + smoke test`
  - Files: `crates/pvthfhe-enclave-adapter/**` (includes `crates/pvthfhe-enclave-adapter/vendor-stub/**`), `.sisyphus/evidence/integration/enclave.md`, `.sisyphus/evidence/integration/enclave-stub-hash.txt`

- [x] 43. **T43: Scaling benchmark suite up to n=1024 + reproducibility scripts**

  **What to do**:
  - Run end-to-end benchmark at n ∈ {128, 256, 512, 1024} with the in-process simulator on reference hardware.
  - Measure: per-party prover time, aggregator wall-clock, final SNARK size, verifier on-chain gas (against Anvil), peak memory.
  - Output JSON envelope per T5; produce three figures (time/gas/proof-size vs n) saved to `bench/figures/`.
  - Include `just bench-scaling` recipe and a `bench/scripts/reproduce.sh` script that documents hardware fingerprint capture.
  - Compare measured numbers vs the cost-table predictions in T15 (winning architecture row); flag deviations >2× as anomalies and investigate.

  **Must NOT do**: run on noisy/shared hardware; skip n=1024 because "it takes too long" (parallelize the runs across hardware if needed but document); silently regenerate baselines on regression.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I3 (the runs themselves are sequential per hardware unit, but the n values can run on separate hosts)
  - **Blocks**: T45
  - **Blocked By**: T30, T33, T34, T37, T39, T40

  **References**:
  - T5 envelope; T15 cost predictions.

  **Acceptance Criteria**:
  - [ ] All 4 n values measured
  - [ ] Reproducibility ±15% for compute, ±5% for gas
  - [ ] Predictions vs measurements compared; deviations >2× annotated
  - [ ] Figures committed

  **QA Scenarios**:
  ```
  Scenario: Scaling bench JSONs exist with envelope
    Tool: Bash
    Steps:
      1. `for n in 128 256 512 1024; do jq -e '.mean and .median and .p99 and .stddev and .env.cpu' bench/results/scaling-n$n.json || echo "BAD: n=$n"; done`
    Expected Result: no BAD output
    Evidence: .sisyphus/evidence/task-43-envelopes.log

  Scenario: Reproducibility within tolerance
    Tool: Bash
    Steps:
      1. `bash bench/scripts/reproduce.sh --n 128 --runs 3`
      2. `python3 bench/scripts/check-tolerance.py bench/results/scaling-n128-run{1,2,3}.json`
    Expected Result: max(|run_i - median|/median) < 0.15
    Evidence: .sisyphus/evidence/task-43-tolerance.log

  Scenario: Predictions vs measurements
    Tool: Bash
    Steps:
      1. `python3 bench/scripts/compare-predictions.py .sisyphus/research/cost-comparison.md bench/results/scaling-*.json`
    Expected Result: 0 deviations >2× without annotation
    Evidence: .sisyphus/evidence/task-43-vsmodel.log
  ```

  **Commit**: YES
  - Message: `bench(scaling): n=128..1024 e2e scaling benchmarks + figures`
  - Files: `bench/results/scaling-*.json`, `bench/figures/*.png`, `bench/scripts/**`, `Justfile`

- [x] 44. **T44: Documentation (README, ARCHITECTURE, SECURITY, REPRODUCING)**

  **What to do**:
  - Author top-level `README.md`: project intent, status, quickstart, link to demo.
  - `ARCHITECTURE.md`: high-level diagram + cross-link to T17 selection memo + T18/T19 specs + T25 boundary.
  - `SECURITY.md`: threat model summary + assumptions ledger pointer + responsible-disclosure stub + known limitations.
  - `REPRODUCING.md`: step-by-step to reproduce demo + scaling benchmarks; hardware fingerprint capture; expected runtime/gas. **Pin exact versions** of `nargo`, `bb`, `foundry` (forge/anvil), and Rust toolchain — these versions are what `Dockerfile.quickstart` installs.
  - Author `Dockerfile.quickstart` at repo root (specified in detail in the QA scenario below): `FROM ubuntu:24.04`, installs `just` via apt (Ubuntu 24.04 supports it; Debian Bookworm does not), plus Rust/Foundry/Noir/BB toolchains pinned to versions in `REPRODUCING.md`.
  - `CITATION.cff` for the eventual ePrint preprint.

  **Must NOT do**: claim production-readiness; promise performance numbers not in `bench/results/`; obscure that this is a research artifact.

  **Recommended Agent Profile**:
  - **Category**: `writing`.
  - **Skills**: none.

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave I3
  - **Blocks**: T45
  - **Blocked By**: T17, T18, T19, T25, T40, T43

  **References**:
  - T17, T18, T19, T24, T25 docs; CITATION.cff schema.

  **Acceptance Criteria**:
  - [ ] All 5 documents present and link-checked
  - [ ] Quickstart reproduces deterministically via the agent-executable scenario below (no human steps)
  - [ ] No production-readiness claims (regex check below)

  **QA Scenarios**:
  ```
  Scenario: Link check
    Tool: Bash
    Steps:
      1. `npx --yes markdown-link-check@latest README.md ARCHITECTURE.md SECURITY.md REPRODUCING.md 2>&1 | tee /tmp/lc.log`
      2. `! grep -E '\\[✖\\]|ERROR' /tmp/lc.log`
    Expected Result: exit 0; no broken-link markers
    Evidence: .sisyphus/evidence/task-44-links.log

  Scenario: Quickstart smoke (agent-executable, deterministic)
    Tool: Bash
    Preconditions: Docker daemon running on the host; `docker` CLI available; image `ubuntu:24.04` pullable (Ubuntu 24.04 has `just` available via apt per the casey/just install docs; Debian Bookworm does NOT, so we cannot use `rust:1.85-bookworm` here)
    Steps:
      1. Author `Dockerfile.quickstart` at repo root that:
         - FROM `ubuntu:24.04`
         - Installs apt deps: `git curl jq build-essential pkg-config libssl-dev ca-certificates just python3 nodejs npm`
         - Installs Rust via `rustup` (channel pinned to match `rust-toolchain.toml`)
         - Installs Foundry via `foundryup`
         - Installs Noir via `noirup` (version pinned in REPRODUCING.md): `RUN curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && /root/.nargo/bin/noirup -v <PINNED_NOIR_VERSION>` and put `/root/.nargo/bin` on PATH
         - Installs Barretenberg `bb` CLI via `bbup` (version pinned in REPRODUCING.md): `RUN curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash && /root/.bb/bbup -v <PINNED_BB_VERSION>` and put `/root/.bb` on PATH (final smoke check `bb --version` MUST exit 0 inside the image)
         - Sets `WORKDIR /work`
         - Default CMD: `bash -lc 'just --version && just demo-e2e --seed 1'`
      2. `docker build -f Dockerfile.quickstart -t pvthfhe-quickstart:latest . 2>&1 | tee /tmp/qs-build.log`
      3. `docker run --rm -v "$PWD:/work" -w /work pvthfhe-quickstart:latest 2>&1 | tee /tmp/qs.log`
      4. `grep -E 'verify: ACCEPT' /tmp/qs.log`
      5. `! grep -E '(error|panic|FAIL)' /tmp/qs.log`
    Expected Result: build succeeds; container exits 0; ACCEPT line present; no error/panic/FAIL lines
    Failure Indicators: apt cannot find `just` (means base image is wrong); `nargo: command not found` or `bb: command not found` or `forge: command not found` (means Dockerfile missing a toolchain); demo-e2e exits non-zero
    Evidence: .sisyphus/evidence/task-44-quickstart.log, .sisyphus/evidence/task-44-quickstart-build.log

  Scenario: No production-readiness claims
    Tool: Bash
    Steps:
      1. `! grep -EHni '(production[ -]ready|production[ -]grade|battle[ -]tested|enterprise[ -]ready)' README.md ARCHITECTURE.md SECURITY.md REPRODUCING.md`
    Expected Result: exit 0 (no matches)
    Evidence: .sisyphus/evidence/task-44-prodclaims.log
  ```

  **Commit**: YES
  - Message: `docs: README, ARCHITECTURE, SECURITY, REPRODUCING, CITATION + Dockerfile.quickstart`
  - Files: `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `REPRODUCING.md`, `CITATION.cff`, `Dockerfile.quickstart`

- [x] 45. **T45: Phase 3 gate report — `just phase3-gate` produces JSON + markdown**

  **What to do**:
  - Implement `just phase3-gate` recipe → script that:
    1. Runs full workspace test + clippy + fmt + deny.
    2. Runs `(cd circuits && nargo test --workspace)` and `forge test --root contracts`.
    3. Runs `just demo-e2e` against Anvil (full chain with verifier deployed).
    4. Runs `just adversarial-suite`.
    5. Runs `just bench-scaling` and asserts envelopes + tolerance.
    6. Confirms presence of all required docs (T44) and evidence files for every task QA scenario.
    7. Confirms gas ≤5M (or annotated overrun ≤10M).
    8. Writes `.sisyphus/evidence/phase3-gate.json` and `.sisyphus/evidence/phase3-gate.md` (canonical paths — referenced everywhere in the plan).
  - Tag `phase3-gate-pass`.

  **Must NOT do**: pass with stale benchmarks; allow the gate to silently skip a sub-step; merge code that fails the gate.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`.
  - **Skills**: `git-master`.

  **Parallelization**:
  - **Can Run In Parallel**: NO (single sink)
  - **Parallel Group**: Wave I4
  - **Blocks**: F1-F4 (FINAL wave)
  - **Blocked By**: T29-T44

  **References**:
  - T16, T28 gate scripts as templates.

  **Acceptance Criteria**:
  - [ ] `just phase3-gate` exits 0 only when all sub-steps pass
  - [ ] Per-step status enumerated in JSON
  - [ ] Tag applied on success

  **QA Scenarios**:
  ```
  Scenario: Phase-3 gate passes
    Tool: Bash
    Steps:
      1. `just phase3-gate; echo "exit=$?"`
      2. `jq -e '.status == "PASS"' .sisyphus/evidence/phase3-gate.json`
    Expected Result: exit 0; PASS
    Evidence: .sisyphus/evidence/task-45-pass.log

  Scenario: Gate fails when adversarial suite is broken
    Tool: Bash
    Steps:
      1. `git stash push -m "phase3-gate-negative" -- crates/pvthfhe-aggregator/tests/adversarial/tampered_share.rs`
      2. `python3 -c "import pathlib; p=pathlib.Path('crates/pvthfhe-aggregator/tests/adversarial/tampered_share.rs'); p.write_text(p.read_text().replace('assert!(verify_rejects', 'assert!(!verify_rejects', 1))"   # flip first reject-asserting test`
      3. `just phase3-gate; echo "exit=$?" | tee /tmp/phase3-fail.log`
      4. `git checkout -- crates/pvthfhe-aggregator/tests/adversarial/tampered_share.rs && git stash drop || true   # restore`
      5. `grep -E "adversarial(-suite)?|tampered_share" /tmp/phase3-fail.log`
    Expected Result: nonzero exit; failure cites adversarial-suite
    Evidence: .sisyphus/evidence/task-45-fail.log
  ```

  **Commit**: YES
  - Message: `feat(gate): phase 3 gate script + reports`
  - Files: `Justfile`, `.sisyphus/scripts/phase3-gate.{rs|py}`, `.sisyphus/evidence/phase3-gate.{json,md}`
  - Pre-commit: `just phase3-gate`

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.
> Do NOT mark F1-F4 checked before user okay. Rejection → fix → re-run → present again → wait.

- [x] F1. **Plan Compliance Audit** — `oracle`
  Read this plan end-to-end. For each "Must Have" line: verify the artifact/behavior exists (read file, run command, query verifier on-chain). For each "Must NOT Have" guardrail: search the codebase for forbidden patterns and reject with file:line on any hit. Confirm every gate report (`phase1-gate.json`, `phase2-gate.json`, `phase3-gate.json`) exists, passes, and includes the mandated fields. Confirm `.sisyphus/evidence/` contains evidence files for every task QA scenario.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Gates [3/3 pass] | Evidence [N/N tasks] | VERDICT: APPROVE/REJECT`

- [x] F2. **Code Quality & Crypto-Slop Review** — `unspecified-high`
  Run `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`, `(cd circuits && nargo test --workspace)`, `forge test --root contracts`, `cargo deny check`. Review every changed Rust/Noir/Solidity file for: hand-rolled crypto primitives (NTT, hash-to-field, transcript, RNG, serialization) when standard exists; `.unwrap()` outside tests; empty catches; `console.log`/`println!` in prod; commented-out code; magic constants without parameter-file linkage; over-generic traits with one impl; proc-macros hiding crypto; "constant-time" claims without evidence; missing golden vectors; missing negative tests; generic names (`data`, `tmp`, `Helper`, `Manager`).
  Output: `Build [PASS/FAIL] | Lint [PASS/FAIL] | Tests [N pass / N fail] | Files [N clean / N issues] | Crypto-slop [N issues] | VERDICT`

- [x] F3. **Real Manual QA** — `unspecified-high`
  Start from clean checkout. Execute EVERY QA scenario from EVERY implementation task — exact steps, capture evidence to `.sisyphus/evidence/final-qa/`. Run `just demo-e2e` and capture the n=128 walk-through. Run `just bench-scaling` and capture the n ∈ {128, 256, 512, 1024} results. Run `just verify-onchain` against fresh Anvil and capture transaction traces. Test cross-task integration: keygen → encrypt → threshold-decrypt → on-chain verify in a single flow. Test edge cases: t-1 honest parties (must fail), t honest parties (must succeed), tampered share, tampered proof, malformed ciphertext.
  Output: `Scenarios [N/N pass] | E2E demo [PASS/FAIL] | Scaling bench [N/N points pass] | On-chain [PASS/FAIL] | Adversarial [N/N reject correctly] | VERDICT`

- [x] F4. **Scope Fidelity Check** — `deep`
  For each task: read its "What to do" section, then read the actual diff in git for that task's commits. Verify 1:1 correspondence: every spec item was built (no missing); nothing beyond spec was built (no creep). Check "Must NOT do" compliance per task. Detect cross-task contamination: Task N touching files owned by Task M outside the declared interface. Flag any unaccounted commits. Verify scope guardrails (Must NOT Have list) absent.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN / N issues] | Unaccounted commits [CLEAN / N] | Scope guardrails [N/N respected] | VERDICT`

→ Present consolidated F1-F4 results to user. Wait for explicit "okay". On rejection or feedback: fix → re-run → present again.

---

## Commit Strategy

- **TDD discipline**: each task produces at least 2 commits — RED (failing test) and GREEN (implementation passes test). REFACTOR commits as needed.
- **Per-task commit format**: `type(scope): description (task-N)` where type ∈ {feat, fix, test, docs, bench, ci, chore, refactor, build}, scope is a crate or area
- **Pre-commit hooks**: `cargo fmt --check && cargo clippy -- -D warnings && cargo test -p <crate-touched>` for Rust; `nargo fmt --check && nargo test` for Noir; `forge fmt && forge test` for Solidity
- **No squash-merging Phase deliverables**: each phase's commits are preserved for archaeology
- **Tag at gates**: `git tag phase1-gate-pass`, `phase2-gate-pass`, `phase3-gate-pass` after each `just phaseN-gate` succeeds

---

## Success Criteria

### Verification Commands
```bash
just phase1-gate          # Expected: exit 0; emits .sisyphus/research/phase1-gate.json
just phase2-gate          # Expected: exit 0; emits .sisyphus/design/phase2-gate.json
just phase3-gate          # Expected: exit 0; emits .sisyphus/evidence/phase3-gate.json
cargo test --workspace    # Expected: 0 failures
cargo clippy --workspace -- -D warnings   # Expected: 0 warnings
(cd circuits && nargo test --workspace)   # Expected: all circuit tests pass
forge test --root contracts                # Expected: all Solidity tests pass
just demo-e2e             # Expected: n=128 e2e succeeds, on-chain verifier returns true
just bench-scaling        # Expected: bench-{128,256,512,1024}.json all generated, scaling within projection
just verify-onchain       # Expected: deployed verifier accepts valid proof, rejects 5+ adversarial proofs
just reproduce-bench      # Expected: numbers within ±15% of published baseline
```

### Final Checklist
- [x] All "Must Have" deliverables exist and pass their verification commands
- [x] All "Must NOT Have" guardrails respected (verified by F4)
- [x] All three phase gates emit machine-readable artifacts and exit 0
- [x] All tests (Rust + Noir + Solidity) pass
- [x] BB-generated Solidity verifier deployed to local Anvil and verifies a real threshold-decryption proof
- [x] n=128 e2e demo runs end-to-end
- [x] Scaling benchmarks at n ∈ {128, 256, 512, 1024} match the projected O(n) per-party / O(polylog n) verifier
- [x] Reproducibility verified by `just reproduce-bench` from a clean checkout
- [x] All evidence files for QA scenarios present in `.sisyphus/evidence/`
- [x] User explicit "okay" given after F1-F4 review wave
