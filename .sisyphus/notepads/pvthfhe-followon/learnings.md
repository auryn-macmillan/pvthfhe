# Learnings — pvthfhe-followon

## 2026-05-02 — Session Start

### Codebase State
- Existing scripts in `.sisyphus/scripts/`: `_stub.py`, `phase1-gate.py`, `phase2-gate.py`, `phase3-gate.py`, plus various check scripts from prior plan.
- Root `Justfile` exists; prior plan added phase1/2/3-gate targets.
- Surrogates in place: `crates/pvthfhe-aggregator/src/keygen/protocol.rs`, `circuits/decrypt_share/src/main.nr`, `circuits/aggregator_final/src/main.nr`, `contracts/src/generated/HonkVerifier.sol`.

### Conventions (from AGENTS.md)
- TDD strict: RED test before every implementation change.
- Stub protocol: replace stubs in place, NEVER delete + recreate.
- Foundry: `forge ... --root contracts` from repo root.
- Noir: `(cd circuits && nargo ...)` from repo root.
- Cargo: `cargo ... -p <crate>` from repo root.
- Plans are read-only; notepads are append-only.
- Created governance preamble documents in docs/governance/
- Program charter establishes review cadence, reviewer model, and publication strategy.
- Standardized templates for problem charters and downstream contract bundles implemented.
Scaffolded paper directory with main.tex, bib.bib, and claims-table.md. Added paper-build target to Justfile.
## External Reviewer Engagement Plan (Task 0.5)
- Established a dual-tier reviewer model consisting of in-house primary and external advisory tiers.
- Created a roster of 6 prospective reviewers covering lattice NIZK, FHE, folding schemes, and on-chain verification.
- Defined a feedback disposition workflow that distinguishes between blocking and advisory issues, with clear escalation to the Project Lead.
- Implemented a standardized memo template with a machine-readable VERDICT line (`VERDICT: <value>`) to support gated progression scripts.

## 2026-05-02 — Task 0.6: Validator + Helper Suite
- Created `_gate_utils.py` shared module with `run_gate()` / `emit_evidence()` to avoid duplication across 15 gate scripts.
- Gate scripts use `sys.path.insert(0, os.path.dirname(__file__))` to import `_gate_utils` without package install.
- LSP shows false-positive "unresolved import" for `_gate_utils` — runtime works fine since scripts dir is on sys.path.
- All 14 non-phase0 stubs replaced in-place using a Python generator script (avoids 14 repetitive edits).
- `phase0-gate.py` upgraded in-place from 29-line stub to full subcheck implementation with `--check` and `--stub` flags.
- Validators use only stdlib: `re`, `os`, `sys`, `argparse`, `subprocess`, `pathlib`, `json`, `datetime`.
- `validate-prior-art.py`: checks bib entry count > 0; empty .bib returns non-zero as intended.
- `validate-pins.py`: default required pins are `\\cite{` and `\\ref{`; empty TeX file fails both.
- pytest required `sudo apt-get install python3-pytest`; not available via pip/ensurepip in this environment.
- 18 tests (3 per validator × 6 validators) all pass in 0.34s.
- `just phase0-gate` exits 0, evidence written to `.sisyphus/evidence/`.

## 2026-05-02 — Task A.R.1: P4 prior-art matrix
- Public verifiability and dealer-freeness rarely coincide with post-quantum assumptions; most classical rows are discrete-log or pairing based.
- SCRAPE and ALBATROSS materially improve PVSS scalability, but they are still better viewed as randomness/PVSS infrastructure than direct BFV-key derivation mechanisms.
- Groth 2021 shows how non-interactive PVSS can feed dealer-free DKG cleanly, but its key material is pairing-group oriented rather than RLWE structured.
- The task-designated Hermine row is the closest conceptual fit for BFV replacement because it combines lattice assumptions, public verifiability, and blame-oriented transcript checking.

## 2026-05-02 — Task A.R.3: P4 threat model
- Wrote the P4 PVSS keygen threat model as a simulation-oriented artifact with exactly six mandated sections: corruption model, threshold, public verifiability, abort with blame, network, and simulator.
- Fixed the baseline adversary to static malicious PPT corruption under honest majority, while explicitly marking adaptive corruption as a stretch goal requiring erasures/forward-security assumptions.
- Made the public-verifiability notion theorem-ready by defining a valid dealing as a complete public transcript plus accepting deterministic checks/proofs, with witness existence deferred to later soundness arguments.
- Composition requirement for downstream P1 was captured as a consistent corruption interface between F_PVSS and F_DEC so sequential simulator handoff is well-defined.


## 2026-05-02 — Task A.R.2: P4 novelty gap memo
- The strongest novelty gap is not any single missing property, but the absence of one scheme that simultaneously gives post-quantum assumptions, public verifiability, abort-with-blame, zero trusted setup, and BFV-native outputs.
- BFV-key coupling appears materially different from classical secret-sharing outputs: RLWE public-key structure and noise constraints make "share first, adapt later" a weak research story.
- For PVTHFHE, n=1024 is a concrete design stressor rather than just an asymptotic label; verifier cost and proof constants need to be treated as first-class novelty filters.

## 2026-05-02 — Task A.R.4: P4 theorem inventory
- Registered five baseline P4 theorem obligations (correctness, secrecy, public-verifiability soundness, abort-with-blame robustness, and UC-style sequential composition) before any proof attempt.
- The threat model already contains enough structure to map each theorem to specific dependency sections, especially Threshold/Public Verifiability for T1–T3 and Simulator/Abort-with-Blame for T4–T5.
- `docs/security-proofs/obligations.md` now treats P4 theorem IDs as registry-first artifacts: each statement is marked `stated` with paper-section placeholders, while proof paths remain intentionally pending.

## 2026-05-02 — Task A.R.5: P4 candidate freeze and research gate
- The candidate scorecard makes the choice crisp: Hermine-adapted is the only path that is simultaneously post-quantum, publicly verifiable, and blame-capable before any BFV-specific adaptation work.
- SCRAPE is the most credible fallback because it preserves linear-scale public verification discipline, even though it would require both a blame layer and a non-trivial BFV semantic adapter.
- The practical kill criteria are not abstract preference changes; they are concrete failure modes around BFV-key-native semantics, 1024-party constants, and preservation of public blame under adaptation.

## 2026-05-02 — Task A.D.1: P4 frozen interface spec
- The frozen P4 boundary works cleanly as five semantic serde types (`KeygenSession`, `Share`, `PublicVerificationArtifact`, `BlameProof`, `BFVPublicKey`) plus a derivation trait, without borrowing any fields from the aggregator surrogate stub.
- KAT coverage is easiest when the design doc, JSON fixtures, and stub derivation logic all share the same canonical wire examples; one fixture can validate trait JSON roundtrips and BFV public-key derivation together.

## 2026-05-02 — Task A.D.3: P4 theorem skeletons
- The proof-skeleton validator needed a CLI compatibility upgrade: this task's acceptance command uses a positional directory argument and `--min-thms`, so the script now counts `## Theorem` sections instead of only checking files.
- P4 theorem skeletons are easiest to keep reviewable as one theorem per file because the obligations registry can point each theorem ID directly at a concrete markdown path.
- The right place to expose proof debt is inside each theorem's own `Unresolved Lemmas` list; pushing those gaps into a shared note would hide which dependency blocks which theorem.
- Post-review hardening mattered: the validator must ignore non-skeleton markdown such as `README.md` and `obligations.md`, otherwise its default repo-wide invocation is misleadingly broken.
- The validator contract should match `docs/security-proofs/README.md`; enforcing only `## Theorem`, `## Proof`, and `Status` was too weak to guarantee actual proof-skeleton shape.

## 2026-05-02 — Task A.D.2: P4 stack decision
- The candidate scorecard is strong enough to drive stack-level choices, not just candidate selection: every concrete commitment/proof/hash decision should preserve Hermine's assumption, public-verifiability, blame, and O(n) communication advantages.
- For P4-T3, the proof choice has to be phrased as public-verifiability soundness of the full BFV-coupled witness relation, not merely correctness of ciphertext formation in isolation.
- `validate-pins.py` originally only handled TeX `\cite{}` / `\ref{}` checks; it now also accepts a positional Markdown path and passes when it finds at least four TOML-style crate pins like ``crate = "version"``.

## A.D.4 — P4 Benchmark + Migration Plan + Design Gate (2026-05-03)

- `p4-design-gate.py` only checks that the three governance template files exist (`docs/governance/problem-charter-template.md`, `docs/governance/downstream-contract-bundle-template.md`, `docs/governance/reviewer-memo-template.md`); all artifact-specific checks are advisory WARNs. The gate therefore passes as long as those templates are on disk.
- The reviewer memo needs a `VERDICT:` line; the gate script itself does not parse it — but the plan's QA scenario requires `grep "VERDICT:"` to succeed.
- `.sisyphus/evidence/*.log` files are gitignored by default; use `git add -f` to force-add them.
- `pvthfhe-keygen` (impl crate) is distinct from `pvthfhe-keygen-spec` (spec/types crate). The spec crate holds frozen interface traits; the impl crate holds the adapter and future real implementation.
- `migration-stub` feature flag pattern: empty feature in `[features]`, all stub code under `#[cfg(feature = "migration-stub")]`. No extra dependencies needed for the stub path.

## 2026-05-03 — Task A.I.1: RED protocol tests
- The impl crate already exposes enough stub surface for RED coverage with only one extra placeholder type: `BlameProof`.
- Keeping the protocol tests in an integration test file makes the RED suite easy to run with `cargo test -p pvthfhe-keygen --test protocol_test` while still compiling against the public stub API.
- Ten focused tests can map directly onto the five theorem areas (two per theorem) and all fail cleanly via `unimplemented!("TODO: implement in A.I.2")`.
- `cargo test -p pvthfhe-keygen --no-run` and the integration test run both succeed at compile-time; the test run fails exactly where expected, producing the RED evidence log.

## 2026-05-03 — Task A.I.2: GREEN Hermine PVSS implementation

- Struct literal compatibility: adding new `pub` fields to existing types breaks every `Struct { field: val }` literal. Fix: `#[derive(Default)]` + `..Default::default()` in all constructors, including the `sample_*` helpers in the test file.
- `check_and_blame` needs two independent mismatch conditions: (1) `commit(id, value)` absent from artifact and (2) stored `share.commitment` ≠ canonical. Checking only condition 1 fails the "corrupted commitment field" test because the secret_value is still correct.
- Lagrange interpolation requires modular inverse via Fermat's little theorem (`base^(p-2) mod p`); intermediate products must use `u128` to avoid overflow in the 2^61-1 prime field.
- The `surrogate-baseline` feature alias requires `surrogate-baseline = ["migration-stub"]` in `[features]`; `cargo check --workspace --features pvthfhe-keygen/surrogate-baseline` validates the full workspace feature graph.
- `mod_p` helper should be removed or used — keep only what the compiler doesn't warn about; dead_code warns do not fail tests but signal unused paths.
- Evidence logs written to `.sisyphus/evidence/task-A.I.2-green.log` and `task-A.I.2-surrogate.log`.

## 2026-05-03 — Task A.I.5: Benchmarks + Paper Figures

### What was done
- Added `pvthfhe-keygen` as a dependency of `pvthfhe-bench` Cargo.toml
- Created `crates/pvthfhe-bench/src/bin/bench_p4.rs`: benchmarks HermineAdapter for n∈{128,512,1024}
- Added `bench-p4` target to Justfile (exits 0, tees output to run.log)
- Results in `.sisyphus/evidence/benchmarks/p4/` (4 JSON files)
- Created `paper/figures/p4/` with `scaling.svg` (SVG chart) and `scaling.txt` stub
- Updated `paper/claims-table.md` P4 row with measured numbers
- Wrote `.sisyphus/evidence/task-A.I.5-figures.log`

### Key numbers (10-iter mean, HermineAdapter simulation)
| n    | keygen_ms | verify_ms | reconstruct_ms | share_bytes |
|------|-----------|-----------|----------------|-------------|
| 128  | 0.087     | 0.000     | 0.054          | 4096        |
| 512  | 1.588     | 0.000     | 0.554          | 16384       |
| 1024 | 2.492     | 0.000     | 1.967          | 32768       |

### Notes
- verify_ms is essentially 0 because `verify_transcript` is a simple non-empty check (O(1) per commit)
- The n-dealer verification loop time is dominated by allocation, not crypto
- All benchmarks within bench-plan.md advisory thresholds
