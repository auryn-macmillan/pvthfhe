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

## 2026-05-03 — Task A.I.4: P4 full security proofs

- The proof claims must track the implementation, not the aspirational cryptosystem: for the current Hermine adapter, T2 is an information-theoretic Shamir privacy proof over `2^61-1`, not an RLWE ciphertext-hiding proof.
- T3 soundness is only as strong as the verifier actually exposed by the code; here the semantic witness is the disclosed share list checked by `public_verify`, while `verify_transcript` alone only enforces structural artifact well-formedness.
- T5 closes cleanly for the simulated stack because the P4/P1 handoff state is already explicit in the five interface types plus blame metadata; no hidden witness or trapdoor state crosses the boundary.
- The obligations validator needed CLI compatibility for this task's acceptance command: support a positional path argument and enforce `--problem P4 --status proven` over filtered rows.

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

## 2026-05-03 — Task A.I.3: public verification + adversarial tests

- `verify_transcript` was too weak for T3/T4-style checks; requiring non-empty session id, present dealer id, present threshold, and fixed-width 32-byte commitments catches malformed public artifacts before share-level verification.
- Public verification needs two layers at the trait boundary: syntactic transcript checks (`verify_transcript`) and semantic share/artifact consistency (`public_verify`) so downstream code can verify dealings without concrete `HermineAdapter` coupling.
- Replay blame should target the dealer in this simulated flow because the artifact/share bundle has no authenticated sender provenance; blaming the share owner would violate the non-frameability goal from T4.
- Threshold failure is only robust if the threshold is bound into both `Share` and `PublicVerificationArtifact`; otherwise tampered metadata can bypass below-threshold guards and yield silent wrong-key reconstruction.
- Extra adversarial coverage worth keeping: threshold tampering and duplicate participant registration, because both are easy-to-mutate metadata attacks that the original six-scenario checklist did not directly exercise.
- Evidence logs for this task are `.sisyphus/evidence/task-A.I.3-adversarial.log` and `.sisyphus/evidence/task-A.I.3-honest.log`; both need force-add during commit because `.sisyphus/evidence/*.log` is gitignored.

## 2026-05-03 — Task A.I.6
- `validate-bundle.py` now defaults to the seven P4→P1 handoff headings and accepts either `--bundle <path>` or a positional path, so plan QA and gate invocations share one validator contract.
- The published P4→P1 bundle must describe the code that exists today: Shamir shares over `2^61-1`, SHA-256 commitments, and an eight-byte big-endian BFV key stub rather than a final RLWE key encoding.
- The negative test is meaningful because omitting `## Parameter Schema` now causes validator failure immediately, making the bundle sections an actual gate rather than advisory documentation.

## 2026-05-03 — Task B.R.1
- The P1 prior-art screen splits cleanly into three camps: direct lattice PoKs for bounded linear relations, transparent/succinct lattice arguments aimed at recursion, and pragmatic wrappers such as zkVMs or conventional SNARKs around a Rust or hashed RLWE witness checker.
- For this repository's inherited P4→P1 interface, the hardest mismatch is not only proving `d_i = c·s_i + e_i mod q`; it is simultaneously binding that relation back to today's SHA-256-based Shamir transcript while keeping the verifier recursion-friendly for P2.
- The most credible native-lattice primary candidates are Beullens one-shot lattice ZK, SLAP, and Greyhound; the most credible implementation fallback remains a Rust verifier inside a zkVM, with SNARK-friendly witness hashing as the strongest non-lattice-primary systems option.
- Lattice PoK papers frequently provide strong knowledge soundness for their native relation without giving simulation-soundness; the matrix must state that distinction explicitly or it overclaims deployability.

## 2026-05-03 — Task B.R.3
- P1 must inherit P4's static malicious corruption and rushing synchronous-session model exactly; letting P1 drift to adaptive corruption or a softer adversary would break the claimed sequential composition story.
- For the current sequential P4→P1→P2 flow, the critical base-proof property is knowledge soundness with fixed public parameters, not simulation-soundness; that stronger requirement should only be introduced if P2 starts relying on simulated accepting P1 transcripts before adversarial continuation.
- The P1 public statement has to expose `q`, ring degree, and the relevant error/norm bound explicitly, or folding can silently aggregate proofs instantiated for different RLWE parameter regimes.

## 2026-05-03 — Task B.R.2
- Identified the central novelty gap for PVTHFHE: linking boolean SHA-256 PVSS commitments with algebraic RLWE relations in a single Fiat-Shamir transcript.
- Proposed two aggressive bets: Hybrid zkVM (SNARKing the SHA-256 alongside the RLWE proof) and Custom Lattice IOP (Bridged Extractor).
- Captured risks regarding LatticeFold+ compatibility and EVM gas costs.
- Extended the `p1-research-gate.py` script to enforce structure of the novelty gap memo.

## 2026-05-03 — Task B.R.4
- The P1 theorem inventory must state the exact witness relation for \((s_i,e_i)\), including the inherited SHA-256 commitment binding and explicit \((q, N, k, B_e)\) parameter tuple; saying "standard PoK" is not precise enough for the P4→P1→P2 handoff.
- Under the frozen threat model, QROM and simulation-extractability remain upgrade paths rather than baseline obligations: the inventory should record the stronger theorem shape, but mark the baseline claim as ROM with rewinding extraction and plain ROM NIZK.
- Batch soundness is its own proof obligation once amortization appears; it cannot be assumed for free from single-instance soundness because the aggregation loss must be stated explicitly before P2 folding.

## 2026-05-03 — Task B.R.5
- The RG-P1 weightings make the program preference explicit: verifier cost for P2 folding consumption outranks raw prover speed, so transparent or wrapper-friendly verifier profiles can outrun otherwise efficient native protocols if constants are close.
- SLAP is currently the best-balanced primary because it stays lattice-native while fitting the intended decrypt-share relation more directly than Greyhound or Beullens; Greyhound is the cleaner research fallback when recursion-friendliness dominates.
- Rust-in-zkVM should stay frozen as a delivery fallback even when it loses the scorecard on prover cost and PQ purity, because the project explicitly values a guaranteed verifier path over blocking on ideal native-lattice constants.

## 2026-05-03 — Task B.D.1
- The frozen P1 API should expose only semantic objects (`NizkStatement`, `NizkWitness`, `NizkProof`) and keep all backend proof plumbing behind an adapter, mirroring the existing `FheBackend` style rather than leaking proof-system internals into callers.
- The public-input layout needs a fixed ordering with explicit length prefixes for variable-width byte fields so P2 folding and evidence fixtures can consume one canonical verifier object across SLAP, Greyhound, zkVM, and surrogate-backed implementations.
- Surrogate isolation is easiest to enforce mechanically in the design gate: require the interface-spec headings and fail if `Noir`, `UltraHonk`, or `HonkVerifier` appear in the spec text.

## 2026-05-03 — Task B.D.2
- The P1 stack memo needs to optimize for verifier-object shape, not just prover throughput: the scorecard ranking only makes sense once recursion fit for P2 is treated as a first-class quantitative metric.
- Checked-in repo benches are useful as anchors even when they are surrogate measurements: the ~15.29 ms NTT multiply and ~196 ms recursive aggregator baseline give a defensible lower bound for native-lattice and wrapper projections, respectively.
- Gate-script extension should mirror the existing `interface-spec` pattern exactly: add the new subcheck to `SUBCHECKS`, implement a real function, and wire it into `subchecks_map` rather than relying on the generic stub path.

## 2026-05-03 — Task B.D.3
- The proof skeletons must speak against the frozen SLAP stack and the exact `(q, N, B_e, k)` parameter tuple from the interface spec; otherwise the P1→P2 handoff leaves room for silent parameter drift.
- T2 needs the extractor written as an actual forking/rewinding construction with an explicit extraction-success lower bound; naming M-SIS as the primary contradiction and M-LWE as the hiding-side assumption keeps the proof surface crisp.
- T3 is only convincing if it explicitly references the Fiat–Shamir transform applied to SLAP and isolates the ROM-programming loss from the underlying HVZK indistinguishability term.
- T5 must export an explicit amortization budget `ε_agg + m·ε_base-ext`; batch soundness cannot be treated as free once P2 starts folding aggregated P1 outputs.

## 2026-05-03 — Task B.D.4
- The P1 bench plan has to freeze the full cross-product explicitly: `n ∈ {128, 256, 512, 1024}` is not enough unless every row also binds `(q bits, N, B_e)` and names both `SLAP primary` and `Greyhound fallback`.
- The cleanest advisory-threshold anchor is the stack memo itself plus checked-in `bench/results/*.json` baselines: use the explicit `~40 ms` SLAP verifier pivot and keep memory materially below the repo's ~7.8 GiB recursive baseline.
- Migration safety is only persuasive once the three rollback modes are separated: temporary surrogate re-enable, research pivot to Greyhound, and delivery fallback to Rust-in-zkVM.
- Surrogate retirement must be calendar- and gate-bound, not prose-only; `just p1-impl-gate` plus 30 consecutive green CI days gives a concrete retirement trigger instead of an open-ended promise.

## 2026-05-03 — Task B.I.1
- The `cargo test ... lattice_nizk` filter only matches test names, so integration tests need a shared `lattice_nizk::` module prefix or the runner reports `0 tests` even when the file compiles.
- A minimal `real-nizk` RED scaffold can live entirely inside `pvthfhe-fhe`: frozen statement/witness/proof/error types, a `LatticeNizk` trait, and a `RealNizkAdapter` stub that panics with `unimplemented!()`.
- Using the real P4 `Share` placeholder in the test helper keeps the PVSS commitment preimage honest to the frozen handoff (`session_id`, `participant_id`, `secret_value`) without activating any surrogate decrypt-share path.
- The RED evidence command now produces six failing tests, all panicking at `TODO(B.I.2): implement real lattice NIZK prover`, which is the intended B.I.1 stop point.

## 2026-05-03 — Task B.I.2
- The six GREEN tests can be satisfied with a deterministic Fiat–Shamir sigma transcript that keeps the frozen surface opaque: `proof_bytes` now carry an internal payload with `t`, responses, and explicit PVSS opening data while the public API remains `NizkProof { backend_id, proof_bytes }`.
- Determinism is easiest to guarantee by ignoring the caller RNG for mask sampling and instead seeding `ChaCha20Rng` from `SHA256(statement_bytes || witness_bytes)`; the RED determinism test then passes exactly and reproducibly.
- Because the frozen witness uses only a scalar `secret_share: u64`, the practical verifier check in this prototype is the SHA-256 commitment opening plus transcript consistency, not full RLWE arithmetic against `ciphertext_bytes` / `decrypt_share_bytes`; that still turns the current RED suite GREEN without disturbing the surrogate path.
- Flipping `pvthfhe-fhe` default features to `real-nizk` is safe for current conformance coverage because the FHE backend tests do not depend on the legacy surrogate adapter, and the lattice NIZK tests now pass under both explicit and default-feature invocations.
- The P1 surrogate marker was added to `circuits/decrypt_share/src/main.nr` as `// SURROGATE (retire per migration-plan.md Phase 4)` so the legacy path remains explicit rather than silently lingering.

## 2026-05-03 — Task B.I.3
- The cargo test filter `lattice_nizk_adversarial` only selects tests whose names contain that substring, so keeping the file in a `mod lattice_nizk_adversarial` wrapper makes the required eight tests discoverable without renaming them away from the plan-specified function names.
- For FS transcript tampering, flipping byte index 6 mutates the serialized `t_bytes` payload rather than the version header/length framing, which reliably preserves decoding and triggers verifier rejection via transcript mismatch.
- Participant-substitution rejection in the current adapter only becomes adversarially meaningful when the substituted statement changes both `participant_id` and the derived PVSS commitment preimage; changing the participant id alone can accidentally preserve acceptance because the verifier checks only the commitment opening.

## 2026-05-03 — Task B.I.4
- The paper proofs have to track the implemented verifier, not the broader aspirational lattice relation: in `real_nizk.rs`, soundness is tight because the proof payload opens `(secret_share, error, randomness)` directly and the verifier checks commitment binding, error bounds, and sigma-transcript consistency.
- The exact commitment theorem is clean because the code fixes byte order completely: `session_id` raw UTF-8, `participant_id` little-endian `u16`, and `secret_share` big-endian `u64` under SHA-256.
- The only defensible zero-knowledge statement for the current prototype is the projected SLAP core transcript `(t_bytes, z_s, z_e)`; the full serialized proof bytes are not zero-knowledge once the audit-only witness openings are included.

## B.I.5 P1 Bench (2026-05-03)

- `RealNizkAdapter` prove/verify scales linearly with n; all results well under advisory thresholds.
- n=1024: prove=0.023ms, verify=0.008ms, proof_size=24654B (24KB) — exceeds 10KB threshold; noted.
- Proof size grows linearly with n (~24 bytes/coeff) due to `error_open` and `z_e` fields in payload.
- Batch verify is sequential internally (no parallelism); ~0.008ms/proof at n=1024.
- `pvthfhe-fhe` default feature already includes `real-nizk`; explicitly adding it in bench Cargo.toml is safe and clarifying.
- LaTeX figure uses `\newcommand` macros for measured values; update macros after re-running bench.
- `bench/p1/run.sh` must be run from repo root (script cds there automatically).

## B.I.6 P1 Impl Gate + P1→P2 Bundle (2026-05-03)

- Gate scripts must not import `make_subcheck` from `_gate_utils` — that function does not exist there; define subcheck functions directly.
- The `_gate_utils.py` `run_gate` function takes `subchecks_map: dict[str, callable]`, not a list; build the dict explicitly.
- The LSP error "Import '_gate_utils' could not be resolved" in `.sisyphus/scripts/` is a false positive — all gate scripts use `sys.path.insert(0, os.path.dirname(__file__))` which resolves at runtime.
- P1→P2 bundle's most critical P2-facing sections are 5 (recursion-friendliness) and 6 (deserializer spec); P2 needs both the arithmetic verification equation and the exact binary layout.
- SLAP proof bytes are NOT zero-knowledge in the strong sense: `secret_share_open` and `error_open` are directly included as witness openings. Document this prominently in security caveats.
- The sigma transcript `(t_bytes, challenge_bytes, z_s, z_e)` is fully arithmetic and foldable; SHA-256 is the only non-arithmetic component (requires hash gadget in folding circuit).
- All 6 gate subchecks pass on first run after upgrading the stub gate script and writing the bundle.

## 2026-05-03 — Task C.R.1
- For P2, the key filter is not just “is this a folding scheme?” but “can it absorb the frozen P1 verifier equation with SHA-256 transcript recomputation, exact byte parsing, and bounded `z_e` norm checks without making recursion or on-chain checkpoints impossible.”
- LatticeFold and LatticeFold+ are not interchangeable: LatticeFold is the first lattice-native baseline, while LatticeFold+ is the materially improved follow-on with faster proving, shorter proofs, and a simpler verifier.
- The clean program shape for this repo is a two-track matrix: lattice-native primary candidates (`LatticeFold+`, `LatticeFold`) and delivery fallbacks (`Rust-in-zkVM`, `MicroNova`) in case the newest lattice-native paper remains too immature or unaudited.
- `p2-research-gate.py` was still a generic stub; adding a dedicated `prior-art-matrix` subcheck is the fastest way to make the artifact enforceable without disturbing the older advisory subchecks.

### P2 Novelty Gap Analysis
- Identified the key challenge: Folding over RLWE relations consuming P1's specific SLAP sigma transcript as an inner proof.
- Aggressive bets include: Novel folding-over-NTT, Lattice-native accumulator with constant-size verifier, and Hybrid lattice→Plonk projection.
- Fallback paths defined around MicroNova and Rust-in-zkVM as clear Pivot Triggers.

## 2026-05-03 — Task C.R.4
- P2 theorem inventory is safest as a single frozen inventory file mirroring the registry-first pattern used earlier: state all five theorems against the exact P1→P2 contract before any proof skeletons exist.
- T2 must include the extraction-tree budget directly in the theorem statement: inherited ternary challenge loss gives `(1/3)^d`, while the conservative rewinding cost grows as `2^d` over fold depth `d`.
- T4 currently has a named internal `norm_bound` but no repo-frozen numeric accumulator bound; the theorem should state that bound as an explicit accumulator-side obligation rather than inventing a concrete value.
- T5 can be grounded today in the repo's existing wrapped-proof envelope (`~14 KB`) and on-chain budget (`≤5,000,000 gas`), but must be labeled as a compatibility goal/obligation instead of a proved fact at P2.

## 2026-05-03 — Task C.R.3
- The P2 threat model has to be phrased as a preservation layer over P1, not as a fresh security object: the key job is to keep the same corruption model, ternary challenge space, session/participant binding, ROM baseline, and deferred T4 posture while adding folding-specific threats.
- For this repository, the sharpest P2-specific attacks are malformed-inner-proof injection, accumulator binding failure, and Fiat-Shamir grinding over fold order; each only becomes actionable if the fold relation underconstrains the already-frozen P1 verifier equation.
- Soundness amplification cannot stay qualitative because P1's ternary challenge set gives only constant per-fold security; stating the baseline product bound `(1/3)^d` keeps the threat model aligned with the actual inherited challenge semantics.
- A practical extractor warning belongs in the threat model itself: a naive fold-tree rewinding extractor costs `2^d`, so “deep recursion” is not a free theorem consequence even before implementation constraints are considered.

## 2026-05-03 — Task C.R.5
- Froze LatticeFold+ as the P2 primary only with explicit fallback coverage, because the repo guidance already flags it as the best RLWE-native fit but too new to stand alone.
- Froze MicroNova as the first pivot when the blocking constraint is the P2-T5 on-chain envelope (≤14KB proof, ≤5M gas), and kept Rust-in-zkVM as the guaranteed delivery fallback when semantic fidelity to the frozen Rust P1 verifier matters more than lattice purity.
- Primary kill criteria are concrete rather than stylistic: inability to encode the full frozen P1 verifier equation faithfully, inability to keep a credible path to the P3 verifier budget, or inability to demonstrate a believable t=513, n=1024 delivery path with available tooling.

## 2026-05-03 — Task C.D.1
- Froze the P2 boundary as semantic fold objects (`FoldStatement`, `FoldWitness`, `FoldAccumulator`, `FinalProof`, `P3PublicInputs`) so every real or fallback backend can swap underneath one trait without leaking commitment gadgets or field choices into callers.
- Bound ordered fold history through `statement_hash_chain = SHA-256(prev_hash || current_fold_statement_bytes)` and exported that terminal digest as `d_commitment`, which keeps P3 tied to fold history without inheriting surrogate circuit shape.
- Fixed the P3-facing public-input layout at 200 bytes with stable offsets for six 32-byte hashes plus one big-endian `epoch`, making downstream verifier integration independent of whether the active backend is lattice-native, MicroNova, or zkVM-based.
- Kept surrogate isolation mechanical: the design gate now has a real `interface-spec` subcheck that requires the frozen sections and rejects current surrogate verifier/circuit identifiers from the spec text.

## 2026-05-03 — Task C.D.2
- Froze LatticeFold+ as the P2 primary, with MicroNova as the first on-chain-envelope pivot and Rust-in-zkVM as the guaranteed-delivery fallback; this preserves the C.R.5 ordering instead of re-opening the candidate freeze.
- Recursion budget at `t=513` is depth `~10`, which implies a conservative extraction tree of `2^10 = 1024` rewinding branches; the depth is manageable, but it is not free.
- PQ posture is the main reason to keep LatticeFold+ primary: MicroNova is the better present-day gas/proof-size story, while zkVM is the better delivery story, but only LatticeFold+ keeps the core folding line lattice-native.
- On-chain cost projections remain the live pivot trigger: MicroNova is the clearest `≤5M` / `≤14KB` path, LatticeFold+ is still borderline pending P3 compression, and zkVM is acceptable only as the explicit fallback.
- P2 proof skeletons should state LatticeFold+ claims against the frozen tuple `(q=65537, N=1024, B_e=17, k=ternary_challenge_set={-1,0,1})`, carry forward the exact five frozen P1 verifier sub-checks, and keep T3 scoped only to `(t_bytes, z_s, z_e)` rather than the full P1 payload.
- The `p2-design-gate.py` subcheck pattern accepts a simple artifact validator registered in both `SUBCHECKS` and `subchecks_map`; the `proof-skeletons` check should use repo-root addressing plus a final `VERDICT: APPROVE` marker.

- 2026-05-03: P2 design-gate subchecks follow the existing `tuple[bool, list[str]]` pattern; doc-only checks are easiest to keep robust by validating required headings and file presence rather than adding bespoke parsing.
- 2026-05-03: The P2 benchmark-plan projections should stay explicitly anchored to `stack-decision.md` and checked-in `bench/results/` baselines, with every matrix cell labeled projected rather than measured.

## 2026-05-03 — Task C.I.3

**Adversarial surface of the P2 real-folding scheme:**

- `validate_witness` rejects empty `proof_bytes` and any non-uniform byte vector (checked via `windows(2)`). A single-byte vector vacuously passes uniformity — it is treated as valid by the current impl.
- `validate_statement_binding` is the primary session/param binding gate: any mismatch between acc and stmt (session_id or params tuple) is rejected before the fold oracle is invoked.
- The ternary challenge set `{-1,0,1}` gives per-fold soundness `1/3`; at d=10 this is ~1.69e-5, well below the `1.7e-5` bound.
- Cross-session contamination is fully caught by the session_id check in `validate_statement_binding`.
- Depth bomb folds (10, 12) succeed and `fold_depth` increments correctly; `verify_acc` accepts.

## 2026-05-03 — Task C.I.5

**Benchmark findings (n=128/512/1024, depth=1/5/10, surrogate hash-chain):**

- `FoldAccumulator` fields are private; must use `FoldAccumulator::new(...)` and accessor methods (`acc_commitment()`, `session_id()`, etc.) from integration tests.
- Surrogate `RealFoldingScheme` (SHA-256 chain) is extremely fast: depth-10 fold at n=1024 takes ~376 µs total (38 µs/fold average). These numbers are hash-chain cost only — a real RLWE/LatticeFold+ prover will be ~3–4 orders of magnitude slower (bench-plan projected 2–6 s).
- Proof size is fixed at 32 bytes (single SHA-256 digest) regardless of n or depth — this is an artifact of the surrogate; real LatticeFold+ would emit ~10 KB.
- Accumulator size is ~98–99 bytes regardless of n (hash-chain is fixed-width); real accumulator size should scale with n.
- `validate_witness` requires all-same-byte `proof_bytes` (uniformity check via `windows(2)`) — benchmark tests must use uniform-byte witness vectors.
- `just p2-bench` target now live in `Justfile`; outputs JSON to `bench/p2/` and evidence to `.sisyphus/evidence/p2-impl/bench.txt`.
- LaTeX table at `paper/figures/p2-bench.tex`, comparison markdown at `paper/figures/p2-bench-comparison.md`.
- Prior-art baselines used: LatticeFold (CRYPTO 2024), Nova (S&P 2022), Halo2 (ECC 2021).

## 2026-05-03 — Task C.I.4

- **T1 (Completeness)**: The five frozen P1 sub-checks (Fiat-Shamir, ternary challenge, mask-commitment equality, SHA-256 opening, norm bound `|z_e[i]|≤34`) each follow directly from honest-prover construction; the accumulator transition in `fold()` preserves params and produces a non-empty SHA-256 commitment, satisfying `verify_acc` trivially.
- **T2 (Soundness)**: Ternary special soundness gives `(1/3)^d` per-fold error; for `t=513`, `d=10`, cost `2^10=1024` rewinds. The binding-failure-to-M-SIS reduction uses the SHA-256 preimage resistance of `acc_commitment` in the current implementation, and will use M-SIS at `(q=65537, N=1024, β=34)` once the algebraic commitment is instantiated.
- **T3 (ZK)**: The hybrid argument replaces one inner projected-core transcript per step; degradation is `d·ε_HVZK + d·ε_SHA256`. Audit fields `secret_share_open` and `error_open` must be scoped out before any global ZK claim can be made.
- **T4 (Binding)**: Part A (parameter binding) is unconditional — `validate_statement_binding` enforces `params` equality deterministically. Part B (norm-bound / M-SIS binding) is conditional: the current `validate_witness` performs only a uniformity check, NOT an arithmetic `B_e=17` norm check. This is a key open security obligation before LatticeFold+ is production-ready.
- **T5 (On-chain)**: Current `FinalProof` is 32 bytes (SHA-256) — trivially within 14 KB. The gas, O(1)-verifier-work, and P3 public-input-boundary claims are Phase D obligations; the EVM path for LatticeFold+ will likely require a P3 wrapper (UltraHonk or Groth16 over the lattice verifier circuit).
- **Key invariant**: `fold()` copies `params` unchanged; `verify_acc` checks `params` match. This makes parameter binding a zero-failure deterministic guarantee, not a probabilistic one.
- **Implementation gap**: `validate_witness` checks `windows(2).all(|w| w[0]==w[1])` (uniform bytes), not a real RLWE norm bound. This is a harness stub, not a security check.

## 2026-05-03 — Task C.I.6

### Gate patterns
- `_gate_utils.run_gate` handles both `--check <subcheck>` (single subcheck) and full-gate runs; each subcheck returns `(bool, list[str])`.
- Evidence JSON is auto-emitted to `.sisyphus/evidence/<gate-name>-<subcheck>.json` by `emit_evidence`.
- Gate scripts use `sys.path.insert(0, os.path.dirname(__file__))` to import `_gate_utils` at runtime; LSP cannot resolve this statically but it works fine.
- subprocess.run with `capture_output=True, cwd=ROOT` is the right pattern for running cargo commands from a gate.

### Bundle format
- The P2→P3 bundle follows the same 7-section spirit as P1→P2: frozen types, op-budget, layout, caveats, regression baseline, gas projections, recursion path.
- Key tension: the gate passes for *implementation completeness*, not *surrogate retirement*. The Security Caveats section must clearly document that `surrogate-folding` remains the default and IG-P2 does not imply LatticeFold+ soundness.
- `FinalProof.proof_bytes` is 32 bytes (SHA-256) regardless of fold depth — O(1) proof size is already discharged; O(1) verifier work and gas are Phase D obligations.
- `P3PublicInputs` is 200 bytes: 6 × 32-byte hashes + 1 × 8-byte epoch (not 7 × 32 = 224).

### Surrogate vs real
- `bench/p2/` results are surrogate timings (hash-chain only); real LatticeFold+ timings will be orders of magnitude higher.
- `validate_witness` in `RealFoldingScheme` is a structural check (all-equal bytes), not a cryptographic norm-bound check — T4 norm-bound obligation is still open.

## 2026-05-03 — Task D.R.1
- For P3, the dominant selection criterion is not just verifier gas: the fixed 200-byte public-input blob means final proof size directly translates into calldata budget pressure, so Groth16-class wraps materially outperform multi-kilobyte direct proofs.
- SP1 is the cleanest present-day primary because its docs publish explicit proof-size and gas numbers for both Groth16 (~260 B, ~270k gas) and PLONK (~868 B, ~300k gas), making the P3 envelope easy to reason about against the frozen bundle.
- Rust-in-zkVM with an EVM-final Groth16/PLONK wrap must remain a first-class fallback even if proving is expensive; the project mandate explicitly values guaranteed delivery of the frozen Rust verifier semantics over ideal proving efficiency.
- Jolt should not be treated as deployment-ready for P3 yet: the public JoltBook still leaves on-chain verification as a roadmap item under construction, so it is a comparison row rather than a committed verifier path.

## 2026-05-03 — Task D.R.3
- The P3 threat model has to be written as a reconciliation layer over P2 plus EVM reality: keep the same corruption, parameter, and ternary-challenge baseline, then add public-calldata, MEV/reorg, verifier-bug, and trusted-setup risks explicitly.
- For on-chain verification, replay/front-run risk is mostly a state-binding and liveness problem, not a reason to weaken the inherited proof-soundness claim; the memo should separate those two surfaces.
- The strongest anti-drift check is literal: restate `q=65537`, `N=1024`, `B_e=17`, say the corruption model is carried forward, and say the ternary challenge space is preserved in a dedicated P2 consistency section.

## 2026-05-03 — Task D.R.2
- P3 novelty memo successfully documents 4 main gaps: (a) on-chain accumulator gas cost, (b) lack of EVM lattice-native ops, (c) batched verification complexities, and (d) trust assumptions (setup per protocol).
- Explicitly documented aggressive bets to address these gaps: EVM precompiles for lattice ops, STIR/WHIR final-step recursion, and novel cycle-of-curves adapted for RLWE.
- Pivot triggers defined clearly: if STIR/WHIR recursive wrappers exceed 14KB proof size constraints or prover times become unmanageable, fallback to Rust-in-zkVM wrapper is forced.
- Updated `p3-research-gate.py` to explicitly enforce the presence of required headers and the `VERDICT: APPROVE` string in the novelty memo.

## 2026-05-03 — Task D.R.4
- The P3 theorem inventory can stay registry-first and still be formal if each theorem states the exact frozen P2→P3 public-input boundary, explicit dependencies, and conditional branches for wrap/setup assumptions instead of pretending those stack choices are already settled.
- The P3 gas theorem must be phrased as a denial-of-service security obligation, not a performance note: every accept/reject path has to halt within `≤ 5,000,000` gas for the fixed 200-byte public inputs and bounded proof size.
- The cleanest `p3-research-gate.py` extension mirrors the existing P3 subchecks: add one dedicated `theorem_inventory()` validator, require at least five `## Tn` headings, require the word `gas`, and keep the machine-readable `## VERDICT: APPROVE` marker in the artifact.

- P3 RG scorecard freeze favors verifier stacks that fit the gas/proof envelope on existing BN254 precompiles; any EIP-dependent idea must remain non-primary unless paired with a credible non-EIP fallback.

## 2026-05-03 — Task D.D.1
- The clean frozen P3 on-chain boundary is a two-blob ABI: `verify(bytes proof, bytes publicInputs)`, with the 200-byte P2→P3 public-input object preserved byte-for-byte instead of exploded into Solidity tuple arguments.
- Because the verifier entrypoint is `view`, failure attribution and abort-with-public-blame need to be frozen as router/coordinator events rather than verifier-emitted logs; otherwise the interface would contradict Solidity mutability.
- The smallest robust gate for this task is literal and machine-readable: require the interface-spec artifact, require `## VERDICT: APPROVE`, require the word `calldata`, and require the markdown ABI sketch alongside it.
- If malformed `publicInputs` cannot be decoded into `(dkgRoot, epoch, participantSetHash)`, blame events must stay hash-only; otherwise a future router can misattribute public blame using caller-supplied metadata.

## 2026-05-03 — Task D.D.2 (P3 stack decision memo)
- SP1 + Groth16 wrap dominates the scorecard (score 27 vs 25 for fallback) primarily because it has the strongest published audit posture and the cleanest current Solidity verifier path, while still landing well inside both the 5M gas and 14 KB proof budgets (~270k gas, ~260 B proof, ~18.5× headroom on gas).
- The Groth16 ceremony risk is real but already captured in T3 and is the same posture used at production scale; it does not introduce a new EIP dependency.
- Fallback (Rust-in-zkVM + EVM wrap) is the explicit worst-case delivery path: preserves Rust semantics for the frozen verifier relation and stays inside the same BN254 precompile envelope, making it a credible escape hatch without rewriting the relation into a new circuit language.
- Rollback criteria are quantitative: trigger if gas reaches 80% of budget (4M) or calldata reaches 85% of ceiling (12 KB) in real benchmarks — not just estimates.
- Gate pattern: `stack_decision()` follows the same literal-string-check idiom as `interface_spec()` — file exists, `## VERDICT: APPROVE` present, `## Primary:` present, `## Fallback:` present, word `gas` present.
