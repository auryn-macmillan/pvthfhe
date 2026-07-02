# Meta-Plan: Surrogate Removal, Dangling Plan Execution, and C7 Research

**Status**: DRAFT — pending Momus review
**Created**: 2026-06-30
**Parent**: None (new meta-plan, consolidates ~15 dangling plans)
**Goal**: Systematically eliminate all remaining surrogates, execute high-priority dangling plans, remove Track A from paper, and launch a C7 research phase.

---

## 0. Pre-Flight: Nova Removal Verification

**Finding**: Nova IS fully removed. Zero hits for `nova-snark`, `arecibo`, `folding-schemes`, `sonobe` in any Cargo.toml. The feature flag `nova-compressor` remains as a legacy name but activates `enable-latticefold`. Track A code (~4,800 lines) was deleted in `c2155cf`.

**Action**: Skip `fix-ivc-verify-p3.md` and `performance-optimization-sub5s.md §A.3a` (both target deleted Nova code). The `nova-compressor` feature flag name is cosmetic — not blocking.

---

## Phase A: Documentation Cleanup (~2 days)

**Principle**: Remove Track A entirely, don't document it. Replace surrogates, don't catalog them.

### A.1 — Remove Track A from paper (~1 day)

| Task | Files | Description |
|------|-------|-------------|
| A.1a | `paper/main.tex` | Delete §6.A "Track A: Sonobe Nova IVC (Concrete)" — entire section (lines 198-285), including all P2-A-T1 through P2-A-T5 theorems and benchmarks. Keep the removal notice as a single historical sentence in §6 introduction. |
| A.1b | `paper/main.tex` | Rename §6.B "Track B: LatticeFold+ over RLWE (Target) [SOLE BACKEND]" → §6 "P2: LatticeFold+ over RLWE" (drop Track A/B nomenclature throughout). Update all cross-references. |
| A.1c | `paper/main.tex` §1 (architecture) | Update to describe LatticeFold+ as the sole folding backend without Track A qualifiers. Remove "Both tracks share the same P4..." sentence. |
| A.1d | `paper/main.tex` §7 (P3) | Remove ecrecover surrogate description. Describe UltraHonk via Noir wrapping MicroNova as the compression path. Note remaining open problem P4 (full LatticeFold+ on-chain verification). |
| A.1e | `paper/claims-table.md` | Delete all Track A rows (P2-A-T1 through P2-A-T5). Rename P2-B-T* → P2-T*. Remove "Track A" / "Track B" / "SURROGATE" / "TARGET" provenance columns — only one backend exists now. |
| A.1f | `paper/main.tex` §8 (conclusion) | Remove references to dual-track architecture. State single-backend LatticeFold+ status with open problems. |
| A.1g | `paper/main.tex` §B (references) | Remove `nova2022`, `sonobe` citations if no longer referenced. |
| A.1h | `paper/artifact-appendix.md` | Update to remove Sonobe Nova references. |

**Gate**: `paper/main.tex` contains zero mentions of "Track A", "Sonobe", or "ecrecover" in substantive sections.

### A.2 — Update ARCHITECTURE.md (~1 hr)

| Task | Files | Description |
|------|-------|-------------|
| A.2a | `ARCHITECTURE.md` | Remove "Sonobe Nova Nova", "Sonobe", "Track A" references. Update to reflect LatticeFold+ as sole folding backend. Remove the "(Track A, now removed)" parentheticals — just describe what exists. |
| A.2b | `ARCHITECTURE.md` | Update P3 section to describe UltraHonk compression path. Note P4 open problem. |
| A.2c | `ARCHITECTURE.md` | Remove dual-track architecture diagram if present. |

**Gate**: `ARCHITECTURE.md` contains zero mentions of "Sonobe" or "Track A".

---

## Phase B: Surrogate Removal (~3 days)

**Principle**: Remove remaining surrogates, don't document them. Replace with real cryptographic operations or fail-closed errors.

### B.1 — Remove keygen encrypted-share fallback (~1 day)

| Task | Files | Description |
|------|-------|-------------|
| B.1a | `crates/pvthfhe-aggregator/src/keygen/simulator.rs:766` | Replace `encrypted_shares.insert(recipient_id, vec![0x11, 0x22])` in the `None` branch with an error: `return Err(anyhow!("recipient {} has no public key registered", recipient_id))`. In a correct demo pipeline, all recipient keys should be in `all_pks`. The silent fallback to a 2-byte surrogate masks configuration bugs. |
| B.1b | `crates/pvthfhe-aggregator/src/keygen/simulator.rs:41,73` | Replace `let session_id = [0x11; 32]` with a real session_id derivation (hash of epoch + participant set). |
| B.1c | Tests | Add RED test: keygen with missing recipient key → error (not silent surrogate). Add GREEN test: real encrypted shares roundtrip decrypt. |

**Gate**: Zero hits for `[0x11, 0x22]` in non-test simulator code. Keygen produces real BFV ciphertexts for all parties.

### B.2 — Replace accumulator placeholder with real transcript codec (~2 days)

**Note**: This overlaps with plan `a1-accumulator-transcript.md`. Execute that plan's AC1-AC13 acceptance criteria.

| Task | Files | Description |
|------|-------|-------------|
| B.2a | `crates/pvthfhe-nizk/src/adapter.rs:898-917` | Replace the "empty accumulator placeholder" logic with the versioned accumulator codec from `pvthfhe-cyclo/src/accumulator_codec.rs`. The codec already exists — wire it into the adapter's `append_accumulator_to_proof` and verification dispatch. |
| B.2b | `crates/pvthfhe-cyclo/src/accumulator_codec.rs` | Verify all 10 codec unit tests pass. Ensure codec handles: versioning, params_digest binding, norm bounds, duplicate participant IDs, depth/instance-count consistency, no trailing bytes. |
| B.2c | `crates/pvthfhe-nizk/src/adapter.rs` | Implement `verify_accumulator_transcript` dispatch that calls the real codec's `decode` → `verify` path instead of the fail-closed stub. Check: session_id, params_digest, norm_bound, fold_depth, commitment/pub_io lengths, participant membership. |
| B.2d | Tests | 13 acceptance criteria from `a1-accumulator-transcript.md`: empty non-folded still verifies (backward compat), tampered commitment rejected, wrong norm bound rejected, depth/instance mismatch rejected, etc. |

**Gate**: `append_accumulator_to_proof` produces real coded accumulator bytes. `verify_accumulator_transcript` accepts real transcripts and rejects 11 adversarial variants.

---

## Phase C: Quick Improvements (~4 days)

### C.1 — Fix scheme-switch + TFHE gates (~1 day)

Execute plan `scheme-switch-fix-tfhe-gates.md`.

| Task | Files | Description |
|------|-------|-------------|
| C.1a | Compressor glue | Pre-populate `SCHEME_SWITCH_DATA` before compressor init — fix R1CS constraint mismatch. |
| C.1b | `tfhe_ops.rs` | Implement `tfhe_not`, `tfhe_and`, `tfhe_or`, `tfhe_xor` in Poulpy backend. |
| C.1c | Tests | 6/6 scheme_switch tests pass. All gate roundtrips produce correct boolean results. `just poulpy-all` completes all phases. |

### C.2 — Sigma repetition for 2^-128 soundness (~1.5 days)

Execute tasks 1-3 from `p1-sigma-repetition.md` (core repetition — defer the full 30-task plan).

| Task | Files | Description |
|------|-------|-------------|
| C.2a | `crates/pvthfhe-nizk/src/sigma.rs` | Add `PROVE_REPETITIONS` constant (default 90) and `prove_multi` / `verify_multi` wrappers that run the sigma protocol in parallel rounds. |
| C.2b | `crates/pvthfhe-nizk/src/adapter.rs` | Wire `prove_multi` into `CycloNizkAdapter::prove()` and `verify_multi` into `verify()`. |
| C.2c | Tests | Verify 90-round parallel repetition soundness: 2 rounds accept honest witness, 2 rounds reject tampered witness with probability > 1/2 per round. Document that 90 rounds achieves 2^-128 soundness budget. |

**Gate**: `CycloNizkAdapter` uses 90-round repetition. Tampered witness rejected. No regression in existing NIZK tests.

### C.3 — Share-commitment binding assertion (~0.5 day)

Execute plan `close-all-gaps.md §C3`.

| Task | Files | Description |
|------|-------|-------------|
| C.3a | `crates/pvthfhe-cli/src/full_pipeline.rs` | Add `assert_eq!(decoded_pvss_commitment, expected_share_commitment)` in the NIZK verify phase after CycloNizkAdapter::verify succeeds. |
| C.3b | Tests | Adversarial test: tampered share commitment → verification fails at assertion, not silently. |

**Gate**: Share commitment binding enforced. Tampered commitment rejected.

---

## Phase D: Medium Implementations (~5 days)

### D.1 — A1 Accumulator Transcript (~3 days)

Execute full plan `a1-accumulator-transcript.md`. This overlaps with B.2 above — the codec already exists (`accumulator_codec.rs`), so this phase focuses on the verification dispatch and adversarial test suite.

| Task | Files | Description |
|------|-------|-------------|
| D.1a | `crates/pvthfhe-nizk/src/adapter.rs` | Complete `verify_accumulator_transcript` with full dispatch: session_id check, params_digest binding, norm_bound ≤ beta_at_t, fold_depth validation, commitment/pub_io length checks, participant membership, per-instance ajtai_commitment_hash, no trailing bytes, duplicate ID rejection. |
| D.1b | Tests | 13 acceptance criteria (AC1-AC13): tampered commitment, wrong norm, depth mismatch, duplicate IDs, empty placeholder backward compat. 5 fail-closed tests. 6 adversarial tests. |
| D.1c | `crates/pvthfhe-aggregator/src/folding/mod.rs` | Wire `append_accumulator_to_proof()` after each fold step. |

**Gate**: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator` passes. `cargo test -p pvthfhe-cyclo fold_verify` passes.

### D.2 — Greco E3 Compute Provider (~2 days)

Execute plan `greco-e3-compute-provider.md` (standalone BFV encryption proofs + FHE compute provider).

| Task | Files | Description |
|------|-------|-------------|
| D.2a | New: `bfv_snapshot.rs` | Standalone BFV encryption proof circuit. |
| D.2b | New: `fhe_compute_circuit.rs` | FHE compute step circuit with Add, Mul, NoiseEval operations. |
| D.2c | `Justfile` | Add `just bfv-snapshot-prove`, `just bfv-snapshot-verify`, `just fhe-compute-prove` commands. |
| D.2d | Benchmarks | Benchmark constraint counts at N=4096, 8192. Compare against CRISP Noir approach. |

**Gate**: Both initiatives have working CLI commands. Benchmarks compared against CRISP. Demo-e2e no regression.

---

## Phase E: Large Implementations (weeks)

### E.1 — C5: Aggregate PK Formation Proof

Execute plan `c5-formation-proof.md`. Full formation proof with Proof-of-Possession per party, on-chain binding, adversarial tests.

**Effort**: ~2 weeks. New circuit, new prover/verifier, Solidity integration.

### E.2 — C7: Threshold Decryption Correctness — Research Phase

**Principle**: Do NOT settle on a specific solution yet. The user has indicated that a more novel approach may be needed beyond the O(n²) Lagrange recombination in the current `c7-correctness.md` plan.

| Task | Description | Deliverable |
|------|-------------|-------------|
| E.2a | **Literature survey** | Survey lattice-friendly approaches to threshold decryption verification: (1) Schwartz-Zippel over RLWE rings — evaluate at multiple random points for soundness amplification without O(n²) in-circuit cost; (2) precomputed Lagrange coefficients as public inputs (already partially explored in `c7-correctness.md`); (3) random linear combination of share evaluations; (4) ProtoGalaxy-style multi-instance folding of per-share evaluation proofs; (5) any recent ePrint papers on verifiable threshold FHE decryption. |
| E.2b | **Prototype 2-3 approaches** | Implement minimal prototypes at N=8 to compare constraint counts, proof sizes, and soundness budgets. Approaches must scale to N=8192 without O(n²) blowup. |
| E.2c | **Decision memo** | Write `.sisyphus/design/c7-solution-decision.md` comparing approaches with concrete constraint estimates at N=8192, proof size estimates, soundness analysis, and implementation complexity. Include a go/no-go recommendation. |
| E.2d | **Gate** | Decision memo approved before ANY production C7 implementation begins. |

**Effort**: ~2-3 weeks for research phase. Implementation deferred to post-decision.

### E.3 — Lattice Folding Improvements

Execute the `p2-lattice-folding.md` plan (Task 2 only — actual batch folding) adapted for the Cyclo backend (not the deleted Nova code).

| Task | Description |
|------|-------------|
| E.3a | Port batch fold concept from `symphony-adoption.md` T1 to `pvthfhe-cyclo/src/driver.rs`. Add `fold_all_batched` that computes random linear combination Σ β_i · inst_i then calls `fold_one_step` once per batch rather than once per instance. |
| E.3b | Add `batch_fold_arity` parameter to `CycloParams` (default: 10, matching `sequential_t`). |
| E.3c | Benchmarks at H=20,50,100,1024 comparing sequential vs batched fold time. |
| E.3d | Verify batch fold produces identical accumulator to sequential fold. |

**Effort**: ~2 days (porting from Nova design to Cyclo implementation, plus benchmarks).

### E.4 — P4: On-Chain IVC Verification

Execute plan `p4-onchain-ivc.md`. UltraHonk-wrapped RecursiveSNARK verification replacing the Poseidon hash shortcut.

**Effort**: ~12.5 days. Requires: Noir circuit for RecursiveSNARK verify, UltraHonk proof generation, Solidity verifier update, gas measurement and optimization.

### E.5 — LatticeFold+ Full Integration

Execute plan `latticefold-plus.md`. Replace all Nova compressor remnants with lattice-native LatticeFold+ folding. This is the strategic direction documented in `lattice-meta-plan.md`.

**Note**: This overlaps with E.3 — coordinate. Full integration is the end state; E.3 provides an intermediate improvement.

**Effort**: ~24 hours for core integration, plus integration testing across all step circuits.

---

## Phase F: Cross-Cutting Verification

### F.1 — Gate Testing

After each phase, run:

```bash
cargo check --workspace
cargo test -p pvthfhe-cyclo --lib
cargo test -p pvthfhe-aggregator --lib
cargo test -p pvthfhe-nizk --lib
cargo test -p pvthfhe-pvss --lib
cargo test -p pvthfhe-compressor --lib
just demo-e2e
```

### F.2 — Surrogate Audit

After all phases complete, run a comprehensive audit:

```bash
# Must return zero results
grep -r "0x11.*0x22" crates/pvthfhe-aggregator/src/
grep -r "vec!\[0x00.*0x01\]" crates/
grep -r "surrogate" crates/pvthfhe-aggregator/src/ crates/pvthfhe-nizk/src/ --include="*.rs" | grep -v "test\|comment\|// "
```

### F.3 — Documentation Consistency

Verify cross-documentation consistency:

- `ARCHITECTURE.md` → matches `crates/*/src/*.rs`
- `SECURITY.md` → matches `OPEN-PROBLEM-BLOCKERS.md`
- `paper/main.tex` → no Track A references
- `README.md` → reflects single-backend LatticeFold+ status

---

## Execution Order

```
Phase 0 (verify Nova removal) ── 10 min
    │
Phase A (documentation) ── 1-2 days
    │
    ├── A.1 (paper) ── parallel with A.2
    └── A.2 (ARCHITECTURE)
    │
Phase B (surrogate removal) ── 3 days
    │
    ├── B.1 (keygen) ── parallel with B.2
    └── B.2 (accumulator)
    │
Phase C (quick improvements) ── 4 days
    │
    ├── C.1 (scheme-switch) ── parallel
    ├── C.2 (sigma repetition) ── parallel
    └── C.3 (share binding) ── parallel
    │
Phase D (medium) ── 5 days
    │
    ├── D.1 (A1 accumulator) ── depends on B.2
    └── D.2 (Greco E3) ── parallel
    │
Phase E (large) ── weeks
    │
    ├── E.1 (C5 formation proof) ── parallel
    ├── E.2 (C7 research) ── starts immediately, runs in parallel
    ├── E.3 (lattice batch folding) ── starts after C.2
    ├── E.4 (P4 on-chain IVC) ── starts after B.2
    └── E.5 (latticefold+ full) ── starts after E.3
    │
Phase F (verification) ── ongoing after each phase
```

**Total estimated wall time**: ~3-5 weeks (phases A-D run serially, E runs in parallel with later phases overlapping).

---

## Acceptance Criteria

- [ ] Zero Track A references in paper, ARCHITECTURE.md, README.md, SECURITY.md
- [ ] Zero `[0x11, 0x22]` surrogates in non-test production code
- [ ] Accumulator transcript codec fully wired — A1 resolved
- [ ] `just demo-e2e` runs with real keygen encryption, real accumulator transcripts
- [ ] Sigma NIZK achieves 2^-128 soundness via 90-round repetition
- [ ] TFHE gates functional, scheme-switch fixed, `just poulpy-all` passes
- [ ] Share-commitment binding enforced in verify path
- [ ] C7 research phase memo published with ≥2 prototype approaches compared
- [ ] Decision memo for C7 approach written and approved
- [ ] Lattice batch folding implemented and benchmarked at H=20-1024
- [ ] C5 formation proof implemented with PoP
- [ ] P4 on-chain IVC verifier implemented (UltraHonk wrapper)
- [ ] All 6 phases pass `cargo check --workspace` and `just demo-e2e`

---

## Stale Plans Superseded by This Meta-Plan

The following plans are fully absorbed into this meta-plan and should be considered EXECUTED upon completion:

- `fix-ivc-verify-p3.md` — **SKIPPED** (Nova removed, no longer applicable)
- `performance-optimization-sub5s.md §A.3a` — **SKIPPED** (Nova removed)
- `next-steps-strategic.md §S4` — absorbed into A.2
- `paper-code-alignment.md §B.1, §C.1` — absorbed into A.1 (with Track A removal, not documentation)
- `close-all-gaps.md §C3` — absorbed into C.3
- `scheme-switch-fix-tfhe-gates.md` — absorbed into C.1
- `p1-sigma-repetition.md` (tasks 1-3) — absorbed into C.2
- `real-keygen-simulator.md` — absorbed into B.1
- `a1-accumulator-transcript.md` — absorbed into B.2 + D.1
- `greco-e3-compute-provider.md` — absorbed into D.2
- `p2-lattice-folding.md` (Task 2) — absorbed into E.3
- `latticefold-plus.md` — absorbed into E.5
- `p4-onchain-ivc.md` — absorbed into E.4
- `c5-formation-proof.md` — absorbed into E.1
- `c7-correctness.md` — **SUPERSEDED** by E.2 (broader research phase)
