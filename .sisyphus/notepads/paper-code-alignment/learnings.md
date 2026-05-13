
## Batch A learnings (2026-05-13)

### A.1 — Paper header update
- Replaced stale 8-line header claiming "no on-chain cryptographic verification" and "Noir circuits are tautological surrogates"
- New 3-line header reflects current state: BFV sigma v4, Sonobe Nova IVC, committed-smudge, research prototype warning preserved
- Line count reduction intentional — the old header had excessive detail that was factually wrong

### A.2 — Architecture/Introduction update
- Added 6-line paragraph after contribution statement listing 5 concrete implementation features
- Uses `\texttt{}` for code identifiers (bfv_sigma.rs, FoldTrackKind::Sk, etc.)
- The old text was a one-liner about trusted-signer surrogate; new text accurately describes the full pipeline

### A.3 — P1 section update
- Replaced single-sentence P1 intro with 2-paragraph description covering both sigma components
- SLAP-style sigma for RLWE well-formedness + bfv_sigma.rs for BFV encryption correctness
- Mentions RNS, binary challenges {0,1}^N, masking bound 2^30, OsRng upgrade
- Theorem statements untouched — they remain as-is (will be addressed in Batch D)

### A.4 — P3 section update
- Replaced implementation note describing ecrecover-only with dual-path description
- Sonobe Nova IVC with CycloFoldStepCircuit is the active compression path
- compressor.verify() and external_verify_compressed_proof() mentioned
- ecrecover path retained as on-chain surrogate (5,273 gas)
- P3-T1 theorem text still says "deferred" — addressed in Batch D (dual-track theorems)

### Technical notes
- texlab (LaTeX LSP) is not installed — diagnostics unavailable for .tex files
- Python string replacement worked reliably for all 4 changes
- One formatting bug discovered and fixed: `\textbf` was truncated to `extbf` (backslash lost in tab context)
# Batch B Learnings — 2026-05-13

## B.1 — Provenance column
- Added "Provenance" column between "Status" and "Paper Section" in claims-table.md.
- Three values: TARGET (Architecture B: LatticeFold+/MicroNova/UltraHonk), SURROGATE (Sonobe Nova/ecrecover), BOTH (proved for both paths).
- P4 rows (infrastructure PVSS): all BOTH — the PVSS layer is shared between both tracks.
- P1 rows: all TARGET (with [^p1] footnote) — lattice-native BFV sigma protocol, real crypto but conditional soundness.

## B.2 — P2 reclassification
- P2-T1, P2-T3, P2-T5: SURROGATE — proved for Sonobe Nova SHA-256 hash accumulation path.
- P2-T2: TARGET — CONTINGENT on LatticeFold+ Lemma 9 (proof file explicitly says "LatticeFold+ refinement").
- P2-T4: TARGET — CONDITIONAL on lattice commitment replacement; designed for RingSIS/M-SIS.
- Rationale: T2 and T4 are about the target LatticeFold+ system even though current code uses Sonobe surrogate.

## B.3 — P3 reclassification
- P3-T1, P3-T2, P3-T5: SURROGATE — proved for ecrecover/ECDSA attestation path.
- P3-T4: BOTH — empirically validated gas bound (5,273 gas) applies to both ecrecover and UltraHonk paths; Forge test confirms ≤5,000,000 gas bound.
- P3-T3: BOTH — trusted-setup explicitness applies to both paths (KZG for target, none for surrogate ecrecover).
- P3-T3 kept as-is per plan: "keep as-is with note about KZG for target path."

## B.4 — P1 criticality footnote
- Added footnote [^p1] on all 5 P1 rows (T1–T5).
- Text: "P1 soundness is conditional on Module-SIS + Cyclo Theorem 3. Formal joint-extractor proof (T2) is a skeleton per SECURITY.md §P1."
- P1-T2 explicitly states in proof file: SKELETON, straight-line extractor works but joint-extractor is incomplete.

## Provenance distribution
| Value | Count | Rows |
|-------|-------|------|
| BOTH | 7 | P4-T1..T5, P3-T3, P3-T4 |
| SURROGATE | 6 | P2-T1, P2-T3, P2-T5, P3-T1, P3-T2, P3-T5 |
| TARGET | 2 | P2-T2, P2-T4 |
| TARGET [^p1] | 5 | P1-T1..T5 |

## Batch C — Benchmark Figure Updates (2026-05-13)

### C.1 — P1 Benchmark Regenerated
- Ran `cargo run --release -p pvthfhe-bench --bin bench_nizk`
- Binary was already built from May 7 (`target/release/bench_nizk`)
- Results changed dramatically from previous (May 3) data:
  - Previous: 0.004-0.023ms prove, 0.001-0.008ms verify, 3-25KB size (SLAP only)
  - Current: ~17ms prove, ~1.7-2ms verify, ~616KB size (BFV sigma + SLAP combined)
- The benchmark now measures the full BFV sigma + SLAP NIZK protocol, not just SLAP
- Times are O(1) in n because BFV sigma operates on fixed CRT limbs
- Updated `paper/figures/p1-bench.tex` with new macros and protocol description

### C.2 — P2 Two-Track DKG Benchmark
- `bench/p2/` exists with `results-{128,512,1024}.json` (surrogate hash-chain)
- No `run.sh` in bench/p2/ — no integrated two-track bench runner exists
- Per `bench/results/i1-one-vs-two-track.md`: "not fairly measurable"
- Updated `paper/figures/p2-bench.tex` with two-track status note
- Updated table values to match actual JSON data (43-360 µs range)

### C.3 — P3 Dual Gas Measurement
- ecrecover path: 5,273 gas max (from `.sisyphus/evidence/p3-impl/bench.txt`, median 5,263)
- UltraHonk path: 39,687 gas (from `bench/results/gas_measurement.json`)
- Updated `paper/figures/p3-bench.tex` with dual rows in table and bar chart

## Batch E — Paper Conclusion and Appendix (2026-05-13)

### E.1 — Updated Conclusion
- Replaced vague "P2 and P3 currently use cryptographic surrogates" with specific
  mention: Sonobe Nova IVC, CycloFoldStepCircuit, ecrecover/ECDSA, BFV sigma v4,
  committed-smudge, two-track DKG, OsRng masking

### E.2 — Remediation Log Appendix
- Added §Remediation Log before \end{document}
- Three rounds documented with commit references:
  - Round 1 (aaacb9e): OsRng masking, logging hygiene, Shamir safety, B_E naming
  - Round 2 (e772daf–b450f24): per-share NIZK verify, committed smudge, dkg_root, BFVPublicKey
  - Round 3 (6f01578–952a078): CommittedSmudge demo, aggregator NIZK, C1 key components

## Batch D Learnings (2026-05-13)

### D.1 - D.4: Dual-track paper architecture
- Restructured §6 (P2) and §7 (P3) in paper/main.tex into dual-track subsections
- §6.A: Sonobe Nova IVC (Track A — proved, concrete)
- §6.B: LatticeFold+ over RLWE (Track B — aspirational, target)
- §7.A: ECDSA/ecrecover attestation (Track A — proved, concrete)
- §7.B: UltraHonk + MicroNova (Track B — skeleton, target)
- P4 (§4) and P1 (§5) left unchanged — both tracks share them
- Theorem labels updated: P2-A-T1..T5, P2-B-T1..T5, P3-A-T1..T5, P3-B-T1..T5

### D.5: Claims table dual-track
- Added "Track A Status" and "Track B Status" columns
- P4/P1 rows: both tracks share same status
- P2 rows: Track A = PROVED (Sonobe), Track B = ASPIRATIONAL/CONTINGENT
- P3 rows: Track A = PROVED (ecrecover), Track B = SKELETON
- Added provenance legend explaining all status values
- Added P1 criticality footnote from SECURITY.md

### D.6: Deferred implementation plans
- Created 4 plan files in .sisyphus/plans/:
  - p2-latticefold-target.md (42 lines)
  - p3-micronova-target.md (45 lines)
  - p1-t2-joint-extractor.md (44 lines)
  - p1-t3-zk-full.md (48 lines)
- Each plan includes: goal, blocked dependencies, research milestones, estimated effort, cross-references

### File modifications
- paper/main.tex: +~20KB (24754 bytes total)
- paper/claims-table.md: rewritten with dual-track columns
- 4 new plan files created

### LaTeX consistency verified
- All theorem labels defined (thm:p4-t1..p4-t5, p1-t1..p1-t5, p2a-t1..p2a-t5, p2b-t1..p2b-t5, p3a-t1..p3a-t5, p3b-t1..p3b-t5)
- No dangling references to old labels (thm:p2-t1 etc.)
- Security Analysis still references thm:p4-t5 correctly
- Sections use \subsection for track sub-sections
- \S references for internal cross-linking
