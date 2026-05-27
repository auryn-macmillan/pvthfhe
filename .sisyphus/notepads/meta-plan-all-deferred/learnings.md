
## G.29 Domain Constants Audit (2026-05-18)

### Key Findings
- Noir defines 6 `DOMAIN_*` constants (values 1-6) in `circuits/protocol_constants/src/lib.nr`
- Rust `full_pipeline.rs` correctly uses domain 1 (vector_hash_8) and domain 6 (bind_8_with_domain_native) for `aggregator_final`
- Domains 2-5 are Noir-internal (used within `decrypt_share` circuit to compute commitment bindings)
- `witness_gen.rs` uses a rolling digest (DIGEST_DOMAIN=987654321) instead of Poseidon — stale/legacy code for deferred `noir_decrypt_share` phase
- Rust `pvthfhe-domain-tags` crate uses STRING-based tags — separate system from numeric Poseidon domain tags
- No fixes needed for active code paths

## G.28: Robust Secret Sharing documentation (2026-05-18)

### What was done
- Added `\subsection{Robust Secret Sharing}` to `paper/main.tex` in the Security Analysis section, after the Fiat-Shamir subsection and before Implementation and Evaluation.
- Added `@inproceedings{fehr2019rss}` to `paper/bib.bib` citing Fehr-Yuan EUROCRYPT 2019.

### Insertion point
- Line 546 of `paper/main.tex` (between Fiat-Shamir subsection end at line 545 and `\section{Implementation and Evaluation}`).

### Content summary
- Current approach: Lagrange interpolation over t shares, error detection via plaintext decode failure.
- Limitation: Cannot identify WHICH party submitted the bad share.
- Solution referenced: VSS/RSS with cheater identification for t < n/2; cites Fehr-Yuan 2019.
- Status: Deferred to future work; misbehavior detection via retry with subset selection is sufficient for honest-majority protocols.

### Verification
- `just paper-gate` passed: all 7 checks (claims-table, theorem-consistency, figures, internal-reviews, external-reviews, submission-bundle).

### Bib entry details
- Key: `fehr2019rss`
- Volume: LNCS 11477 (EUROCRYPT 2019, Part II)
- DOI: 10.1007/978-3-030-17656-3_6

## G.17: FoldVerifierStepCircuit deferred documentation (2026-05-18)

### Why deferred
The `FoldVerifierStepCircuit` in `crates/pvthfhe-compressor/src/nova/fold_verifier_circuit.rs` has only degenerate constraints (counter increments). Security review finding D.2 flagged that left/right accumulator hashes are received as external inputs but never verified against any folding relation. Real fold verification requires verifying Nova accumulation of CycloFold proofs, checking accumulator hash consistency, and enforcing the Nova recurrence relation. This awaits the Interfold/composite IVC design phase (G.16).

### What was done
- Added prominent `## Status: DEFERRED (G.17, security review finding D.2)` doc comment at the top of the file listing the four requirements for real fold verification.
- Added `// PLACEHOLDER` comment above the degenerate constraints in `generate_step_constraints` explicitly noting they provide "ZERO actual verification."
- No code logic changes. The placeholder constraints remain so the circuit compiles and can be folded.

## G.18: LatticeFoldTreeCircuitFamily DEFERRED documentation (2026-05-18)

### What was done
Added prominent DEFERRED documentation to `crates/pvthfhe-compressor/src/nova/latticefold_circuit_family.rs`:
- File-level doc comment now starts with `## Status: DEFERRED (G.18, security review finding D.3)` explaining that both circuit variants produce identical 0-R1CS-mult constraints (degenerate placeholders).
- Listed the three real constraints needed: (1) P1 ring equation enforcement over witness data, (2) parent hash commits to child hashes, (3) distinct constraint shapes for leaf vs internal within Gaussian IVC.
- Added inline `// PLACEHOLDER` comment above the `match circuit_idx` block in `generate_step_constraints`.

### Verification
- `cargo check -p pvthfhe-compressor` passes.
- No code logic changed, no tests removed.
- File grew from 176 to 190 lines (14 lines of doc comments added).

### Pattern
Same DEFERRED documentation pattern as G.17 — prominently mark degenerate placeholder code at both file level and call site so future developers don't mistake it for a real implementation.
