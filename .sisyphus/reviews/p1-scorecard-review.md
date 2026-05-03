# P1 Scorecard Review Memo

**Reviewer**: Internal oracle review
**Gate**: RG-P1 / B.R.5
**Date**: 2026-05-03

## Summary

VERDICT: APPROVE

The scorecard evaluates all required viable candidates against the weighted RG-P1 criteria, freezes exactly one primary, and records explicit fallback paths that preserve both research ambition and delivery safety.

## Scoring Rationale

- The weighting correctly prioritizes verifier cost for P2 folding consumption over raw prover speed.
- The table scores all six required candidates: SLAP, Greyhound, Beullens one-shot lattice ZK, SNARK-friendly hash-of-RLWE-witness, LANES/LNS21, and Rust-in-zkVM.
- The scorecard distinguishes lattice-native fit from mixed-assumption wrapper approaches rather than letting succinct conventional SNARK verification dominate the decision by itself.
- The FHE-parameter-compatibility column is grounded in the intended `(q, N, error bound)` relation, not the current surrogate shape.

## Primary Justification

**SLAP** is an approved primary because it is the highest-scoring balanced option: it stays lattice-native and PQ-aligned under the frozen ROM baseline while matching the intended decrypt-share/plaintext-consistency relation more closely than the other viable candidates. It is the best current compromise between native proof fidelity and downstream verifier constraints.

## Fallback Justification

- **Greyhound** is an approved research fallback because it offers the best native-lattice verifier path if recursion-friendliness overtakes all other concerns.
- **Rust-in-zkVM** is an approved delivery fallback because it is explicitly acceptable as the worst-case path and guarantees that P1 can still ship a real verifier if native-lattice constants fail.

## Risks

- SLAP still requires adaptation work to bind the inherited SHA-256 commitment semantics and the RLWE relation under one Fiat-Shamir transcript.
- Greyhound remains exposed to engineering immaturity and uncertain constants for the exact P1 witness.
- Rust-in-zkVM weakens the clean lattice-native story and may impose high prover latency, so it should remain a fallback rather than the research default.
- The present freeze is ROM-baseline only; any later QROM claim would require a scorecard refresh rather than being inferred from this approval.
