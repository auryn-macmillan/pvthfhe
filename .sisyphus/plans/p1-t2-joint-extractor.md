# P1-T2 Joint Knowledge Extractor Roadmap

**Created**: 2026-05-13
**Updated**: 2026-05-13 (status review)
**Status**: OPEN (Lemma 9 dependency — research-blocked)
**Paper reference**: §5 (P1), theorem P1-T2; claims-table footnote

## Implementation Status (2026-05-13)

P1-T2 remains research-blocked. The straight-line extractor (`docs/security-proofs/p1/T2.md`) is approved for the SHA-256 binding path. Implementation of the NIZK-level improvements has been extensive (R4 audit sigma equation fix, bfv_sigma plaintext domain check, decrypt NIZK witness binding, dealer identity binding, batched share-encryption proof, per-track domain separation). These strengthen the base protocol that P1-T2's extractor would compose with. However, the joint extractor composition with Cyclo Theorem 3 remains blocked on Lemma 9.

**No additional implementation is possible without Lemma 9 resolution.** This plan serves as a research roadmap and documentation artifact.

## Goal

Construct a formal joint knowledge extractor for the Cyclo-companion Ajtai NIZK that composes the Cyclo folding protocol with the Ajtai commitment and RLWE decryption relation, yielding a unified extraction argument at the frozen PVTHFHE parameters.

## Current State

P1-T2 is currently PROVED for the straight-line extractor under SHA-256 binding only. The proof (`docs/security-proofs/p1/T2.md`) provides knowledge soundness for the implemented relation but does not compose with Cyclo folding knowledge soundness (Cyclo Theorem 3) to produce a joint extractor. Lemma 9 (`docs/security-proofs/lemma9.md`) remains a CONJECTURE.

## Blocked Dependencies

| Dependency | Status |
|-----------|--------|
| Lemma 9 (Cyclo joint extractor) | CONJECTURE |
| M-SIS hardness at frozen parameters | Standard assumption (unproven) |
| Fiat-Shamir heuristic in ROM | Standard assumption |

## Research Milestones

1. **M1: Forking-lemma extraction** — Formalize the ROM forking-lemma argument for the multi-layer composition (Cyclo fold + Ajtai commitment + RLWE relation). Quantify extraction probability and reduction loss.

2. **M2: M-SIS reduction** — Reduce the forking-lemma extraction event to M-SIS over the commitment ring R_{q_commit} at N=8192. Bound the norm of the extracted witness difference.

3. **M3: Challenge-space analysis** — Prove that the biased ternary challenge set {-1,0,1} over the cyclotomic ring X^{256}+1 does not produce singular extraction matrices except with negligible probability (Lemma 9 heuristic).

4. **M4: Joint extractor composition** — Compose the straight-line extractor from P1-T2 with Cyclo Theorem 3 and the M-SIS reduction to produce a unified extractor for the full PVTHFHE P1 relation.

5. **M5: Formal write-up** — Produce a self-contained proof document with explicit reduction tightness and parameter bounds.

## Estimated Effort

~4–8 weeks of cryptographic research. The M3 challenge-space analysis is the highest-risk milestone (may require ring-theoretic arguments beyond current literature).

## Cross-references

- `docs/security-proofs/lemma9.md` — Lemma 9 conjecture details
- `docs/security-proofs/p1/T2.md` — Current P1-T2 proof (straight-line extractor)
- `docs/security-proofs/p1/theorem-inventory.md` — P1 theorem inventory
- `SECURITY.md` §P1 — Open problem statement
