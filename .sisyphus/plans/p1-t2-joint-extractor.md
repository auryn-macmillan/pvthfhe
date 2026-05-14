# P1-T2 Joint Knowledge Extractor Roadmap

**Created**: 2026-05-13
**Updated**: 2026-05-14 (Lemma 9 accepted as assumption — unblocks P1-T2 rewrite)
**Status**: OPEN — P1-T2 extractor needs rewriting for rewinding extractor (no witness openings exist in serialized proof). Lemma 9 accepted as documented assumption. The joint extractor composition with Cyclo Theorem 3 remains to be written.
**Paper reference**: §5 (P1), theorem P1-T2; claims-table footnote

## Implementation Status (2026-05-14)

P1-T2 extractor rewritten (`0465ce2`) as a rewinding forking-lemma extractor. The proof is now consistent with the ZK sigma transcript (no witness openings). Lemma 9 accepted as documented assumption (`6ce6efa`). The NIZK-level improvements from R4 audit and Interfold-Equivalent PVSS strengthen the base protocol. 

**Remaining**: The joint extractor composition with Cyclo Theorem 3 (M4) — a self-contained proof document that composes the rewinding extractor with Cyclo folding knowledge soundness. Milestones M1-M3 are prerequisite research for M4. This is purely theoretical proof-writing; no code changes are needed.

## Goal

Construct a formal joint knowledge extractor for the Cyclo-companion Ajtai NIZK that composes the Cyclo folding protocol with the Ajtai commitment and RLWE decryption relation, yielding a unified extraction argument at the frozen PVTHFHE parameters.

## Current State

P1-T2 has been rewritten at `0465ce2` as a rewinding extractor operating on the ZK sigma transcript `(t_bytes, z_s, z_e)`. The extractor uses forking-lemma rewinding under the ROM, accepting Lemma 9 as a documented assumption for challenge difference invertibility. The SHA-256 binding path remains the reduction target. The joint extractor composition with Cyclo Theorem 3 has not been written.

## Blocked Dependencies

| Dependency | Status |
|-----------|--------|
| Lemma 9 (Cyclo joint extractor) | ACCEPTED ASSUMPTION (`docs/security-proofs/lemma9.md` §0) |
| M-SIS hardness at frozen parameters | Standard assumption (unproven) |
| Fiat-Shamir heuristic in ROM | Standard assumption |

## Research Milestones

- [x] **M1: Forking-lemma extraction** ✅ — **COMPLETE** (`0465ce2` rewinding extractor + M1 formalization at `docs/security-proofs/p1/joint-extractor/M1-forking-lemma.md`). The ROM forking-lemma argument is formalized for the 3-layer composition. Extraction probability: ε² - 4ε/|C|. Tightness: 1/ε² for dominant term.
- [ ] **M2: M-SIS reduction** — Reduce the forking-lemma extraction event to M-SIS over the commitment ring R_{q_commit} at N=8192. Bound the norm of the extracted witness difference. Deferred pending deeper cryptanalysis.
- [ ] **M3: Challenge-space analysis** — Prove that the biased ternary challenge set {-1,0,1} over the cyclotomic ring X^{256}+1 does not produce singular extraction matrices except with negligible probability (Lemma 9 heuristic). Deferred (Lemma 9 accepted as assumption, formal proof remains open).
- [ ] **M4: Joint extractor composition** — Compose the rewinding extractor from P1-T2 with Cyclo Theorem 3 and the M-SIS reduction to produce a unified extractor for the full PVTHFHE P1 relation.
- [ ] **M5: Formal write-up** — Produce a self-contained proof document with explicit reduction tightness and parameter bounds.

## Estimated Effort

~4–8 weeks of cryptographic research. The M3 challenge-space analysis is the highest-risk milestone (may require ring-theoretic arguments beyond current literature).

## Cross-references

- `docs/security-proofs/lemma9.md` — Lemma 9 conjecture details
- `docs/security-proofs/p1/T2.md` — Current P1-T2 proof (straight-line extractor)
- `docs/security-proofs/p1/theorem-inventory.md` — P1 theorem inventory
- `SECURITY.md` §P1 — Open problem statement
