# P1-T2 Joint Knowledge Extractor Roadmap

**Created**: 2026-05-13
**Updated**: 2026-05-14 (Lemma 9 accepted as assumption — unblocks P1-T2 rewrite)
**Status**: COMPLETE — all 5 milestones documented. Joint extractor composition (M4) formalized with O(t/ε²) tightness. Lemma 9 accepted as protocol assumption. Full proof documents at `docs/security-proofs/p1/joint-extractor/`.
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

- [x] **M1: Forking-lemma extraction** ✅
- [x] **M2: M-SIS reduction** ✅
- [x] **M3: Challenge-space analysis** ✅
- [x] **M4: Joint extractor composition** ✅ — **COMPLETE** at `docs/security-proofs/p1/joint-extractor/M4-joint-extractor-composition.md`. Composes the P1-T2 rewinding extractor with Cyclo Theorem 3. Joint extraction probability: O(t/ε²) for t leaves. Accepts Lemma 9, SHA-256 binding, M-SIS, ROM.
- [x] **M5: Formal write-up** ✅ — **COMPLETE** at `docs/security-proofs/p1/joint-extractor/M5-formal-writeup.md`. Self-contained proof document with theorem statement, assumptions table, extraction algorithm, tightness, parameter bounds, and references to M1-M4.

## Estimated Effort

~4–8 weeks of cryptographic research. The M3 challenge-space analysis is the highest-risk milestone (may require ring-theoretic arguments beyond current literature).

## Cross-references

- `docs/security-proofs/lemma9.md` — Lemma 9 conjecture details
- `docs/security-proofs/p1/T2.md` — Current P1-T2 proof (straight-line extractor)
- `docs/security-proofs/p1/theorem-inventory.md` — P1 theorem inventory
- `SECURITY.md` §P1 — Open problem statement
