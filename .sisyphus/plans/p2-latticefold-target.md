# P2 LatticeFold+ Target Implementation Plan

**Created**: 2026-05-13
**Status**: OPEN — Lemma 9 accepted as documented assumption (2026-05-14). Unblocks research. Cyclo Theorem 3 (ePrint 2026/359) + Lemma 9 invertibility assumption provide the soundness foundation. The active backend is `cyclo-rlwe-t10-lemma9-heuristic`.
**Paper reference**: §6.B (Track B), theorems P2-B-T1 through P2-B-T5

## Goal

Replace the Nova Nova IVC surrogate (Track A) with a native LatticeFold+ accumulation scheme that folds RLWE ciphertext witnesses via algebraic relations over the Cyclo CCS encoding.

## Blocked Dependencies

| Dependency | Status | Resolution |
|-----------|--------|------------|
| Lemma 9 (Cyclo joint knowledge extractor) | CONJECTURE | `docs/security-proofs/lemma9.md` — requires formal extraction argument |
| Cyclo CCS encoding at frozen parameters | DESIGN | `docs/security-proofs/p2/T1.md` Lemma 1 — adapter required |
| Norm enforcement in `validate_witness` | OPEN | `crates/pvthfhe-aggregator/src/folding/mod.rs` |
| Linear lattice commitment replacement (SHA-256 → Com_A) | OPEN | `docs/security-proofs/p2/T4.md` |

## Research Milestones

1. **M1: Resolve Lemma 9** — Construct unified knowledge extractor for Cyclo/Ajtai NIZK at frozen parameters (q=65537, N=1024, B_e=17). Estimated: ~2–4 weeks of cryptographic research.

2. **M2: LatticeFold+ CCS adapter** — Implement CCS constraint system matching the frozen P1 verifier equation under ternary challenge space {-1,0,1}. Reference: Cyclo ePrint 2026/359, LatticeFold+ design.

3. **M3: Norm enforcement** — Add coefficient-bound checks (`||w||_∞ ≤ 17`) to `validate_witness` in the folding harness.

4. **M4: Lattice commitment** — Replace SHA-256 accumulator with `Com_A(w) = A·w mod q` linear lattice commitment. Requires Ajtai matrix generation at frozen parameters.

5. **M5: Integration with MicroNova (P3 Track B)** — Once LatticeFold+ folding works, connect to MicroNova compression pipeline per `.sisyphus/plans/p3-micronova-target.md`.

## Estimated Effort

~8–12 weeks of cryptographic engineering (excludes Lemma 9 research time, which is unbounded).

## Cross-references

- `docs/security-proofs/lemma9.md` — Lemma 9 conjecture details
- `docs/security-proofs/p2/T1.md` — Folding completeness (VERDICT: APPROVE for Nova)
- `docs/security-proofs/p2/T4.md` — Accumulator binding (CONDITIONAL)
- `.sisyphus/plans/p3-micronova-target.md` — P3 Track B plan
- `.sisyphus/design/spec-real-p2p3.md` — P2/P3 real specification
