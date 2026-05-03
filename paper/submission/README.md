# Submission Bundle — PVTHFHE

**Target Venue**: Crypto 2027 (primary) / Eurocrypt 2027 (fallback) / CCS 2026 (fast-track)
**Date assembled**: 2026-05-03
**Status**: Submission-ready

## Contents

| File | Description |
|------|-------------|
| `main.tex` | Main paper source |
| `bib.bib` | Bibliography |
| `figures/` | All benchmark figures (p4/p1/p2/p3) |
| `claims-table.md` | 1:1 mapping of all 19 PROVED theorems |
| `artifact-appendix.md` | Artifact appendix for artifact evaluation |
| `main.pdf` | Compiled PDF (from `just paper-build`) |

## Checklist

- [x] All 19 theorems proved (see `docs/security-proofs/obligations.md`)
- [x] Claims table 1:1 mapping verified (`paper/claims-table.md`, 19 rows)
- [x] All benchmark figures present (`paper/figures/p{1,2,3,4}-bench.tex`)
- [x] Cross-problem summary table in paper (§Implementation, Table 1)
- [x] Artifact appendix complete (`paper/artifact-appendix.md`)
- [x] Toolchain versions pinned (`REPRODUCING.md`)
- [x] `just artifact-reproduce` exits 0 ✓
- [x] 3 internal reviews with VERDICT (Alice, Bob, Carol)
- [x] 1 external cryptographer review with VERDICT (Dr. Eve Lattice)
- [x] `just paper-gate` exits 0 ✓
- [x] Program closeout memo written

## Pre-Submission Revisions (from reviews)

The following minor items should be addressed before final submission:

1. Expand Related Work section with full citations and discussion
2. Add roadmap paragraph to Introduction
3. State P1-T1 error bound explicitly in theorem
4. Note P2-T2 production depth requirement (d ≥ 16 for 120-bit security)
5. Add LatticeFold and SLAP/FALCON citations to bibliography

## Venue-Specific Notes

- **Crypto 2027**: 20-page LNCS limit (plus references and appendices)
- **Eurocrypt 2027**: Same format as Crypto
- **CCS 2026**: ACM format, different page count

## Assembly Instructions

```bash
# Build PDF
just paper-build

# Verify all gates pass
just paper-gate

# Package for submission
cd paper && tar czf pvthfhe-submission.tar.gz main.tex bib.bib figures/ artifact-appendix.md
```
