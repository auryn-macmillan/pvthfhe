# Internal Review — Paper Completeness and Presentation
**Reviewer**: Carol (Paper Lead)
**Date**: 2026-05-03
**Scope**: Paper structure, abstract, related work, claims-table completeness, artifact appendix

## Summary

Reviewed the overall paper (`paper/main.tex`) for structural completeness and internal
consistency. Checked that all 19 theorems are present, the claims table maps 1:1 to
obligations.md PROVED rows, and the artifact appendix is complete.

## Structural Review

### Abstract
The abstract correctly summarizes the O(n)/O(polylog n) complexity claims and the
four-layer structure. ✓

### Section Coverage
All four problem sections (P4/P1/P2/P3) are present with theorem environments. ✓

### Theorem Count
19 theorem environments in main.tex, matching 19 PROVED/proven rows in obligations.md. ✓

### Cross-Problem Summary Table
Table 1 (cross-problem performance summary) is present and consistent with bench evidence. ✓

### Figures
All four bench figures (p4-bench.tex, p1-bench.tex, p2-bench.tex, p3-bench.tex) are
referenced and `\input`-ted in the Implementation section. ✓

## Claims-Table Audit

`paper/claims-table.md` has 19 rows, all with `PROVED` status, covering all P4/P1/P2/P3
theorems from obligations.md. ✓

## Artifact Appendix

`paper/artifact-appendix.md` is complete:
- Hardware requirements stated ✓
- Toolchain versions pinned ✓
- Kick-the-tires instructions present ✓
- Full reproduction instructions present ✓
- Limitations clearly documented ✓

## Issues Found

- **Moderate**: The Related Work section is currently a placeholder citation list.
  For submission, this needs to be expanded with actual discussion. Flag for pre-submission
  pass.
- **Minor**: Introduction does not yet include a "Roadmap" paragraph pointing to sections.
  Standard for Crypto/Eurocrypt papers.

## Conclusion

The paper is structurally complete for internal review. The two items (related work expansion,
roadmap paragraph) are pre-submission improvements, not blockers.

VERDICT: ACCEPT (conditional on related work expansion before final submission)
