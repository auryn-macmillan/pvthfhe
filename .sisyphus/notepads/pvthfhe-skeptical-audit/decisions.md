# Decisions — pvthfhe-skeptical-audit

## 2026-05-03 Session Start

- Evidence artifacts go to `.sisyphus/evidence/audit-*` directories
- Per-axis verdicts MUST be kept separate (Impl × Proof × Test) — never collapsed
- P3 honesty fix: BOTH disclose (paper/README) AND produce design sketch (.sisyphus/evidence/p3-real-verifier-sketch.md)
- SURROGATE retirement = replacement, NOT annotation
- Wave 1 tasks T1-T8 are independent and fire in parallel

## 2026-05-03 T20

- Reclassified `P2-T4` from a gap to `PROVED-WITH-CITATION`, but only with an explicit condition string in `obligations.md`: norm enforcement + lattice commitment replacement.
- Added the missing paper theorem for `P1-T4` without renumbering or changing existing theorem order.
- Left the existing `P2-T4` theorem statement in `paper/main.tex` unchanged, because the task required adding missing theorem environments/statements rather than rewriting established statements.

## 2026-05-09 R9 — Benchmarks, Docs, External-Audit Prep

- **R9.1 Benchmarks**: Marked preliminary (not re-run) per audit INFO-1 and plan allowance "or marked preliminary." Existing numbers measure stub pipeline.
- **R9.3 REPRODUCING.md**: Toolchain pins already match plan requirements. Added preliminary-benchmark notice only.
- **R9.4 Threat model**: Synthesized from 6 existing design docs (audit report, assumptions ledger, security proofs, proof boundary, fold soundness, noise budget) rather than inventing new content.
- **R9.5 External-audit packet**: Designed as a navigable index for external reviewers, not a repeat of content already in the audit report.
