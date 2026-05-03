# External Reviewer Memo

**Reviewer**: OpenCode Internal Reviewer
**Date**: 2026-05-03
**Problem/Gate**: P4 Implementation Gate / A.I.6
**Sections Reviewed**:
- `.sisyphus/scripts/p4-impl-gate.py`
- `.sisyphus/scripts/validate-bundle.py`
- `.sisyphus/contracts/p4-to-p1-bundle.md`
- `crates/pvthfhe-keygen/src/lib.rs`
- `crates/pvthfhe-keygen/src/hermine.rs`
- `docs/security-proofs/p4/t2-secrecy.md`
- `docs/security-proofs/p4/t3-public-verifiability-soundness.md`
- `docs/security-proofs/p4/t4-abort-with-blame-robustness.md`
- `docs/security-proofs/p4/t5-sequential-composition.md`
- `paper/claims-table.md`

## Findings
1. The P4→P1 downstream contract bundle is now published with the seven required sections and matches the current implementation rather than aspirational RLWE semantics: Shamir shares over `2^61-1`, SHA-256 commitments, and the eight-byte BFV key stub are all documented explicitly.
2. The bundle validator now accepts both `--bundle` and the positional path form used by plan QA, and it rejects missing required P4 handoff sections as expected.
3. The P4 claims-table row is frozen, which is appropriate because the implementation gate now packages the inherited assumptions, transcript shape, and residual risks needed before any P1 work begins.

## Verdict
VERDICT: APPROVE

---
**Signature**:
OpenCode Internal Reviewer
