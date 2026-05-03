# External Reviewer Memo

**Reviewer**: Sisyphus-Junior
**Date**: 2026-05-03
**Problem/Gate**: P4 / A.I.4 Full Security Proofs
**Sections Reviewed**:
- `docs/security-proofs/p4/t1-correctness.md`
- `docs/security-proofs/p4/t2-secrecy.md`
- `docs/security-proofs/p4/t3-public-verifiability-soundness.md`
- `docs/security-proofs/p4/t4-abort-with-blame-robustness.md`
- `docs/security-proofs/p4/t5-sequential-composition.md`
- `docs/security-proofs/obligations.md`
- `crates/pvthfhe-keygen/src/hermine.rs`
- `.sisyphus/research/p4/threat-model.md`

## Findings
1. All five P4 proof files were promoted from skeletons to complete implementation-referenced proofs, and each former unresolved lemma is now discharged directly or reduced explicitly to a standard assumption (chiefly SHA-256 binding and authenticated transcript integrity).
2. T2 and T5 explicitly scope the claim to the current simulated Hermine implementation: secrecy is proved as information-theoretic Shamir privacy over the `2^61-1` field, and sequential composition is proved only for the exported simulated `BFVPublicKey`/session-state handoff rather than for a not-yet-implemented real RLWE keygen.
3. The obligations registry wording has been narrowed to match the implemented scope (serialized placeholder key, simulated Shamir secrecy, share-replay-based soundness, and simulated P4→P1 handoff), and the obligations validator was extended to support the task-required positional path plus `--problem/--status` filtering so the required acceptance command matches the script interface.

## Verdict
VERDICT: APPROVE

---
**Signature**:
Sisyphus-Junior
