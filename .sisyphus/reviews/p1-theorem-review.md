# P1 Theorem Inventory Review

Date: 2026-05-03
Task: B.R.4 — P1 Theorem Inventory + Proof Obligations

## Scope Reviewed
- `docs/security-proofs/p1/theorem-inventory.md`
- `docs/security-proofs/obligations.md`
- `.sisyphus/scripts/p1-research-gate.py`

## Findings
- The inventory now enumerates T1–T5 and gives each theorem an explicit assumption, model, concrete statement sketch, proof technique, reduction target, and `skeleton` status.
- T2 and T3 are stated concretely in ROM terms rather than deferred as “standard”; both bind the witness relation to the inherited SHA-256 commitment and explicit RLWE parameter tuple.
- T4 records the current non-requirement for simulation-extractability while still documenting the upgraded theorem shape that would be needed if P2 changes.
- `docs/security-proofs/obligations.md` now includes P1 rows in the existing registry format with status `skeleton`.
- The P1 research gate now supports `--check theorem-inventory` and verifies both artifact existence and at least five theorem headings.

## Verdict
VERDICT: APPROVE
