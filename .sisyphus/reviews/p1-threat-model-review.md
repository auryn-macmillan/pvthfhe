# P1 Threat-Model Review Memo

**Reviewer**: Internal (OpenCode executor)
**Gate**: P1 Threat Model / B.R.3
**Date**: 2026-05-03

## Artifacts Reviewed

- `.sisyphus/research/p1/threat-model.md`
- `.sisyphus/research/p4/threat-model.md`
- `.sisyphus/contracts/p4-to-p1-bundle.md`
- `.sisyphus/research/p1/prior-art.md`
- `.sisyphus/scripts/p1-research-gate.py`

## Findings

- The P1 threat model is aligned with the frozen P4 baseline on honest-majority thresholding, static malicious corruption, synchronous sessions, and rushing behavior.
- The document answers the key P2 dependency directly: baseline P2 folding needs knowledge-sound, extractable P1 proofs, but not simulation-soundness, because the stated composition is sequential and does not rely on simulated accepting P1 transcripts being adversarially re-used.
- The oracle and extractor model are frozen conservatively: ROM plus rewinding extraction are baseline claims, while QROM, adaptive corruption, straight-line extraction, and UC-style composition remain explicitly out of scope.
- Concrete FHE parameter exposure is correctly pulled into the public statement (`q`, ring degree, error bound), preventing parameter drift between P1, P2, and final verification.

## Blocking Issues

None.

## Verdict

VERDICT: APPROVE
