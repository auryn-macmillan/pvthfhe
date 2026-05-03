# P2 Threat-Model Review Memo

**Reviewer**: Internal (OpenCode executor)
**Gate**: P2 Threat Model / C.R.3
**Date**: 2026-05-03

## Artifacts Reviewed

- `.sisyphus/research/p2/threat-model.md`
- `.sisyphus/research/p1/threat-model.md`
- `.sisyphus/contracts/p1-to-p2-bundle.md`
- `.sisyphus/research/p2/prior-art.md`
- `.sisyphus/scripts/p2-research-gate.py`

## P1 Consistency Check

- The corruption model is consistent with P1: static malicious corruption of at most `t-1` out of `n` parties under honest majority remains the baseline.
- The challenge space remains the inherited ternary set `{-1, 0, 1}`, so P2 does not introduce challenge-domain drift relative to the frozen P1 verifier.
- Session binding and participant binding carry through from P1 because the folded relation continues to depend on the bound `session_id` and participant-specific `pvss_commitment` opening semantics described in the bundle.
- The extractor/oracle model stays aligned with P1: ROM plus rewinding extraction are baseline claims, while simulation-extractability, QROM hardening, and adaptive corruption remain deferred or out of scope.
- The assumption ledger avoids RLWE drift by treating RLWE as inherited from P1 and adding only accumulator-binding assumptions (M-SIS / RingSIS-family) as P2-specific dependencies.

## Findings

- The threat model covers the required folding-specific attacks explicitly: invalid-inner-proof injection, accumulator binding failure, Fiat-Shamir grinding across folds, and quantitative soundness amplification.
- The knowledge-soundness section states a concrete extraction budget of `2^d` rewindings for fold depth `d`, which correctly warns that deep folding needs an explicit theorem rather than qualitative language.
- The soundness amplification analysis is no longer heuristic: with inherited ternary challenges, the baseline per-fold error `ε = 1/3` yields total error `(1/3)^d` under the stated independent-fold product analysis.
- The document remains faithful to the P1→P2 contract by treating P2 as a preservation layer over the frozen P1 verifier equation instead of a place to silently strengthen deferred security properties.

## Blocking Issues

None.

## Verdict

VERDICT: APPROVE
