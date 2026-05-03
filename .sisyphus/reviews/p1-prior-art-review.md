# P1 Prior-Art Review Memo

**Reviewer**: Internal (OpenCode executor)
**Gate**: P1 Prior-Art Matrix / B.R.1
**Date**: 2026-05-03

## Artifacts Reviewed

- `.sisyphus/research/p1/prior-art.md`
- `.sisyphus/contracts/p4-to-p1-bundle.md`
- `.sisyphus/scripts/p1-research-gate.py`

## Findings

- The prior-art matrix covers the required lattice-proof families, including Lyubashevsky FS Σ-proofs, LANES/LNS19/LNS21, MatRiCT/Esgin et al., Beullens one-shot lattice ZK, Bootle-Lyubashevsky-Seiler, Albrecht-Lai lattice SNARGs, lattice Bulletproofs, SLAP, Greyhound, transparent lattice IOPs, zkVM-as-NIZK, and the SNARK-friendly hash-of-RLWE-witness comparison row.
- The matrix does not conflate proof-of-knowledge with simulation-soundness; rows explicitly note that simulation-soundness is generally absent unless added by an external compilation or wrapper.
- Tradeoffs among prover time, proof size, verifier time, recursion-friendliness, and on-chain feasibility are called out directly enough to support candidate triage for P1 and downstream P2 recursion.
- The shortlist identifies at least three viable primary candidates and at least two viable fallback candidates, with the zkVM row preserved as the operational fallback.

## Blocking Issues

None.

## Verdict

VERDICT: APPROVE
