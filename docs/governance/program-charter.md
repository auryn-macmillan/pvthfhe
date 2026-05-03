# PVTHFHE Program Charter

This document outlines the governance and operational policies for the PVTHFHE follow-on research program.

## Review Cadence

The program follows a gated progression for each research problem (P4, P1, P2, P3). Review occurs at each designated gate:

- **Research Gate (RG)**: Verification of theoretical foundations and literature review.
- **Design Gate (DG)**: Validation of technical specifications and architectural choices.
- **Implementation Gate (IG)**: Final review of code, tests, and benchmarks.

Novelty reviews are conducted during each Research and Design Gate to ensure the program remains at the state of the art.

## Reviewer Model

The program employs a dual-tier reviewer model:

1. **In-house Primary**: Continuous technical oversight and alignment check.
2. **External Advisory**: Deep-dive technical review at each Design Gate to provide objective validation and specialized expertise.

Gates requiring human intervention use a formal verdict system: `APPROVE`, `REJECT`, or `REQUEST_CHANGES`, accompanied by detailed memos.

## Theorem-Proof Obligation

Theoretical rigor is central to the program. Each cryptographic construction must adhere to the following obligation:

- A theorem-proof skeleton is required before implementation begins.
- A full formal proof must be completed concurrently with the implementation phase.

## Pivot and Kill Criteria

The program or specific sub-problems may be pivoted or terminated based on the following criteria:

- **Impossibility**: Discovery of a fundamental theoretical blocker.
- **Infeasible Parameters**: Parameter requirements that exceed practical operational bounds.
- **Reviewer Rejection**: Repeated failure to pass a Design or Research Gate.
- **Novelty Preemption**: External publication that renders the current approach obsolete or redundant.

## Publication Strategy

The primary goal is high-tier academic publication (e.g., Crypto, Eurocrypt, or CCS).

- A unified paper is the primary target.
- A decision on whether to split the research into separate papers will be made at the conclusion of the P2 Design phase.

## Constraint-Priority Ladder

When technical requirements conflict, the following priority ladder applies:

1. **Security**: Non-negotiable cryptographic soundness and privacy.
2. **Scale**: Support for target party counts and data volumes.
3. **Verifier Cost**: Minimizing on-chain or end-user verification overhead.

## Authority on Disagreement

In cases of technical or procedural disagreement that cannot be resolved through the standard review process, the Project Lead holds final decision-making authority.
