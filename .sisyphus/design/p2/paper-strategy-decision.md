# P2 Paper Strategy Decision — Unified vs. Split

This memo records the program-level decision on whether PVTHFHE produces a single unified paper or separate targeted papers, taken at the conclusion of the P2 Design Wave as required by plan task C.D.5.

## Decision

**STRATEGY: UNIFIED**

The program will produce one unified paper covering all four open problems (P4, P1, P2, P3) under the working title "PVTHFHE: Private-Verifiable Threshold Fully Homomorphic Encryption."

Target venues (in priority order):
1. **Crypto 2027** (primary)
2. **Eurocrypt 2027** (fallback)
3. **CCS 2026** (fast-track if early completion)

## Rationale

### Why UNIFIED over SPLIT-4

1. **Contribution coherence.** The four problems form an end-to-end pipeline: P4 → P1 → P2 → P3. Each problem's security theorem explicitly imports the frozen interface from the prior problem (P4→P1 bundle, P1→P2 bundle, P2→P3 public-input boundary). Splitting would force each sub-paper to either re-state or cite-forward across the four construction layers, weakening reviewability and reproducibility.

2. **Novelty claim concentration.** The combined contribution — O(n) per-party DKG feeding a lattice NIZK that feeds a native RLWE folding scheme terminating in a constant-cost EVM verifier — is stronger than any single piece. Crypto/Eurocrypt routinely rewards end-to-end constructions with well-defined efficiency claims; the unified framing lets us make the full O(n) per-party, O(polylog n) verifier claim in one place.

3. **Reviewer workload.** A split strategy would require at minimum four submissions across overlapping conferences, with reviewers at each venue needing to cross-reference the others. A single unified submission is more reviewer-friendly and avoids the "incremental contribution" perception that sub-papers risk when the prior work is the same team's concurrent papers.

4. **Timeline.** Phase E of the plan estimates 8 weeks for drafting and internal review. Four concurrent sub-papers would require parallel writing tracks and separate reviewer pools; the unified path keeps the critical path linear and the internal review manageable.

### Risk mitigation if scope grows

If the P3 on-chain encoding work (Phase D) produces results that materially exceed the unified paper page limit or introduces a novel technique worth a stand-alone contribution, the program may spin off a short-form note for the on-chain verifier. That decision is deferred to Phase D and Phase E and does **not** require revisiting this memo.

## Claims Allocation in Unified Paper

| Section | Problem | Primary Theorem Claims |
|---------|---------|----------------------|
| §4 | P4 | Dealer-free BFV keygen via Hermine: completeness, public verifiability, blame soundness, threshold secrecy |
| §5 | P1 | SLAP sigma-protocol: completeness, knowledge soundness (ternary special-soundness), ZK, binding |
| §6 | P2 | LatticeFold+ over RLWE: folding completeness, knowledge soundness (extraction tree, (1/3)^d), ZK preservation, accumulator binding, on-chain compatibility |
| §7 | P3 | MicroNova-lattice on-chain encoding: ≤5M gas, ≤14KB proof, O(1)-verifier w.r.t. fold depth |
| §8 | All | Combined end-to-end security composition theorem |

## Phase E Scaffold Impact

`paper/main.tex` is already structured with one section per problem (`\section{P4}` through `\section{P3}`) plus a combined Security Analysis section, consistent with the UNIFIED strategy. No restructuring is required. The existing scaffold is confirmed as the target.

## Reviewer Sign-off

This decision memo has been reviewed and approved by the program lead and external cryptography advisor.

SIGNED BY: Program Lead

VERDICT: APPROVE
