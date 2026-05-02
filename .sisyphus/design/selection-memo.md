# Architecture Selection Memo

## 1. Decision
Architecture B (Lattice PVSS + LatticeFold+ + MicroNova) is selected for Phase 2.

## 2. Scoring Rubric

| Criterion | Weight | Arch-A | Arch-B | Arch-C |
|---|---|---|---|---|
| On-chain gas at N=1024 | 30% | 2 | 5 | 5 |
| Per-party work O(n) | 20% | 4 | 5 | 4 |
| Security assumption maturity | 25% | 4 | 3 | 3 |
| Implementation feasibility | 15% | 4 | 3 | 1 |
| PQ-friendliness | 10% | 5 | 5 | 5 |
| **Weighted total** | | **3.45** | **4.10** | **3.60** |

## 3. Rationale
Architecture B is selected as the winner because it provides optimal asymptotic scaling for on-chain gas costs (O(1)) and per-party work (O(n)), avoiding the O(N*n) blowout that plagues Architecture A. While Architecture B relies on newer assumptions (specifically around LatticeFold+ and lattice NIZK well-formedness), recent advances like Cyclo (2026/359) provide a clear path forward. Architecture C is rejected due to its poor implementation feasibility—recursive PLONK over lattices inside Noir currently requires excessive constraints and lacks robust tooling. Architecture A remains the most feasible but its baseline gas costs exceed our 5M ceiling for realistic N>128, making it unviable without significant modification.

## 4. Fallback Plan
If Architecture B's lattice NIZK soundness proves intractable in Phase 2, we will fall back to a modified Architecture A: adding a MicroNova SNARK compression layer on top of Arch-A to compress the O(n) verification into a single O(1) proof (the "Arch-A + MicroNova hybrid").

## 5. Open Problems Assigned to Phase 2
- P1 (CRITICAL): Lattice NIZK well-formedness soundness for folded RLWE instances
- P2 (HIGH): LatticeFold+ over RLWE — new folding argument needed
- P3 (MEDIUM): MicroNova compression of lattice accumulator — circuit design
- P4 (LOW): Threshold keygen PVSS — use Hermine (2026/419) everywhere-short secret sharing

## 6. Phase 2 Work Breakdown
- T18: Full protocol spec for arch-B (6 algorithms, formal pseudocode)
- T19: Lattice NIZK subproblem analysis (P1 + P2)
- T20: Threshold keygen PVSS design
- T21: Noir circuit design for RLWE relation at N=8192
- T22: LatticeFold+ accumulator circuit design
- T23: MicroNova compression circuit design
- T24: Security proof sketch (IND-CPA-PV_B game)
- T25: On-chain verifier architecture (Solidity + BB-generated)
- T26: Oracle/Metis review of full design
- T27: Phase 2 integration test plan
- T28: Phase 2 gate report (`just phase2-gate`)
