# Architecture Cost Comparison

## Unified Cost Table

| Dimension | Arch-A (Silent Setup) | Arch-B (Lattice Folding) | Arch-C (Noir Recursive) |
|---|---|---|---|
| **Per-party work** | O(N·log N) NTT + O(1) NIZK | O(N·log N) NTT + O(1) fold contribution | O(1) Noir proof (~3.7s at N=8192) |
| **Aggregator work** | O(N) NIZK verify | O(log N) fold rounds | O(N) recursive verify calls |
| **Verifier work (on-chain)** | O(N) KZG batch OR O(1) SNARK | O(1) single SNARK | O(1) single SNARK |
| **Proof size** | ~14KB (UltraHonk) or ~N·48B (KZG) | ~14KB (UltraHonk) | ~14KB (UltraHonk) |
| **On-chain gas** | 3.65M (batch-128 KZG) or ~200-500k (SNARK) | ~200-500k | ~200-500k |
| **Security assumption** | RLWE + KZG/AGM | RLWE + LatticeFold soundness (open) | RLWE + recursive UltraHonk (open) |
| **PQ status** | FHE: PQ; verifier: non-PQ (BN254) | FHE: PQ; verifier: non-PQ (BN254) | FHE: PQ; verifier: non-PQ (BN254) |
| **Trusted setup** | KZG (for SNARK path) | KZG (for MicroNova) | KZG (for UltraHonk) |
| **Key open problem** | Silent-setup port soundness | Lattice NIZK well-formedness soundness | O(N) aggregation circuit feasibility |
| **Feasibility at N=1024** | HIGH (KZG batch near gas ceiling) | MEDIUM (folding soundness unproven) | LOW (aggregation circuit ~10M-50M gates) |

## Narrative Summary

### Gas Ceiling Analysis
For on-chain verification, the batch-128 KZG verification in Arch-A consumes ~3.65M gas, which is 73% of the soft 5M gas ceiling constraint. While Arch-A's KZG path is feasible at N=128, it approaches the limit. Scaling to N=1024 would require a batch-1024 KZG verification, likely exceeding the absolute 10M gas ceiling. Conversely, the O(1) SNARK compression path (an Arch-A variant, as well as Arch-B and Arch-C) comfortably operates within limits, costing ~200k-500k gas.

### Feasibility Ranking
At N=1024, the ranking for practical feasibility is **Arch-B > Arch-A > Arch-C**.
Although Arch-C is conceptually simpler by shifting complexity to recursive Noir + UltraHonk, the O(N) aggregation circuit is a critical blocker. At N=1024, the aggregator circuit could require 10M-50M gates, which is infeasible given current Barretenberg proving limits.

### Open Problems & Technical Risks
1. **Lattice NIZK soundness (Arch-B)**: The hardest theoretical problem is proving well-formedness soundness for the folded lattice representations in Arch-B. 
2. **Silent-setup port soundness (Arch-A)**: A more tractable problem backed by existing literature. Arch-A requires porting existing silent-setup concepts to our specific constraint environment.
3. **Aggregation circuit feasibility (Arch-C)**: Primarily an engineering and scale question. O(N) constraints in recursive SNARKs fundamentally hit current proving backend limitations.

### Recent Literature Updates
The literature refresh (T14) highlights a significant update: **Cyclo (2026/359)** noticeably improves the folding efficiency of Arch-B, solidifying it as the most promising scalable path. Additionally, **Zyskind et al. (2025/1781)** introduces noise-flooding-free decryption techniques which could offer benefits to Arch-A.
