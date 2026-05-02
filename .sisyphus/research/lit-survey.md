# PV-ThFHE Literature Survey

## Overview
This survey examines the landscape of Publicly Verifiable Threshold Fully Homomorphic Encryption (PV-ThFHE), focusing on O(n) per-party complexity and O(polylog n) verification cost.

## Comparison Table (8-axis)

| Paper | Scaling | Assumptions | Malicious-secure | Transparent | PQ | On-chain | Limitations | Open Problems |
|---|---|---|---|---|---|---|---|---|
| **LatticeFold** (2024/257) | O(log N) | Module-SIS | Yes (SNARK) | Yes | Yes | High | Folding overhead | Non-interactive folding |
| **LatticeFold+** (2025/247) | O(log N) | Module-SIS | Yes (SNARK) | Yes | Yes | High | Prover complexity | Small field optimizations |
| **Greyhound** (2024/1293) | O(log N) | LWE/SIS | Yes (SNARK) | Yes | Yes | Med | Proof size (53KB) | Sublinear verification |
| **vFHE** (2024/1764) | O(1) verify | LWE/RLWE | Yes (NIZK) | Yes | Yes | High | Boolean circuits only | Large-scale arithmetic |
| **trBFV** (2024/1285) | O(N) | RLWE | Yes (PVSS) | No | Yes | Low | Communication O(N) | Robust DKG |
| **Low-Comm ThFHE** (2024/1984)| O(1) share | LWE | Semi-honest | No | Yes | Med | No verification | Malicious robustness |
| **Noise-Padding** (2025/409) | O(1) share | LWE/MLWE | Semi-honest | No | Yes | Med | Complex noise management | Robustness |
| **Ajax** (2025/1834) | O(N) keys | FHEW-like | Semi-honest | No | Yes | Med | No noise flooding | Malicious security |
| **Zama ThFHE** (2025/699) | O(N) | TFHE/BGV/BFV | Malicious | No | Yes | Low | Noise flooding overhead | Robust decryption |
| **Noah's Ark** (2023/815) | O(N) | TFHE | Semi-honest | No | Yes | Low | Noise flooding | Efficient ZK |
| **ApproxSS-FHE** (2025/084) | O(N^2+K) | RLWE | Semi-honest | No | Yes | Med | Approx recovery | Malicious security |
| **O(1) PVSS** (2025/1964) | O(1) dist | CCATE | Yes (NIZK) | No | Yes | High | Setup cost | Dynamic membership |
| **Ringtail** (2024/1113) | O(N) | LWE | Yes | No | Yes | High | 2-round only | Interactive overhead |
| **Threshold Raccoon** (2024/184)| O(N) | Dilithium-like| Yes | No | Yes | High | 3-round | Comm/User cost |
| **AOM-MLWE Sign** (2024/496) | O(N) | AOM-MLWE | Yes | No | Yes | High | New assumption | Adaptive security |
| **Strong UT** (2024/2078) | O(N) | FHE | Simulation | No | Yes | Low | Generic construction | Efficiency |

## Architecture Seeds

### Seed A: Folding-Based PV-ThFHE (LatticeFold+)
- **Mechanism**: Use LatticeFold+ to fold decryption proofs across N parties.
- **Pros**: O(log N) verification, transparent setup.
- **Cons**: High prover latency for large N.

### Seed B: PVSS-Compressed ThFHE (O(1) PVSS)
- **Mechanism**: Use CCA2-secure threshold encryption to compress share distribution.
- **Pros**: O(1) online complexity, high scalability.
- **Cons**: Heavy offline setup, not fully transparent.

### Seed C: Noise-Aware Verifiable FHE (vFHE + Noise Padding)
- **Mechanism**: Integrate Ring-R1CS verification from vFHE with Noise Padding from Paper 2025/409.
- **Pros**: Native FHE verification, efficient shares.
- **Cons**: Restricted to specific circuit types (Boolean/Ring R1CS).
