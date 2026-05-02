# Phase 1 Gate Report: Publicly Verifiable Threshold FHE

## 1. Executive Summary

Phase 1 concluded with a comprehensive exploration of the design space for publicly verifiable threshold FHE (PV-ThFHE). We investigated three candidate architectures, established a robust threat model, and benchmarked critical path components including RLWE relations in Noir, lattice folding overheads, and on-chain KZG verification costs.

The central challenge identified is scaling to large committees ($N \ge 1024$) while maintaining $O(1)$ on-chain verification gas and $O(n)$ per-party work. Architecture A (Silent Setup) provides high feasibility but faces a gas ceiling for its native KZG batching path. Architecture C (Noir Recursive) is conceptually elegant but currently blocked by the extreme circuit sizes ($>10\text{M}$ gates) required for $O(N)$ recursive aggregation.

**Recommendation: Architecture B (Lattice Folding + MicroNova)** is the primary recommendation for Phase 2. It offers the best scaling profile through $O(\log N)$ folding rounds and $O(1)$ on-chain verification gas via SNARK compression. While it introduces a significant theoretical open problem regarding lattice NIZK well-formedness soundness, recent literature (Cyclo, 2026/359) has materially improved its feasibility.

Phase 2 will focus on the full protocol specification of Architecture B, formalizing the lattice NIZK subproblem, and designing the threshold key generation and on-chain verifier.

## 2. Threat Model Recap

The PV-ThFHE system operates under the following security parameters and adversarial constraints:

*   **Corruption Model**: Honest-majority threshold, where $t = \lfloor n/2 \rfloor + 1$.
*   **Adversary**: Static malicious with rushing capabilities. The adversary chooses corrupted parties upfront and can deviate arbitrarily from the protocol.
*   **Security Level**: 120-bit security floor for all RLWE parameters.
*   **Abort Model**: Abort-with-public-blame. Any party submitting invalid shares or proofs is publicly identified, allowing for attributable failure.
*   **Verifiability**: Any external observer can audit the public transcript and verify the correctness of the threshold decryption without access to secret material.

## 3. Architecture Comparison

We evaluated three architectures against our scaling and gas constraints.

| Dimension | Arch-A (Silent Setup) | Arch-B (Lattice Folding) | Arch-C (Noir Recursive) |
| :--- | :--- | :--- | :--- |
| **Scaling** | $O(N)$ Verifier (KZG) | $O(\log N)$ Aggregator | $O(N)$ Aggregator Circuit |
| **On-chain Gas** | ~3.65M (Batch-128) | ~500k (SNARK) | ~500k (SNARK) |
| **N=1024 Feasibility** | HIGH (but hits gas ceiling) | MEDIUM | LOW (circuit size) |
| **Primary Risk** | Gas ceiling at $N \ge 1024$ | NIZK Soundness | Proving Time/Size |

*   **Arch-A**: Relies on batched KZG openings. Feasible for small committees but the linear gas growth with $N$ makes it unsuitable for the $N=1024$ target without additional SNARK layers.
*   **Arch-B**: Uses lattice folding to aggregate $N$ proofs into a single accumulator, then compresses it. This achieves the target $O(1)$ on-chain cost.
*   **Arch-C**: Direct recursion in Noir. Rejected because the aggregator circuit size for $N=1024$ (estimated 10M-50M gates) exceeds current Barretenberg backend capabilities.

## 4. Benchmark Summary

Benchmarks from T11, T12, and T13 provided the empirical basis for the cost model.

*   **RLWE Relation (T11)**: A surrogate RLWE circuit for $N=64$ coefficients demonstrated linear scaling. Extrapolating to production $N=8192$ results in an estimated ~4096 gates and ~3.7s proving time per share.
*   **Folding (T12)**: Measured $O(1)$ amortized folding time. The accumulator size remained constant at 280 bytes across all tested committee sizes, confirming the efficiency of the NIFS-style aggregation.
*   **KZG Gas (T13)**: On-chain verification for a batch of 128 openings consumed 3,649,775 gas. This is 73% of our 5M gas target, confirming that linear batching will not scale to $N=1024$.

## 5. Bootstrapping Decision

The decision for Phase 1 is to **DEFER** the implementation of publicly verifiable (PV) bootstrapping.

**Rationale**: Estimates for PV bootstrapping in Noir/BB show a 30x-100x overhead compared to simple decryption-share proofs.
*   CKKS PV bootstrapping: 30x-80x overhead.
*   BFV PV bootstrapping: 60x-100x overhead.
Given that PV bootstrapping is not on the critical path for the core threshold decryption goal, it will be revisited in Phase 3 if recursive folding optimizations (like MicroNova) prove efficient enough to absorb the overhead.

## 6. Recommendation: Architecture B

Architecture B is recommended as the primary path for PV-ThFHE.

**Rationale**:
1.  **Gas Efficiency**: It provides a constant ~500k gas cost on-chain regardless of the committee size, which is essential for our $N=1024$ target.
2.  **Aggregation Efficiency**: $O(\log N)$ folding rounds provide a more scalable aggregation path than linear SNARK recursion.
3.  **Modern Advancements**: Integration with Cyclo (2026/359) reduces the norm growth during folding, improving prover performance.

**Acknowledged Risks**: The primary risk is the theoretical soundness of the lattice NIZK well-formedness for folded instances. If this proves intractable, Architecture A with a SNARK compression layer serves as the secondary fallback.

## 7. Open Problems for Phase 2

1.  **Lattice NIZK Well-formedness Soundness**: Proving that the folded lattice instances preserve the "shortness" and "correctness" properties of the original RLWE relations.
2.  **LatticeFold-over-RLWE**: Developing the specific folding argument for RLWE relations, potentially leveraging the MicroNova framework.
3.  **Silent-setup Port Security**: If falling back to Arch-A, ensuring the security reduction holds for our specific ring dimension and modulus.

## 8. Phase 2 Scope

Phase 2 (Design) will encompass the following workstreams:

1.  **Full Protocol Specification**: A detailed mathematical spec for Architecture B, including the lattice PVSS and folding logic.
2.  **Lattice NIZK Subproblem Analysis**: Focused research on the soundness gaps identified in Phase 1.
3.  **Noir Circuit Design**: Designing the ACIR-efficient RLWE relation circuits for the $N=8192$ production regime.
4.  **Threshold Keygen Protocol**: Designing the publicly verifiable secret sharing (PVSS) mechanism for committee setup.
5.  **On-chain Verifier Design**: Solidity architecture for the UltraHonk/MicroNova verifier.
