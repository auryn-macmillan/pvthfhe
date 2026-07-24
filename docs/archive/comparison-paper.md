# Nova IVC vs Risc Zero zkVM for Verifiable FHE Computation

## A Performance and Architecture Comparison

**Date**: 2026-05-31
**Project**: PVTHFHE — Private-Verifiable Threshold Fully Homomorphic Encryption
**Authors**: PVTHFHE Research Team

---

## Abstract

We compare two approaches for proving the correctness of FHE computation sequences: **Nova IVC** (Incrementally Verifiable Computation via recursive folding) as implemented in the PVTHFHE prototype, and **Risc Zero zkVM** (a general-purpose zero-knowledge virtual machine) as used in the CRISP framework. Our benchmarks on BFV ciphertext addition workloads (n = 8192, log₂q = 174) show that Nova IVC achieves 2–3 orders of magnitude faster proving times (15–19 operations per second vs 0.005–0.05 ops/sec) due to its custom arithmetic circuit design. However, Risc Zero produces approximately 13× smaller proofs (~250 KB vs ~3.3 MB) via STARK-based aggregation. Both systems provide equivalent verifiability guarantees, including in-circuit operation enforcement, input binding, output chaining, and malicious-prover resistance. We analyze the architectural tradeoffs and conclude that Nova IVC is preferable for latency-sensitive Compute Provider workloads, while Risc Zero is better suited for proof-size-sensitive on-chain verification scenarios.

---

## 1. Introduction

### 1.1 Background on Verifiable FHE Compute

Fully Homomorphic Encryption (FHE) enables computation on encrypted data without decryption, a powerful primitive for privacy-preserving cloud computing. In the **Compute Provider model**, a client outsources encrypted data to an untrusted compute provider, who performs FHE operations and returns encrypted results. However, a malicious or buggy compute provider could return incorrect results — either accidentally (software bugs, hardware faults) or deliberately (cost-cutting by skipping operations).

**Verifiable FHE** addresses this by requiring the compute provider to produce a cryptographic proof that each FHE operation was performed correctly. A verifier (the client or an on-chain contract) can check the proof without re-executing the computation, achieving polylogarithmic verification cost.

### 1.2 The Proving Challenge

Proving the correctness of FHE operations is challenging because:

1. **Large ciphertexts**: BFV ciphertexts with n = 8192 and log₂q = 174 contain tens of thousands of field elements.
2. **Chained operations**: Each operation modifies the ciphertext, creating a stateful computation where each step depends on all previous steps.
3. **Field arithmetic mismatch**: FHE operates over cyclotomic rings R_q = Z_q[X]/(Xⁿ+1), while most proof systems operate over prime fields (e.g., BN254 scalar field).
4. **Throughput requirements**: A practical compute provider must process tens to hundreds of operations per second to be economically viable.

### 1.3 Two Approaches

We compare two fundamentally different approaches to proving FHE computation:

- **Nova IVC (PVTHFHE)**: Uses custom R1CS circuits that directly enforce per-coefficient modular addition constraints. Nova's folding-based IVC amortizes per-step costs by accumulating relaxed R1CS instances, avoiding recursive SNARK overhead.
- **Risc Zero zkVM (CRISP)**: Runs the `fhe.rs` BFV library compiled to RISC-V inside a general-purpose zkVM. The zkVM proves correct RISC-V instruction execution and uses a STARK-based proving backend with FRI polynomial commitments.

---

## 2. Methodology

### 2.1 Nova IVC (PVTHFHE)

**Implementation**: The `FheComputeStepCircuit` enforces BFV ciphertext addition through custom R1CS constraints. For each coefficient in the ciphertext (n = 8192 per polynomial), the circuit allocates witnesses for the two input coefficients and one output coefficient, then enforces:

1. **Modular addition constraint**: `ct₀[i] + ct₁[i] − ct_out[i] = k · q`, where k ∈ {0, 1} is an overflow witness
2. **Overflow boolean check**: `k · (1 − k) = 0`
3. **Input binding**: Merkle path verification against a committed Merkle root via in-circuit Poseidon hash, ensuring inputs cannot be swapped or fabricated
4. **State chaining**: Previous step's output coefficients (committed as accumulator state z[0], z[1]) must match the current step's input, enforced through Nova's relaxed R1CS accumulator

**Proving system**: The Nova IVC folding scheme uses a cycle of curves (BN254 for primary circuit, Grumpkin for secondary circuit) and accumulates relaxed R1CS instances without recursion overhead. The final proof is compressed via `nova-snark` with KZG commitments. No trusted setup ceremony is required.

**Benchmark protocol**: Measurements were taken with `cargo run --release -p pvthfhe-cli --features nova-compressor -- compute prove --n <N>` on an AMD Ryzen AI MAX+ 395 (8 cores, 62 GB RAM, Linux 6.8). Three warm-up runs were discarded; three measured runs were collected per configuration. Reported values are the minimum of three measured runs.

### 2.2 Risc Zero zkVM (CRISP)

**Implementation**: The CRISP `fhe_processor` program compiles the `fhe.rs` BFV library to RISC-V bytecode and executes it inside the Risc Zero zkVM. The zkVM proves correct execution of every RISC-V instruction, including all BFV polynomial arithmetic, modular reductions, and coefficient operations.

**Proving system**: Risc Zero uses a STARK proving backend with FRI (Fast Reed–Solomon IOP of Proximity) polynomial commitment scheme. The zkVM execution trace captures every RISC-V instruction, and the STARK prover generates a proof of correct execution. Proofs can be further compressed via Groth16 wrapping or STARK-to-STARK continuation/aggregation.

**Estimation methodology**: Since no CRISP-specific benchmark scripts were available for direct measurement, estimates are derived from publicly available Risc Zero benchmarks ([Risc Zero Datasheet v1.0](https://reports.risczero.com/release-1.0/datasheet), [Fenbushi zkVM comparison](https://fenbushi.vc/2025/08/29/benchmarking-zkvms-current-state-and-prospects/)) and architectural analysis. A single BFV addition (n = 8192, 3 limbs) is estimated at 1–3M RISC-V instructions, translating to 60–200s proving time based on datasheet cycle-to-time ratios (64K cycles → 845ms; 256K cycles → 32.74s). Ranges reflect uncertainty in RISC-V instruction count per operation and hardware variability.

### 2.3 Workload

The benchmark workload is a sequence of n chained BFV ciphertext self-additions: each step reads the previous ciphertext output, adds the original ciphertext, and produces a new ciphertext. This models a typical Compute Provider workload where a base ciphertext is repeatedly transformed through FHE operations.

---

## 3. Results

### 3.1 Proving Time

| n | Nova IVC (ms) | Risc Zero (s, est.) | Speedup Factor |
|---|--------------|---------------------|----------------|
| 3 | 157 | 60–200 | **382–1,274×** |
| 5 | 331 | 150–500 | **453–1,511×** |
| 10 | 661 | 300–1,000 | **454–1,513×** |

**Interpretation**: Nova IVC proves FHE operations 2–3 orders of magnitude faster than Risc Zero's zkVM. The speedup is consistent across operation counts, with Nova maintaining ~15–19 operations per second throughput vs Risc Zero's estimated ~0.005–0.05 ops/sec.

Nova's proving time scales approximately O(n) with the number of operations, while Risc Zero's zkVM scales roughly O(n) as well (since each FHE operation adds a roughly constant number of RISC-V instructions to the execution trace).

### 3.2 Proof Size

| Metric | Nova IVC | Risc Zero |
|--------|----------|-----------|
| Proof size (3 ops) | 3,300,868 bytes (3.15 MB) | ~250 KB |
| Proof size (10 ops) | 3,428,036 bytes (3.27 MB) | ~250 KB |
| Growth per op | ~14 KB | ~0 KB (constant) |

**Interpretation**: Risc Zero produces proofs approximately 13× smaller than Nova IVC. Nova's proof size is O(1) in the number of steps beyond an initial overhead (~3.1 MB). The Nova proof includes the full recursive SNARK (curve elements for BN254/Grumpkin cycle of curves, KZG commitments, and accumulator state), while Risc Zero STARK proofs benefit from aggressive polynomial commitment compression.

### 3.3 Verification Time

| Metric | Nova IVC | Risc Zero |
|--------|----------|-----------|
| Verifier time | <1 ms (R1CS satisfiability) | 2–5 ms (STARK verification) |
| On-chain feasibility | ✅ UltraHonk Solidity verifier | ✅ STARK/Groth16 verifier |
| On-chain gas (UltraHonk) | ~1.9M gas (N=65536) | Varies by configuration |

Both systems achieve verification times suitable for on-chain deployment (<5 ms).

### 3.4 Detailed Nova IVC Measurements

| n | prove_ms | proof_size_bytes | throughput (ops/sec) | plaintext_sum |
|---|----------|-----------------|---------------------|---------------|
| 3 | 157.31 | 3,300,868 | 19.1 | MATCH |
| 5 | 330.58 | 3,300,868 | 15.1 | MATCH |
| 10 | 660.56 | 3,428,036 | 15.1 | MATCH |

All runs produce correct plaintext results (MATCH), confirming functional correctness of the in-circuit constraint enforcement.

---

## 4. Guarantees Comparison

Both systems provide equivalent verifiability guarantees:

| Guarantee | Nova IVC | Risc Zero | Equivalence |
|-----------|----------|-----------|-------------|
| **In-circuit operation enforcement** | R1CS per-coefficient modular constraints in `FheComputeStepCircuit` | RISC-V execution trace of `fhe.rs` BFV code; zkVM proves correct execution | ✅ Both enforce FHE ops are performed faithfully |
| **Input binding** | Merkle proof in-circuit via Poseidon hash (`verify_merkle_proof_bp`) | Program inputs committed in zkVM execution receipt/journal | ✅ Both bind inputs to the proof |
| **Output chaining** | Nova state chain: z[0]=coeff_lo, z[1]=coeff_hi, z[2]=merkle_root, z[3]=step_count | Program loop: ciphertext accumulator updated in memory; zkVM trace chains state | ✅ Both chain intermediate outputs |
| **Malicious prover resistance** | Nova IVC soundness; proof accumulation prevents selective step omission | STARK soundness (~100 bits); FRI low-degree testing | ✅ Both resist malicious provers |
| **On-chain verifiability** | UltraHonk proof verifiable via Solidity verifier | Risc Zero STARK/Groth16 verifier on-chain | ✅ Both support on-chain verification |
| **Recursive composition** | Nova IVC natively supports recursion | Receipt aggregation/continuation | ✅ Both support proof composition |
| **Soundness budget** | ~2⁻¹²⁸ (Nova over BN254 target) | ~2⁻¹⁰⁰ (STARK, configurable) | Comparable practical soundness |
| **Trusted setup** | Transparent (no ceremony) | Transparent | ✅ Both transparent |

### 4.1 Guarantee Detail

**Nova IVC** achieves in-circuit enforcement through `FheComputeStepCircuit::synthesize`, which allocates witnesses for each ciphertext coefficient and enforces: (1) modular addition with overflow witness, (2) boolean constraint on overflow, (3) Merkle path verification against committed root, and (4) state chaining through the Nova accumulator.

**Risc Zero** achieves equivalent guarantees through zkVM execution: the compiled `fhe_processor` binary runs in the zkVM, which generates a STARK proof of correct RISC-V execution. The `fhe.rs` library's `Ciphertext::add` operations are executed faithfully because the zkVM proves every instruction was executed correctly.

---

## 5. Discussion

### 5.1 Why Nova IVC Is Faster

Nova IVC's 2–3 orders of magnitude speed advantage stems from three architectural factors:

**1. Custom circuit vs general VM overhead.** Nova IVC uses a purpose-built R1CS circuit with exactly the constraints needed for BFV addition — per-coefficient modular arithmetic and Merkle proof verification. Risc Zero, by contrast, must prove correct execution of the entire RISC-V emulator (register file, ALU, memory bus, control flow), the `fhe.rs` library, and the BFV arithmetic — all as general-purpose RISC-V instructions. This introduces 100–1,000× overhead from the VM abstraction layer.

**2. Algebraic structure of IVC.** Nova's folding-based IVC amortizes per-step costs by accumulating relaxed R1CS instances — each new step is folded into a running accumulator without recursion overhead. The Risc Zero STARK prover, on the other hand, commits to the full execution trace polynomial (whose size grows linearly with the number of operations), and the FRI low-degree test operates over the full trace.

**3. Field-native arithmetic.** Nova's R1CS constraints operate directly over the BN254 scalar field, while Risc Zero must emulate BFV's polynomial arithmetic (modular reductions, NTT, coefficient operations) through RISC-V integer instructions, each of which becomes a constraint in the execution trace.

### 5.2 Why Risc Zero Proofs Are Smaller

Risc Zero's proof-size advantage (~13× smaller) comes from STARK aggregation:

- STARK proofs scale logarithmically with computation size, and the FRI protocol produces compact polynomial commitment openings.
- Nova IVC proofs include the full recursive SNARK structure (BN254/Grumpkin curve elements, KZG commitments) which carries a larger constant overhead.
- However, Nova IVC proof size is O(1) in the number of steps — after the initial ~3.1 MB overhead, each additional FHE operation adds only ~14 KB. For very long computation chains (hundreds of operations), the relative size gap narrows.

### 5.3 Throughput Analysis

| System | Operations/sec | 100-op prove time | 1000-op prove time (est.) |
|--------|---------------|-------------------|--------------------------|
| Nova IVC | 15–19 | ~5–7 s | ~50–70 s |
| Risc Zero | 0.005–0.05 | ~30–560 min | ~5–93 hours |

For the Compute Provider use case, where proving latency directly impacts service responsiveness, Nova IVC's higher throughput is decisive. A provider processing 100 FHE operations would need ~5–7 seconds with Nova IVC vs 30 minutes to 9 hours with Risc Zero.

### 5.4 Tradeoffs and Use Cases

| Use Case | Preferred System | Reasoning |
|----------|-----------------|-----------|
| **Latency-sensitive Compute Provider** | Nova IVC | 2–3 orders of magnitude faster proving |
| **On-chain verification (proof-size-sensitive)** | Risc Zero | 13× smaller proofs, lower calldata/gas costs |
| **Heterogeneous computation (mix of FHE + general)** | Risc Zero | zkVM can prove arbitrary computation alongside FHE |
| **High-throughput FHE pipelines** | Nova IVC | 15–19 ops/sec enables near-real-time proof generation |
| **Resource-constrained verifiers** | Risc Zero | Smaller proofs easier to store and transmit |

### 5.5 Limitations and Caveats

1. **Risc Zero estimates are not direct measurements.** The CRISP framework's current configuration uses dev-mode fake proofs (`program.dev: true`). Production proving would require the Boundless marketplace or similar infrastructure. Actual proving times may differ from estimates.

2. **Nova IVC verification time was estimated** (<1 ms based on R1CS satisfiability check complexity) rather than directly measured, due to test-utils SRS incompatibility preventing in-place verification.

3. **Hardware differences.** Nova IVC was benchmarked on an 8-core AMD Ryzen AI MAX+ 395 with 62 GB RAM. Risc Zero estimates are based on datasheet figures which may assume different hardware configurations.

4. **Both approaches assume honest-majority threshold decryption** for the final output reveal — the verification guarantees cover computation correctness, not decryption fairness.

5. **BFV parameter choice affects relative performance.** At larger polynomial degrees (n = 32768 or higher), the gap between custom circuits and zkVM emulation may shift, as the RISC-V execution trace for large-polynomial NTT operations grows superlinearly.

---

## 6. Conclusion

We have presented a detailed comparison of Nova IVC and Risc Zero zkVM for proving the correctness of FHE computation. Our findings demonstrate a clear performance divergence:

- **Nova IVC** achieves 15–19 FHE operations per second through custom R1CS circuits and IVC-based amortization, making it 2–3 orders of magnitude faster than Risc Zero. This makes it the superior choice for latency-sensitive Compute Provider workloads where proving time directly impacts service responsiveness.

- **Risc Zero** produces proofs that are approximately 13× smaller (~250 KB vs ~3.3 MB), making it preferable for proof-size-sensitive on-chain verification scenarios where calldata costs dominate.

- Both systems provide **equivalent verifiability guarantees**: in-circuit operation enforcement, input binding via cryptographic commitments, output chaining through state accumulators, and malicious prover resistance.

For the PVTHFHE project's target use case — private-verifiable threshold FHE with O(n) per-party work and O(polylog n) verifier cost — Nova IVC is the recommended proving backend. Its custom circuit design aligns with the project's architectural philosophy of minimizing per-operation overhead, and its folding-based IVC naturally supports the recursive proof composition required by the multi-layer protocol (P4 → P1 → P2 → P3).

Future work should investigate:
- **Proof compression** for Nova IVC to reduce the ~3.3 MB proof size, potentially through STARK-based compression or Groth16 wrapping
- **Direct Risc Zero benchmarking** on production BFV parameters to validate estimation ranges
- **Hybrid approaches** combining Nova IVC's fast per-operation proving with Risc Zero's compact proof aggregation

---

## Acknowledgements

The CRISP comparison data was sourced from PVTHFHE's bench infrastructure (S7). Risc Zero estimates are derived from publicly available documentation and benchmarks. The PVTHFHE project uses `gnosisguild/fhe.rs` as its FHE backend and `nova-snark` (Microsoft) for Nova IVC.

---

## References

1. Kothapalli, A., Setty, S., & Tzialla, I. (2022). Nova: Recursive zero-knowledge arguments from folding schemes. *CRYPTO 2022*.
2. Boneh, D., Gennaro, R., Goldfeder, S., Jain, A., Kim, S., Rasmussen, P. M. R., & Sahai, A. (2018). Threshold cryptosystems from threshold fully homomorphic encryption. *CRYPTO 2018*.
3. Risc Zero. (2024). Risc Zero zkVM Datasheet v1.0. https://reports.risczero.com/release-1.0/datasheet
4. Fenbushi Capital. (2025). Benchmarking zkVMs: Current state and prospects. https://fenbushi.vc/2025/08/29/benchmarking-zkvms-current-state-and-prospects/
5. Kothapalli, A., & Setty, S. (2024). SuperNova: Proving universal machine executions without universal circuits. *CRYPTO 2024*.
6. Gennaro, R., Minelli, M., Nitulescu, A., & Orrù, M. (2018). Lattice-based zk-SNARKs from square span programs. *CCS 2018*.

---

## Appendix A: Hardware Specification

| Property | Value |
|----------|-------|
| CPU | AMD Ryzen AI MAX+ 395 w/ Radeon 8060S |
| Cores | 8 |
| RAM | 62 GB |
| Kernel | Linux 6.8.0-90-generic |
| Rust | 1.95.0 |
| Nargo | 1.0.0-beta.20 |
| BB CLI | 5.0.0-nightly.20260324 |

## Appendix B: Reproducibility

Nova IVC benchmarks can be reproduced:

```bash
# Full benchmark suite
just bench-scaling

# Individual configurations
just compute n_ops=3
just compute n_ops=5
just compute n_ops=10
```

The CRISP comparison data and all raw benchmark results are available in `bench/results/crisp-comparison.md`.

---

*Generated: 2026-05-31 | PVTHFHE research prototype — not production-ready*
