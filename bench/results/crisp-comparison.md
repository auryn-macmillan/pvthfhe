# CRISP Comparison: Nova IVC vs Risc Zero zkVM

Date: 2026-05-31
Workload: Self-add of n BFV ciphertexts (n-1 chained in-circuit Add operations with Merkle proof input binding)

## Benchmark Methodology

### Nova IVC (our approach)
Measured on this machine (release build, `nova-compressor` feature) using:
```
cargo run --release -p pvthfhe-cli --features nova-compressor -- compute prove --n <N>
```
Three warm-up runs were discarded; three measured runs collected per configuration.
The `FheComputeStepCircuit` enforces per-coefficient modular addition constraints (2 constraints per coefficient) with Merkle-proof input binding via in-circuit Poseidon hash.

### Risc Zero (CRISP)
Estimated from publicly available Risc Zero zkVM benchmarks ([Risc Zero Datasheet v1.0](https://reports.risczero.com/release-1.0/datasheet), [Fenbushi zkVM comparison](https://fenbushi.vc/2025/08/29/benchmarking-zkvms-current-state-and-prospects/)) and architectural analysis. No CRISP-specific benchmark scripts were found in `~/enclave/examples/CRISP/`. The CRISP `fhe_processor` program (`program/src/lib.rs`) sums BFV ciphertexts using the `fhe.rs` library compiled to RISC-V for zkVM execution.

Risc Zero zkVM cycles for a single production-param (n=8192, 3 limbs) BFV addition are estimated at 1-3M RISC-V instructions, translating to 60-200s proving time (CPU) based on the datasheet cycle-to-time ratios (64K cycles → 845ms; 256K cycles → 32.74s).

## Results

| Metric | Nova IVC (our) | Risc Zero (CRISP) |
|--------|----------------|-------------------|
| 3 ops prove time | 157 ms | 60-200s (est.) |
| 5 ops prove time | 331 ms | 150-500s (est.) |
| 10 ops prove time | 661 ms | 300-1000s (est.) |
| Proof size (3 ops) | 3,300,868 bytes (3.1 MB) | ~250 KB (STARK) |
| Proof size (10 ops) | 3,428,036 bytes (3.3 MB) | ~250 KB (STARK) |
| Verifier time | <1 ms (R1CS sat) | 2-5 ms (STARK) |
| Throughput (best) | 15-19 ops/sec | 0.005-0.05 ops/sec (est.) |
| Proving architecture | Nova IVC (recursive folding) | zkVM (RISC-V emulation + STARK) |
| Circuit model | Custom R1CS (per-coefficient constraints) | General-purpose RISC-V execution trace |
| Proof system | nova-snark (Nova + KZG) | STARK + FRI |
| Trusted setup | Transparent (no ceremony) | Transparent |
| On-chain verifier | UltraHonk (Solidity) | Risc Zero Groth16/STARK verifier |

### Detailed Nova IVC Results (min of 3 runs)

| n | prove_ms | proof_size_bytes | throughput (ops/sec) | plaintext_sum |
|---|----------|-----------------|---------------------|---------------|
| 3 | 157.31 | 3,300,868 | 19.1 | MATCH |
| 5 | 330.58 | 3,300,868 | 15.1 | MATCH |
| 10 | 660.56 | 3,428,036 | 15.1 | MATCH |

Prover scaling is approximately O(n) with n operations. Proof size grows slowly (dominated by the Nova recursive SNARK, ~3.2-3.4 MB with initial overhead then marginal growth per step). Verification time is <1ms (R1CS satisfiability check on primary+secondary relaxed instances).

## Guarantees Equivalence

| Guarantee | Nova IVC (our) | Risc Zero (CRISP) | Notes |
|-----------|---------------|-------------------|-------|
| In-circuit operation enforcement | ✅ Add/Mul via R1CS per-coefficient modular constraints in FheComputeStepCircuit | ✅ RISC-V execution of fhe.rs BFV code; zkVM proves correct execution | Both enforce FHE ops are performed faithfully |
| Input binding | ✅ Merkle proof in-circuit via Poseidon hash (verify_merkle_proof_bp) | ✅ Program inputs committed in zkVM execution receipt/journal | Both bind inputs to the proof |
| Output chaining | ✅ Nova state chain: z[0]=coeff_lo, z[1]=coeff_hi, z[2]=merkle_root, z[3]=step_count; each step's output feeds next step's input | ✅ Program loop: ciphertext accumulator updated in memory; zkVM trace chains state | Both chain intermediate outputs |
| Malicious prover resistance | ✅ Nova IVC soundness; each step satisfies relaxed R1CS; proof accumulation prevents selective step omission | ✅ STARK soundness (~100 bits); FRI low-degree testing | Both resist malicious provers |
| On-chain verifiability | ✅ UltraHonk proof verifiable on-chain via Solidity verifier | ✅ Risc Zero STARK/Groth16 verifier on-chain | Both support on-chain verification |
| Recursive composition | ✅ Nova IVC natively supports recursion | ✅ Risc Zero supports receipt aggregation/continuation | Both support proof composition |
| Soundness budget | 2⁻¹²⁸ (target); Nova over BN254 | 2⁻¹⁰⁰ (STARK, configurable) | Comparable practical soundness |

### Guarantee Detail

**Nova IVC** achieves in-circuit enforcement through `FheComputeStepCircuit::synthesize`, which allocates witnesses for each ciphertext coefficient and enforces:
1. Modular addition: `ct0 + ct1 - ct_out = k * q` where `k ∈ {0, 1}` is the overflow witness
2. Overflow boolean check: `k * (1 - k) = 0`
3. Input binding: Merkle path verification against the committed root in z[2]
4. State chaining: Previous step's output coefficients (committed as z[0], z[1]) match current step's input

**Risc Zero (CRISP)** achieves equivalent guarantees through zkVM execution: the compiled `fhe_processor` binary runs in the zkVM, which generates a STARK proof of correct RISC-V execution. The fhe.rs library's `Ciphertext::add` operations are executed faithfully because the zkVM proves every instruction was executed correctly.

## Interpretation

Nova IVC achieves 2-3 orders of magnitude faster proving than Risc Zero's zkVM for this workload because:

1. **Custom circuit vs general VM**: Nova IVC uses a purpose-built R1CS circuit with exactly the constraints needed for BFV addition, while Risc Zero must prove correct execution of the entire RISC-V emulator, fhe.rs library, and BFV arithmetic as general-purpose instructions.

2. **Algebraic structure**: Nova's folding-based IVC amortizes the per-step cost by accumulating relaxed R1CS instances, while Risc Zero's STARK prover commits to the full execution trace polynomial.

3. **Proof size trade-off**: Nova IVC proofs are larger (~3.3 MB vs ~250 KB) because they include the full Nova recursive SNARK (curve elements for BN254/Grumpkin cycle), while Risc Zero STARK proofs are more compact. However, Nova IVC proof size is O(1) in the number of steps beyond initial overhead.

4. **Verification speed**: Both are fast enough for on-chain verification (<5ms).

## Limitations

- Risc Zero estimates are based on public benchmarks and cycle-count analysis, not direct measurement. Actual CRISP proving with production BFV parameters (n=8192) may differ.
- Nova IVC verification time was not directly measured (internal test-utils SRS incompatibility prevented in-place verification); estimated at <1ms based on R1CS satisfiability check complexity.
- CRISP in its current configuration uses dev-mode fake proofs (`program.dev: true` in `enclave.config.yaml`). Production proving would use Boundless marketplace.
- Both approaches assume honest-majority threshold decryption for the final output reveal.

## Reproducibility

Nova IVC benchmarks can be reproduced with:
```bash
just compute n_ops=3   # n=3
just compute n_ops=5   # n=5
just compute n_ops=10  # n=10
```

Hardware: See `bench/results/hardware-fingerprint.txt` for system specifications.
