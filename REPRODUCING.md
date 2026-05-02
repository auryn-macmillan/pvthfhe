# Reproducing Benchmarks

This document provides instructions for reproducing the scaling and performance benchmarks reported in this repository.

## Toolchain Versions (PINNED)

Reproducibility requires the exact toolchain versions used during development:

- **Rust**: `1.95.0` (stable)
- **Nargo (Noir)**: `1.0.0-beta.20`
- **BB CLI (Barretenberg)**: `5.0.0-nightly.20260324`
- **Forge (Foundry)**: `1.6.0-v1.7.0`

## Hardware Fingerprint

The benchmarks were executed on the following hardware:

- **CPU**: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S
- **RAM**: 8 GB
- **OS**: Ubuntu 24.04 LTS (Linux 6.8.0)

## Reproducing the Scaling Suite

To run the scaling benchmarks ($n=128$ to $n=1024$):

```bash
# Run the scaling benchmarks
just bench-scaling

# Run the reproducibility script (captures fingerprint and runs 3 repeats)
just reproduce-bench
```

## Expected Runtimes

| Number of Parties ($n$) | Aggregator Latency (ms) | Verifier Gas |
| :--- | :--- | :--- |
| 128 | 1.5 | 1,278* |
| 256 | 6.0 | 1,278* |
| 512 | 43.0 | 1,278* |
| 1024 | 188.0 | 1,278* |

*\*Note: Verifier gas is constant due to the use of a surrogate UltraHonk verifier. Real UltraHonk verification costs are estimated between 200k and 500k gas.*

## Reproducing On-Chain Verification

To verify the gas costs and correctness of the Solidity verifier:

```bash
just verify-onchain
```

## Scaling Methodology

Scaling benchmarks are performed in-process using the `pvthfhe-bench` crate. The benchmarks simulate the full pipeline:
1.  **DKG**: Simulated 3-round PVSS.
2.  **Partial Decrypt**: Generation of shares for $n$ parties.
3.  **Aggregation**: Folding $n$ proofs using the `FoldingAccumulator`.
4.  **Verification**: Final SNARK verification.

The measurements reflect end-to-end latency on the host machine.
