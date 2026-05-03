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

## P4 Stack Pins

The P4 Hermine-adapted PVSS design memo fixes the Rust-side cryptographic and serialization stack to the following crate versions:

- `serde = "1.0.228"`
- `serde_json = "1.0.145"`
- `sha2 = "0.10.9"`
- `sha3 = "0.10.8"`
- `merlin = "3.0.0"`
- `risc0-zkvm = "2.1.0"`
- `sp1-sdk = "5.0.0"`

These pins cover the frozen serde/JSON wire format, SHA-256 transcript digests, SHAKE256 transcript challenges, the native Rust Fiat-Shamir transcript layer, and the approved zkVM fallbacks.

## Artifact Reproduction (Paper Claims)

To reproduce the core paper claims in one command:

```bash
just artifact-reproduce
```

This runs, in order:
1. `cargo build --workspace` — builds all Rust crates
2. `just p3-bench` — on-chain gas benchmark (verifies P3 gas-bound claim)
3. `just e2e-real` — end-to-end real integration test

Expected total runtime: ≤ 5 minutes on reference hardware.
Evidence files are written to `.sisyphus/evidence/p3-impl/`.

For the full gate suite:

```bash
just phase1-gate && just phase2-gate && just phase3-gate && just paper-gate
```
