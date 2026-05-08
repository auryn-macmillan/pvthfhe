# PVTHFHE: Private-Verifiable Threshold FHE

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE:
> - **on-chain verifier uses Sonobe substitution (off-chain Sonobe + on-chain commitment)**
> - **Noir circuits implement the real aggregation and wrapping logic**
> - **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.

Research prototype for private-verifiable threshold Fully Homomorphic Encryption (FHE).

## Intent

PVTHFHE targets private-verifiable threshold FHE with $O(n)$ per-party work and $O(\text{polylog } n)$ verifier cost. Our research prototype demonstrates the feasibility of this architecture. Due to current recursive SNARK performance constraints, we use Sonobe as a substitute for the folding (P2) layer behind a bounded migration surface.

## Status: Research Prototype

**Warning: This is a research prototype.**

- **NOT production-ready.**
- **NOT battle-tested.**
- **FHE backend**: ⚠️ real but unproven (honest-but-curious only; no Greco well-formedness proofs yet).
- **Open Problem P1**: Lattice NIZK well-formedness soundness is not formally proven.
- **Stage 0 Build-time Tripwire**: The project includes a build-time tripwire (see `SECURITY.md`) to prevent inadvertent production use.
- **Folding Layer**: LatticeFold+ over RLWE is substituted by Sonobe in the current prototype.
- **On-chain Verification**: The on-chain `PvtFheVerifier` uses an off-chain Sonobe + on-chain commitment topology (see `ARCHITECTURE.md`).
- **Benchmark Comparison**: See [bench/results/comparison-5d7853a.md](bench/results/comparison-5d7853a.md) for a performance evaluation of the Sonobe substitution; all 12 rows are now populated with wired PVTHFHE timings and merge notes where stages collapse into a single pass.

## Quickstart

### Dependencies

- **Rust**: 1.95.0
- **Foundry**: 1.6.0-v1.7.0
- **Noir**: 1.0.0-beta.20
- **BB CLI**: 5.0.0-nightly.20260324
- **Just**: casey/just

### Local Setup

```bash
# Clone the repository
git clone https://github.com/example/pvthfhe
cd pvthfhe

# Run the end-to-end demo (defaults: n=8, t=5, seed=1)
just demo-e2e
```

The demo runs the full real-cryptography pipeline: keygen, NIZK, RLWE folding via Cyclo, and Sonobe Nova compression + verify. The on-chain Solidity verifier step is **not** exercised by `just demo-e2e`; use `just bench-comparison` to include the on-chain verify path.

### Docker Quickstart

```bash
docker build -f Dockerfile.quickstart -t pvthfhe-quickstart .
docker run --rm pvthfhe-quickstart
```

## Key Commands

- `just demo-e2e`: Run end-to-end demo (n=8, t=5; full real-crypto pipeline, no on-chain step) (supported range: n ≤ 255).
- `just test-all`: Run full test suite across Rust, Noir, and Solidity.
- `just bench-scaling`: Run scaling benchmarks for n=128 to 1024.
- `just verify-onchain`: Verify the aggregated proof on a local EVM.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): System design and protocol details.
- [SECURITY.md](SECURITY.md): Threat model, assumptions, and limitations.
- [REPRODUCING.md](REPRODUCING.md): Detailed steps for reproducing benchmarks.
- [Design Docs](.sisyphus/design/): Detailed specifications and research notes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
