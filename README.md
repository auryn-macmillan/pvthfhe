# PVTHFHE: Private-Verifiable Threshold FHE

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains **critical cryptographic surrogates** that provide no real security:
> - **no on-chain cryptographic verification — verifier accepts any proof bytes**
> - **Noir circuits are tautological surrogates** (assert(x == x) — no real constraints)
> - **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.

Research prototype for private-verifiable threshold Fully Homomorphic Encryption (FHE).

## Intent

PVTHFHE targets private-verifiable threshold FHE with $O(n)$ per-party work and $O(\text{polylog } n)$ verifier cost. Our research prototype demonstrates the feasibility of this architecture, using cryptographic surrogates for the folding (P2) and on-chain verification (P3) layers.

## Status: Research Prototype

**Warning: This is a research prototype.**

- **NOT production-ready.**
- **NOT battle-tested.**
- **Open Problem P1**: Lattice NIZK well-formedness soundness is not formally proven.
- **Open Problem P2**: LatticeFold+ over RLWE is simulated.
- **Open Problem P3**: The deployed `P3RealVerifier.sol` uses a **trusted-signer surrogate** (`ecrecover` against a hard-coded key) — it does **not** cryptographically verify the P2 accumulator. Full on-chain soundness is an open implementation task.

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

# Run the end-to-end demo
just demo-e2e --seed 1
```

### Docker Quickstart

```bash
docker build -f Dockerfile.quickstart -t pvthfhe-quickstart .
docker run --rm pvthfhe-quickstart
```

## Key Commands

- `just demo-e2e`: Run end-to-end demo (n=128).
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
