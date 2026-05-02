# PVTHFHE: Private-Verifiable Threshold FHE

Research prototype for private-verifiable threshold Fully Homomorphic Encryption (FHE).

## Intent

PVTHFHE targets private-verifiable threshold FHE with $O(n)$ per-party work and $O(\text{polylog } n)$ verifier cost. It enables a set of parties to jointly perform FHE operations where each step is publicly verifiable without revealing secret shares.

## Status: Research Prototype

**Warning: This is a research prototype.**

- **NOT production-ready.**
- **NOT battle-tested.**
- **Open Problem P1**: Lattice NIZK well-formedness soundness is not formally proven.
- **Open Problem P2**: LatticeFold+ over RLWE is simulated.

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
