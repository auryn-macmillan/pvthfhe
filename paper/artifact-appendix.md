# Artifact Appendix

This appendix documents the research artifact accompanying the paper
**PVTHFHE: Private-Verifiable Threshold Fully Homomorphic Encryption**.

## Artifact Summary

The artifact is an open-source Rust/Noir/Solidity research prototype implementing
the four-layer PVTHFHE protocol (P4 → P1 → P2 → P3). It includes:

- **Rust workspace** (`crates/`): P4 PVSS keygen, P1 lattice NIZK, P2 folding accumulator, P3 verifier bindings, CLI, and bench harness.
- **Noir circuits** (`circuits/`): Zero-knowledge circuit for P1 well-formedness witness.
- **Solidity contracts** (`contracts/`): On-chain P3 verifier with gas-bound guarantees.
- **Benchmarks** (`bench/`): Scaling benchmarks and figure generation scripts.
- **Security proofs** (`docs/security-proofs/`): Formal proof sketches for all 19 theorems.

## Scope

The artifact supports:

- **Claim C1 (P4 Correctness/Performance)**: `just bench-p4` reproduces keygen/reconstruct latency and share sizes.
- **Claim C2 (P1 NIZK)**: `bench/p1/run.sh` reproduces P1 prove/verify latency.
- **Claim C2 (P1 NIZK)**: Theorem statements in `docs/security-proofs/p1/`.
- **Claim C3 (P2 Folding Soundness)**: `just p2-bench` runs folding accumulation bench.
- **Claim C4 (P3 Gas Bound ≤ 5,000,000)**: `just p3-bench` runs on-chain verifier gas measurement.
- **Claim C5 (End-to-End)**: `just e2e-real` runs the full pipeline integration test.

## Hardware Requirements

- CPU: x86_64 or ARM64, ≥ 8 GB RAM
- OS: Linux (Ubuntu 22.04+) or macOS 14+
- No GPU required

## Toolchain Prerequisites

See `REPRODUCING.md` for pinned versions:

| Tool       | Version                    |
|------------|----------------------------|
| Rust       | 1.95.0 (stable)            |
| Nargo      | 1.0.0-beta.20              |
| BB CLI     | 5.0.0-nightly.20260324     |
| Foundry    | 1.6.0-v1.7.0               |
| Just       | ≥ 1.13.0                   |

## Kick-the-Tires Instructions (≈ 15 min)

```bash
# 1. Build
cargo build --workspace

# 2. Run P3 on-chain benchmarks
just p3-bench

# 3. Run E2E real test
just e2e-real

# Or run all three via:
just artifact-reproduce
```

## Full Reproduction Instructions

```bash
# All gates (validates all claims):
just phase1-gate
just phase2-gate
just phase3-gate
just paper-gate

# All benchmarks:
just bench-p4
just bench-scaling
just p2-bench
just p3-bench
just e2e-real
```

## Expected Outputs

| Step | Expected Output | Evidence File |
|------|-----------------|---------------|
| `just p3-bench` | Gas ≤ 5,000,000 for accept/reject paths | `.sisyphus/evidence/p3-impl/bench.txt` |
| `just e2e-real` | All integration tests pass | `.sisyphus/evidence/p3-impl/adversarial-e2e.txt` |
| `just bench-p4` | Keygen n=128 ≤ 10ms | `.sisyphus/evidence/benchmarks/p4/run.log` |

## Limitations

- P1 simulation extractability is not proven (see §P1-SimExtractability).
- P2 uses a simulated RLWE folding backend; the real LatticeFold+ proof is a research placeholder.
- P4 Ring-LWE secrecy is deferred to a full RLWE proof (current: Shamir-only simulation).
- BB CLI and Noir are required for circuit proofs but optional for Rust-only bench.

## License

MIT. See `LICENSE`.
