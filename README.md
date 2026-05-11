# PVTHFHE: Private-Verifiable Threshold FHE

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE.
> An external security audit (2026-05-08) found **69 findings** (26 CRITICAL, 28 HIGH)
> across all layers. The end-to-end pipeline is **not** a sound cryptographic artifact.
> **Do not use for The Interfold or any production deployment.**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [SECURITY.md](SECURITY.md),
> [WARNING.md](WARNING.md), and [`.sisyphus/audit/AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md) for details.

Research prototype for private-verifiable threshold Fully Homomorphic Encryption (FHE).

## Intent

PVTHFHE targets private-verifiable threshold FHE with $O(n)$ per-party work and $O(\text{polylog } n)$ verifier cost. Architecture B (Lattice PVSS + LatticeFold+ + MicroNova + UltraHonk) is the target design. The current prototype uses Sonobe as a substitute for the folding (P2) and compression (P3) layers.

## Audit Status

**Skeptical audit completed 2026-05-08.** Verdict: **NOT SUITABLE FOR PRODUCTION OR EXTERNAL DISTRIBUTION.**

| Layer                          | Status                | Headline finding |
|--------------------------------|-----------------------|------------------|
| FHE backend (BFV via fhe.rs)   | Honest-but-curious only | Reshare RNG seeded by `party_id` (F23 CRIT) |
| DKG / Shamir resharing         | **BROKEN**            | Production `KeygenAdapter` derives all coefficients from public-SHA (F60 CRIT) |
| PVSS encryption                | **BROKEN**            | GF(256) Shamir + deterministic randomness (F20/F27/F28) |
| Lattice NIZK well-formedness   | **BROKEN**            | Proof envelope leaks witness (F4); secret from public statement (F5) |
| Cyclo folding (RLWE fold)      | **BROKEN**            | Witness norm = `bytes.iter().max()` (F1); challenge ∈ {−1,0,1} → 2⁻¹⁵·⁸ soundness (F2) |
| Aggregator folding scheme      | **BROKEN**            | `HashChainFoldingScheme` is SHA chain (F44); witness validator accepts `[a,a,a,…]` (F45) |
| Nova compression (Sonobe)      | **MISDIRECTED**       | Genuine Nova IVC over `ToyStepCircuit { z+ext }` (F48–F50) |
| On-chain verifier (Solidity)   | **BROKEN**            | Verify path skips session check (F9); missing import (F10); tautology tests (F17) |
| End-to-end pipeline binding    | **DECOUPLED**         | Plaintext recovery bypasses proof system (F57) |

**Full audit report**: [`.sisyphus/audit/AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md)

## Soundness Budget (Target Design)

The target design (Architecture B) targets the following soundness parameters:

| Parameter | Value | Source |
|-----------|-------|--------|
| Folding soundness (ε_fold) | 2⁻¹⁶⁰ (exponential bound) | `.sisyphus/design/fold-soundness-budget.md` |
| Folding rounds (T) | 10 | Cyclo parameters |
| Challenge space |C|  | 2¹⁶ = 65536 | Constant subring Z_q ⊂ R_q |
| Overall protocol soundness | ≤ 2⁻¹²⁸ target | `proof-boundary.md` |
| Noise budget (honest) | 2⁴⁶·² → 109.8 bits decoding slack | `.sisyphus/design/noise-budget.md` |
| Noise budget (malicious) | 2⁵⁰·⁷ → 105.3 bits decoding slack | `.sisyphus/design/noise-budget.md` |

**Current prototype soundness**: Effectively 0 across all layers. See audit §3.2 "Composed soundness."

### Open Problems

| ID | Problem | Status |
|----|---------|--------|
| P1 | Lattice NIZK well-formedness soundness for folded RLWE | **OPEN** |
| P2 | LatticeFold+ over RLWE folding argument | **OPEN** |
| P3 | MicroNova-lattice-encoding soundness | **OPEN** (research conjecture) |

## Threat Model

See [`.sisyphus/design/threat-model-v1.md`](.sisyphus/design/threat-model-v1.md) for:
- Adversary model (PPT, active network, ≤ t−1 corrupted parties)
- Required security properties (8 properties for Interfold core component)
- Residual assumptions and open risks

## Status: Research Prototype

**Warning: This is a research prototype.**

- **NOT production-ready.**
- **NOT battle-tested.**
- **FHE backend**: ⚠️ real library (`gnosisguild/fhe.rs`) but unproven in the context of this pipeline.
- **Open Problem P1**: Lattice NIZK well-formedness soundness is not formally proven.
- **Open Problem P2**: LatticeFold+ over RLWE folding argument is not formally proven.
- **Stage 0 Build-time Tripwire**: Release builds fail without explicit opt-in (see `SECURITY.md`).
- **Benchmarks**: All pre-rebuild benchmark numbers measure the stub/surrogate pipeline (SHA chains, toy circuits), not the target protocol. See `bench/results/comparison-5d7853a.md` and audit finding INFO-1.

## Quickstart

### Dependencies

- **Rust**: 1.95.0
- **Foundry**: 1.6.0–1.7.0
- **Noir**: 1.0.0-beta.20
- **BB CLI**: 5.0.0-nightly.20260324
- **Just**: casey/just

### Local Setup

```bash
# Clone the repository
git clone https://github.com/example/pvthfhe
cd pvthfhe

# Build (research mode — requires opt-in)
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build

# Run the end-to-end demo (defaults: n=8, t=5, seed=1)
just demo-e2e
```

The demo exercises the current threshold-FHE pipeline end-to-end; **see `SECURITY.md` and `WARNING.md` for the precise list of cryptographic surrogates and what is and is not real.**

### Docker Quickstart

```bash
docker build -f Dockerfile.quickstart -t pvthfhe-quickstart .
docker run --rm pvthfhe-quickstart
```

## Key Commands

- `just demo-e2e`: Run end-to-end demo (n=8, t=5; current pipeline, no on-chain step) (supported range: n ≤ 255).
- `just test-all`: Run full test suite across Rust, Noir, and Solidity.
- `just bench-scaling`: Run scaling benchmarks for n=128 to 1024.
- `just verify-onchain`: Verify the aggregated proof on a local EVM.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): System design and protocol details.
- [SECURITY.md](SECURITY.md): Threat model, assumptions, and limitations.
- [REPRODUCING.md](REPRODUCING.md): Detailed steps for reproducing benchmarks.
- [`AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md): Full security audit report (69 findings).
- [`threat-model-v1.md`](.sisyphus/design/threat-model-v1.md): Formal threat model and soundness budget.
- [Design Docs](.sisyphus/design/): Detailed specifications and research notes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
