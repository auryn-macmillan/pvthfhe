# PVTHFHE: Private-Verifiable Threshold FHE

> ⚠️ **RESEARCH PROTOTYPE — NOT PRODUCTION-READY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE.
> Two security audits (2026-05-08: 70 findings; 2026-05-09: 188 findings) have been
> completed and all automatable findings have been remediated. Three open cryptographic
> problems remain (see §Open Problems). The end-to-end pipeline is **not** a formally
> verified cryptographic artifact and has **not** undergone adversarial dress rehearsal.
>
> See [SECURITY.md](SECURITY.md), [WARNING.md](WARNING.md), and
> [`.sisyphus/audit/AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md) for details.

Research prototype for private-verifiable threshold Fully Homomorphic Encryption (FHE).

## Intent

PVTHFHE targets private-verifiable threshold FHE with O(n) per-party work and O(polylog n)
verifier cost. The current prototype uses:

| Layer | Implementation | Status |
|-------|---------------|--------|
| DKG | Pedersen-DKG over BFV/RLWE secret domain (`.sisyphus/design/dkg-construction.md`) | ✅ Real (BN254 Shamir, OsRng, smudging) |
| NIZK | Cyclo-companion Ajtai D2 sigma + BFV sigma (conditional, P1 OPEN) | ⚠️ Real with conditional soundness |
| Folding (P2) | Sonobe Nova with Cyclo CCS witness representation (`.sisyphus/design/fold-construction.md`) | ✅ Real (CCS satisfiability, ∞-norm) |
| Compression (P3) | Sonobe Nova IVC with CycloFoldStepCircuit | ✅ Real (commitment folding, norm escalation) |
| On-chain verifier | OpenZeppelin AccessControl + TimelockController | ✅ Real (AccessControl, multisig, runId) |
| Decrypt (smudge) | `legacy_local_smudge` (non-equivalent) vs `committed_smudge_pvss` (target committed mode) | ✅ Doc split (F.3) |

## Audit Status

**Two audits completed. All automatable findings remediated.**

| Layer | Post-Remediation Status |
|-------|--------------------------|
| FHE backend (BFV via fhe.rs) | ✅ Real lattice crypto; `Secrecy<T>` + `Zeroize` on keys † |
| DKG / Shamir resharing | ✅ Pedersen-DKG over BFV; BN254 Shamir; OsRng reshare |
| PVSS encryption | ✅ BN254 scalar Shamir; OsRng encryption randomness |
| Lattice NIZK well-formedness | ✅ Witness-free proofs; D2-preimage binding; CRS-bound Ajtai |
| Cyclo folding (RLWE fold) | ✅ Real ∞-norm; CCS satisfiability; \|C\|=2¹⁶ challenge space |
| Aggregator folding | ✅ CCS-based fold; single canonical path |
| Nova compression (Sonobe) | ✅ CycloFoldStepCircuit; epoch-bound SRS |
| On-chain verifier (Solidity) | ✅ AccessControl (3 roles); multisig (≥2/3 + 48h); runId liveness |
| End-to-end pipeline | ✅ Fold binding; atomic plaintext; semantic roundtrip verified |

† FHE backend assumes honest-but-curious threshold parties (see SECURITY.md §Threat Model).

**Remediation plans**: `.sisyphus/plans/pvthfhe-remediation.md` (179/179 ✅) and
`.sisyphus/plans/audit-2026-05-09-remediation.md` (55/55 ✅). All gate-level checkboxes
are closed under `.sisyphus/plans/pvthfhe-gate-resolution.md`.

## Soundness Budget

| Parameter | Value | Source |
|-----------|-------|--------|
| Folding soundness (ε_fold) | 2⁻¹⁶⁰ (exponential bound, 10 rounds, 2¹⁶ challenges) (aspirational — depends on P1, P2, P3 resolution) | `.sisyphus/design/fold-soundness-budget.md` |
| DKG secrecy | ≤ 2⁻¹²⁸ (t−1 shares indistinguishable from uniform) | `pvthfhe-keygen/tests/dkg_secrecy.rs` |
| Composed soundness | R1.5 ⊕ R2.4 ⊕ R3.1+R3.2 ⊕ R4.4 ⊕ R5.2 ⊕ R6.1 ⊕ R8.5 ≥ 2⁻¹²⁸ (aspirational — depends on P1, P2, P3 resolution) | Plan gate-level verification |
| BFV parameters | n=8192, log₂q=174, σ_smudge=2⁴⁰·σ_err | `.sisyphus/design/smudging.md` |

### Open Problems

| ID | Problem | Status |
|----|---------|--------|
| P1 | Lattice NIZK well-formedness soundness (Greco M-SIS reduction for BFV) | **OPEN** |
| P2 | Lattice folding over RLWE (LatticeFold+/Cyclo Lemma 9) | **OPEN** (Sonobe substitute) |
| P3 | Parametrized Sonobe step circuit verification (same ext-scaling) | **OPEN** (documented limitation) |

## Threat Model

See [`.sisyphus/design/threat-model-v1.md`](.sisyphus/design/threat-model-v1.md) for:
- Adversary model (PPT, active network, ≤ t−1 corrupted parties)
- 8 required security properties for Interfold core component
- Residual assumptions and open risks

## Status: Research Prototype

- **NOT a formally verified cryptographic artifact.**
- **NOT battle-tested** (no adversarial dress rehearsal).
- **FHE backend**: Real `gnosisguild/fhe.rs` BFV library. Parameters are production-grade but have not undergone independent parameter review.
- Folding uses **Sonobe Nova** as a substitute for lattice-native folding (P2). Soundness budget assumes Sonobe soundness over BN254+grumpkin cycle.
- **Stage 0 Build-time Tripwire**: Release builds require `PVTHFHE_ALLOW_RESEARCH_BUILD=1`. See `SECURITY.md`.
- **Benchmarks**: Need re-running against the rebuilt pipeline. See `bench/results/`.

## Quickstart

### Dependencies

- **Rust**: 1.95.0
- **Foundry**: 1.6.0–1.7.0
- **Noir**: 1.0.0-beta.20
- **BB CLI**: 5.0.0-nightly.20260324
- **Just**: casey/just

### Local Setup

```bash
git clone https://github.com/auryn-macmillan/pvthfhe
cd pvthfhe

# Build (research mode)
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build

# Run the end-to-end demo (defaults: n=10, t=4, seed=1)
just demo-e2e
```

The demo exercises the current threshold-FHE pipeline end-to-end using real cryptographic
primitives. **The NIZK witness uses real BFV secret key material. The folding path uses real
CCS satisfiability. The compressor uses real Sonobe Nova IVC.** See `WARNING.md` for
known limitations.

## Key Commands

- `just demo-e2e`: End-to-end demo (n=10, t=4; all 9 steps with real crypto).
- `just test-all`: Full test suite across Rust, Noir, and Solidity.
- `just bench-scaling`: Scaling benchmarks (n=128 to 1024).

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): System design and protocol details.
- [SECURITY.md](SECURITY.md): Threat model, assumptions, and limitations.
- [REPRODUCING.md](REPRODUCING.md): Detailed steps for reproducing benchmarks.
- [WARNING.md](WARNING.md): Known cryptographic surrogates and their status.
- [`.sisyphus/audit/AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md): First audit (70 findings).
- [`.sisyphus/audit/AUDIT-2026-05-09.md`](.sisyphus/audit/AUDIT-2026-05-09.md): Second audit (188 findings).
- [`.sisyphus/design/threat-model-v1.md`](.sisyphus/design/threat-model-v1.md): Formal threat model and soundness budget.
- [`.sisyphus/design/`](.sisyphus/design/): Design documents (DKG, folding, NIZK, smudging, parameter freeze).

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
