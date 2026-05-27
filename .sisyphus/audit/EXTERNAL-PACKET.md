# PVTHFHE External Audit Packet

> **Bundle version**: v1  
> **Date**: 2026-05-09  
> **Repository state**: `87fc2ef` (audited baseline)  
> **Purpose**: Single-entry document for external auditors, security reviewers, and diligence teams evaluating the PVTHFHE cryptographic system.

---

## Executive Summary

PVTHFHE is a research prototype for **private-verifiable threshold Fully Homomorphic Encryption (FHE)**. The target design (Architecture B) uses Lattice PVSS + LatticeFold+ + MicroNova + UltraHonk to achieve O(n) per-party work with O(polylog n) verifier cost.

An internal skeptical audit (2026-05-08) catalogued **69 findings** (26 CRITICAL, 28 HIGH) across all layers. The end-to-end pipeline does not constitute a sound cryptographic artifact. Every layer — DKG, lattice NIZK, PVSS, RLWE fold, Nova compression, on-chain verifier, decrypt aggregation — contains at least one CRITICAL exploit or proves a statement unrelated to the protocol's security claim.

**Verdict**: NOT SUITABLE FOR PRODUCTION OR EXTERNAL DISTRIBUTION in current state.

**Path forward**: A burn-and-rebuild remediation plan targets ~6 calendar months with 3 senior cryptography engineers. The external-audit packet is the starting point for that rebuild.

---

## Document Bundle

### Core Security Documents

| Document | Path | Description |
|----------|------|-------------|
| **Audit Report** | [`AUDIT-2026-05-08.md`](AUDIT-2026-05-08.md) | Full 69-finding security audit with per-layer breakdown, exploit descriptions, code citations, and remediation references. **Start here.** |
| **Threat Model v1** | [`../design/threat-model-v1.md`](../design/threat-model-v1.md) | Adversary model, security properties (8), soundness budgets, enforcement layers, residual assumptions. |
| **Assumptions Ledger** | [`../design/assumptions-ledger.md`](../design/assumptions-ledger.md) | Complete inventory of 21 cryptographic assumptions with status (ASSUMED/REDUCED/PROVED/CONDITIONAL/TABLED), reduction targets, and references. |
| **Security Proofs** | [`../design/security-proofs.md`](../design/security-proofs.md) | Formal statements and reduction sketches for T-IND-CPA, T-DEC-SOUND, T-PV-SOUND, T-ROBUSTNESS. |
| **Proof Boundary** | [`../design/proof-boundary.md`](../design/proof-boundary.md) | Frozen assignment of 12 security properties to enforcement layers (Lattice NIZK / Rust / SNARK / Solidity). |

### Design Specifications

| Document | Path | Description |
|----------|------|-------------|
| **Key Generation** | [`../design/spec-keygen.md`](../design/spec-keygen.md) | 3-round PVSS DKG protocol with blame matrix. |
| **Decryption** | [`../design/spec-decrypt.md`](../design/spec-decrypt.md) | Threshold decryption, partial-decrypt NIZK, aggregation, on-chain verifier. |
| **PVSS Protocol** | [`../design/spec-pvss.md`](../design/spec-pvss.md) | Lattice PVSS construction details. |
| **Folding Construction** | [`../design/fold-construction.md`](../design/fold-construction.md) | Cyclo/LatticeFold+ folding with CCS encoder, norm growth, challenge sampling. |
| **NIZK Construction** | [`../design/nizk-construction.md`](../design/nizk-construction.md) | Ajtai commitment + Fiat-Shamir NIZK for share well-formedness. |
| **Real P2+P3 Freeze** | [`../design/spec-real-p2p3.md`](../design/spec-real-p2p3.md) | Joint design freeze for Cyclo P2 and MicroNova P3 layers. |

### Soundness Budgets

| Document | Path | Content |
|----------|------|---------|
| **Fold Soundness** | [`../design/fold-soundness-budget.md`](../design/fold-soundness-budget.md) | Challenge space derivation (|C|=2¹⁶ for T=10, ε=2⁻¹⁶⁰), FS implementation, comparison with Nova. |
| **Noise Budget** | [`../design/noise-budget.md`](../design/noise-budget.md) | BFV noise analysis: honest case (2⁴⁶·², 109.8 bits slack), malicious case (2⁵⁰·⁷, 105.3 bits slack). |
| **Parameters** | [`../design/parameters.md`](../design/parameters.md) | Concrete parameters: N=8192, log₂q≈174, t_plain=2¹⁷, threshold t=⌊n/2⌋+1. |

### Benchmarks

| Artifact | Path | Notes |
|----------|------|-------|
| **Comparison Report** | [`../../bench/results/comparison-5d7853a.md`](../../bench/results/comparison-5d7853a.md) | PVTHFHE vs Interfold trBFV side-by-side. ⚠️ Measures stub/surrogate pipeline, not target protocol. |
| **Reproducing Guide** | [`../../REPRODUCING.md`](../../REPRODUCING.md) | Toolchain pins, hardware fingerprint, scaling methodology. |
| **Scaling results** | [`../../bench/results/scaling-n128.json`](../../bench/results/scaling-n128.json) through `scaling-n1024.json` | n=128..1024 benchmark runs. ⚠️ Preliminary only. |

### Codebase Map

| Layer | Crates | Circuits | Contracts |
|-------|--------|----------|-----------|
| **FHE backend** | `pvthfhe-fhe` (wraps `gnosisguild/fhe.rs`) | — | — |
| **DKG / Keygen** | `pvthfhe-keygen`, `pvthfhe-pvss` | — | — |
| **NIZK (P1)** | `pvthfhe-nizk` | `circuits/share_wf/` | — |
| **Folding (P2)** | `pvthfhe-cyclo`, `pvthfhe-aggregator` | — | — |
| **Compression (P3)** | `pvthfhe-compressor` (Nova), `pvthfhe-micronova` | `circuits/nova_state_commitment/` | — |
| **Verifier (P3)** | `pvthfhe-offchain-verifier` | `circuits/aggregator_final/`, `circuits/decrypt_share/` | `contracts/src/PvtFheVerifier.sol` |
| **Pipeline** | `pvthfhe-cli`, `pvthfhe-bench` | — | — |

---

## Quick-Start for Auditors

### 1. Read the Audit Report First

[`AUDIT-2026-05-08.md`](AUDIT-2026-05-08.md) is the authoritative catalogue of current vulnerabilities. Key sections:

- **§0.2**: One-line summary per layer (what is broken)
- **§0.3**: What is correct (do not regress these 12 items)
- **§1.3**: Property-status matrix (7 of 8 properties violated)
- **§2**: 69 detailed findings with code citations and exploits
- **§3**: Composed soundness reduction (effectively 0)
- **§5**: Recommendations (do not distribute; burn-and-rebuild)

### 2. Review the Threat Model

[`../design/threat-model-v1.md`](../design/threat-model-v1.md) defines:

- Adversary model (PPT, static corruption ≤ t−1, active network)
- 8 target security properties
- Soundness budgets per layer (P1: 2⁻¹²⁸, P2: 2⁻¹⁶⁰, P3: 2⁻¹²⁸)
- Enforcement layer per property (proof boundary)
- Open problems (P1: NIZK well-formedness, P2: LatticeFold+ RLWE, P3: MicroNova encoding)
- Residual assumptions (smudging, ROM, Nova substitution, FHE backend trust)

### 3. Verify the Assumptions

[`../design/assumptions-ledger.md`](../design/assumptions-ledger.md) enumerates 21 cryptographic assumptions. Verify that:

- No assumption is stronger than claimed
- No reduction gap exceeds 2⁻¹²⁸
- Conditional assumptions have documented caveats
- All PROVED claims have cited proof content

### 4. Examine Code

The codebase is organized as a Rust workspace (`crates/`), Noir workspace (`circuits/`), and Foundry project (`contracts/`). Build with:

```bash
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build
(cd circuits && nargo compile)
forge build --root contracts
```

### 5. Run Benchmarks

```bash
just bench-comparison-gate   # Lint: policy invariants + bench tests pass
just bench-comparison        # Full comparison run (3x e2e + render)
just bench-scaling           # Scaling from n=128 to n=1024
```

⚠️ **All current benchmark numbers measure the stub pipeline** (SHA chains, toy circuits). The target Architecture B performance is estimated to be higher by 1–3 orders of magnitude depending on layer.

---

## Key Cryptographic Parameters

| Parameter | Value | Layer |
|-----------|-------|-------|
| Ring dimension N | 8192 | FHE, Cyclo |
| Ciphertext modulus log₂q | 174 (3 RNS limbs) | FHE |
| Plaintext modulus t_plain | 2¹⁷ = 131072 | FHE |
| Secret distribution | Ternary {−1,0,1} | FHE, Cyclo |
| Smudging noise σ_smudge | 2⁴⁰ · σ_err (σ_err=3.19) | P1/P2 |
| Cyclo rank a | 13 | P2 |
| Cyclo φ_commit | 256 | P2 |
| Folding rounds T | 10 | P2 |
| Challenge space |C|  | 2¹⁶ = 65536 | P2 |
| Norm bound β | 1344 (after T folds) | P2 |
| Curve (on-chain) | BN254 | P3 |
| Threshold t | ⌊n/2⌋ + 1 | Protocol |

---

## Summary of Critical Open Items for External Review

1. **P1 — Lattice NIZK well-formedness**: The soundness of per-share well-formedness proofs over RLWE relations is not formally proven. This is the single most impactful gap.

2. **P2 — LatticeFold+ over RLWE**: The folding argument's soundness when instantiated over polynomial rings (rather than fields) is not proven. Cyclo ePrint 2026/359 suggests the approach but does not provide a complete proof for the required rank/ring combination.

3. **P3 — MicroNova lattice encoding**: The correctness of the accumulator-to-SNARK encoding (mapping lattice accumulator state to SNARK witness) is a research conjecture, not a proven theorem.

4. **Nova substitution**: The current prototype uses Nova (field-based Nova) as a substitute for LatticeFold+. The migration boundary and soundness implications of this substitution are documented but not formally analyzed.

5. **On-chain verifier vacuity**: `P3RealVerifier.sol` is an ECDSA authenticator, not a cryptographic verifier of FHE computation. The target design's on-chain verifier is not implemented.

6. **DKG secrecy**: The production `KeygenAdapter` derives all secret material from public-SHA (F60). This is a total break of DKG secrecy, independent of all other findings.

7. **End-to-end decoupling**: The proof system and plaintext recovery are independent code paths (F56, F57). Plaintext correctness is not bound to proof validity.

---

## Contact / Process

This packet is designed to be self-contained for an external audit engagement. All referenced paths are relative to the repository root.

- **Auditor identity** (internal): Prometheus (deep-research/planning agent)
- **Audit date**: 2026-05-08
- **Repository**: `https://github.com/example/pvthfhe` (commit `87fc2ef`)
- **Remediation plan**: See `REMEDIATION-PLAN.md` (if present) or contact the project maintainers

For questions about any finding, cross-reference the finding ID (e.g., F23, F60) with the audit report's detailed finding catalogue (§2) and Appendix A (finding cross-reference table).

---

*Packet version*: 1.0  
*Last updated*: 2026-05-09
