# PVTHFHE Threat Model v1

> **Document version**: 1.0  
> **Date**: 2026-05-09  
> **Status**: DRAFT — reflects target Architecture B design intent; current prototype violates most properties (see audit).  
> **Sources**: [AUDIT-2026-05-08.md](../audit/AUDIT-2026-05-08.md), [assumptions-ledger.md](assumptions-ledger.md), [security-proofs.md](security-proofs.md), [proof-boundary.md](proof-boundary.md), [fold-soundness-budget.md](fold-soundness-budget.md), [noise-budget.md](noise-budget.md), [SECURITY.md](../../SECURITY.md)

---

## 1. Scope

This document defines the threat model for the **target Architecture B** of PVTHFHE (Lattice PVSS + LatticeFold+ + MicroNova + UltraHonk). The **current prototype** (commit `87fc2ef`) is a research artifact that violates nearly all properties described herein; see [AUDIT-2026-05-08.md](../audit/AUDIT-2026-05-08.md) for the per-layer finding catalogue.

### 1.1 In Scope

- Cryptographic soundness of the threshold-FHE pipeline against PPT adversaries
- DKG secrecy and correctness
- Verifiable share well-formedness (NIZK)
- Threshold decryption soundness and correctness
- On-chain verifiability with O(polylog n) verifier cost
- Session binding (replay prevention)
- Protocol liveness with honest majority

### 1.2 Out of Scope

- Side-channel / timing attacks (deferred to post-v1 hardening)
- Physical attacks on TEE enclaves
- Quantum adversaries (post-quantum security is a stretch goal, not v1 requirement)
- Economic/game-theoretic attacks on slashing
- Denial-of-service below the protocol layer

---

## 2. Adversary Model

### 2.1 Computational Power

- **Classical PPT**: Probabilistic polynomial-time adversary with classical computing resources.
- **Post-quantum**: Out of scope for v1, but primitive choice should not preclude future PQ migration. The lattice layers (P1, P2, FHE) are PQ; the pairing layers (P3, BN254) are not.

### 2.2 Corruption Model

- **Static corruption**: Adversary selects corrupted parties before protocol execution.
- **Threshold**: Up to `t-1` of `n` parties may be corrupted, where `t = ⌊n/2⌋ + 1`.
- **Honest majority**: At least `t` parties remain honest throughout.

### 2.3 Network Model

- **Active network**: Adversary can reorder, delay, or drop messages.
- **No DDoS below protocol**: Liveness assumes bounded message delays (`Δ₁`, `Δ₂` timeouts).
- **No message insertion**: Authenticated channels assumed (out-of-band PKI or on-chain registry).

### 2.4 On-Chain Model

- **Permissionless verifier**: Anyone can submit proofs to the on-chain verifier.
- **Prover may be adversarial**: The aggregator submitting final proofs may collude with corrupted parties.
- **Gas budget**: On-chain verification must fit within EVM block gas limits.

---

## 3. Security Properties (Target Design)

Derived from [AUDIT-2026-05-08.md §1.2](../audit/AUDIT-2026-05-08.md).

| ID | Property | Target Soundness | Primary Layer |
|----|----------|-----------------|---------------|
| **SEC-1** | **DKG correctness**: ≥`t` honest parties produce a valid threshold key `pk` and consistent shares `sk_i` | — (correctness, not soundness) | Rust aggregator (B) |
| **SEC-2** | **DKG secrecy**: Adversary corrupting <`t` parties learns nothing about `sk` beyond `pk` | Semantic security under RLWE | Lattice PVSS |
| **SEC-3** | **Verifiable share well-formedness**: Each share envelope is publicly verifiable as correctly formed | Soundness ≥ 2⁻¹²⁸; ZK against PPT verifier | Lattice NIZK (D) |
| **SEC-4** | **Threshold decryption correctness**: ≥`t` honest partials → correct plaintext | — (correctness) | BFV + smudging |
| **SEC-5** | **Threshold decryption soundness**: Accepted proof ⇒ ≥`t` honest partials combined correctly | Soundness ≥ 2⁻¹²⁸ | Inside SNARK (A) + Lattice NIZK (D) |
| **SEC-6** | **On-chain verifiability**: Aggregated proof verifies on EVM in O(polylog n) gas | Soundness ≥ 2⁻¹²⁸ | Solidity verifier (C) + UltraHonk |
| **SEC-7** | **Session binding**: Every accepted proof bound to `(session_id, epoch, ciphertext)`; replay impossible | Atomic consume | Rust aggregator (B) + Solidity (C) |
| **SEC-8** | **Liveness**: Honest quorum can always produce an accepted proof in bounded time | — (robustness) | Protocol timeouts + blame |

### 3.1 Current Prototype Status

| Property | Status | Blocker Findings |
|----------|--------|-----------------|
| SEC-1 (DKG correctness) | Partial (FHE backend ok) | F23, F60, F63 |
| SEC-2 (DKG secrecy) | **Violated** | F23, F20, F27, F28, F59 |
| SEC-3 (Share WF) | **Violated** | F4, F5, F8, F15, F19 |
| SEC-4 (Decrypt correctness) | Partial (FHE backend ok) | — |
| SEC-5 (Decrypt soundness) | **Violated** | F8, F9, F44, F48, F54, F55, F57, F58 |
| SEC-6 (On-chain O(polylog n)) | **Unverified** | F9, F10, F47–F50 |
| SEC-7 (Session binding) | **Violated** | F9, F11 |
| SEC-8 (Liveness) | Demo-only | F38, F41 |

---

## 4. Cryptographic Primitives

### 4.1 Primitives by Layer

| Layer | Primitive | Parameter | Assumption | PQ? |
|-------|-----------|-----------|------------|-----|
| **FHE (P0)** | BFV over `R_q` | N=8192, log₂q≈174, ternary secret | RLWE (A-LATTICE-2) | ✓ |
| **DKG Keygen** | Lattice PVSS (Hermine) over `R_q` | Threshold `t`, field `Z_p` (p=2⁶¹-1) | MLWE, PVSS-secrecy | ✓ |
| **NIZK (P1)** | Ajtai commitment + Fiat-Shamir | a=13, φ=256, norm β≤1344 | M-SIS (A-LATTICE-1) | ✓ |
| **Folding (P2)** | Cyclo / LatticeFold+ | T=10 rounds, |C|=2¹⁶, norm B̂=86,016 | M-SIS (A-LATTICE-1), Lemma 9 heuristic (A-LATTICE-4) | ✓ |
| **Compression (P3)** | MicroNova IVC + HyperKZG | BN254, state_len=5, cycles≥2 | q-SDH/KZG (A-DLOG-1), DLOG (A-DLOG-2, A-DLOG-3) | ✗ |
| **Final proof** | UltraHonk over BN254 | KZG polynomial commitment | KZG binding (A-DLOG-1), ROM (A-MODEL-1) | ✗ |
| **FS transcript** | SHA-256 / Poseidon-BN254 | — | Collision resistance (A-HASH-1, A-HASH-2) | ✓ / ✗ |
| **Smudging** | Discrete Gaussian | σ_smudge = 2⁴⁰ · σ_err (σ_err=3.19) | Smudging lemma | ✓ |

### 4.2 Full Assumption Ledger

See [`.sisyphus/design/assumptions-ledger.md`](assumptions-ledger.md) for the complete inventory of cryptographic assumptions (21 total) with status, reduction targets, and references.

---

## 5. Soundness Budgets

### 5.1 Folding Layer (P2)

| Parameter | Value | Source |
|-----------|-------|--------|
| Folding rounds (T) | 10 | PVTHFHE_CYCLO_PARAMS |
| Challenge space |C|  | 2¹⁶ = 65536 | [fold-soundness-budget.md](fold-soundness-budget.md) |
| Soundness ε_fold (exponential) | 2⁻¹⁶⁰ ≪ 2⁻¹²⁸ ✓ | |C|⁻ᵀ |
| Soundness ε_fold (linear, conservative) | 1.5×10⁻⁴ | T·|C|⁻¹ |
| Norm growth β_T | 1344 | Spec-real-p2p3 §4.3 |
| Extraction slack β̄ | 43,008 ≪ 2⁴⁹ | 2·β_T·(2γ)¹ |
| Lemma 9 heuristic κ_nu | 2⁻⁹⁴ (≥2⁻⁸⁰) | Conditional (A-LATTICE-4) |

### 5.2 BFV Noise Budget

| Regime | Noise (log₂) | Decoding Slack | Source |
|--------|-------------|----------------|--------|
| Fresh encryption | 2⁸·² | 148 bits | [noise-budget.md](noise-budget.md) |
| Per-party partial (after smudge) | 2⁴¹·⁷ | — | σ_smudge = 2⁴⁰·σ_err |
| Honest aggregate (t=512) | 2⁴⁶·² | 109.8 bits | √t growth |
| Malicious aggregate (t=512, worst-case) | 2⁵⁰·⁷ | 105.3 bits | Linear bound |
| Total headroom | — | >100 bits | ≪ Δ/2 = 2¹⁵⁶ |

### 5.3 End-to-End Soundness (Target)

| Component | Target | Approach |
|-----------|--------|----------|
| P1 NIZK well-formedness | 2⁻¹²⁸ | M-SIS binding + FS (ROM) |
| P2 Folding | 2⁻¹⁶⁰ | |C|⁻ᵀ with |C|=2¹⁶ |
| P3 IVC compression | 2⁻¹²⁸ | Nova IVC + KZG polynomial commitment |
| **Joint composition** | **≤ 2⁻¹²⁸** | Max of per-component soundness errors |

---

## 6. Enforcement Layers (Proof Boundary)

From [proof-boundary.md](proof-boundary.md) (frozen Phase 2):

| Property | Primary Layer | Status |
|----------|--------------|--------|
| PB-01: Share well-formedness | D (Lattice NIZK) | OPEN (P1) |
| PB-02: NIZK correctness | D (Lattice NIZK) | OPEN (P1) |
| PB-03: Threshold count | A (Inside SNARK) | CONDITIONAL |
| PB-04: Aggregation linearity | D (Lattice NIZK) | OPEN (P2) |
| PB-05: Noise smudging | B (Rust aggregator) | OPEN/PARTIAL |
| PB-06: Plaintext decoding | A (Inside SNARK) | CONDITIONAL |
| PB-07: Replay prevention | B (Rust aggregator) | Off-chain only |
| PB-08: Public key consistency | B (Rust aggregator) | CLOSED |
| PB-09: Blame identification | B (Rust aggregator) | CONDITIONAL (P1) |
| PB-10: Proof binding | C (Solidity) | CONDITIONAL (KZG) |
| PB-11: Calldata integrity | C (Solidity) | CLOSED |
| PB-12: Parameter consistency | C (Solidity) | CLOSED |

---

## 7. Residual Assumptions & Open Risks

### 7.1 Open Research Problems

| ID | Problem | Impact | Mitigation |
|----|---------|--------|------------|
| **P1** | Lattice NIZK well-formedness soundness for folded RLWE is not formally proven | SEC-3, SEC-5 broken; PB-01, PB-02 OPEN | Conditional on resolution of open problem |
| **P2** | LatticeFold+ over RLWE folding argument is not formally proven | SEC-5 broken; PB-04 OPEN | Conditional on resolution of open problem |
| **P3** | MicroNova-lattice-encoding soundness is an open research conjecture | PB-03, PB-06 conditional | Research conjecture; treat as gap |

### 7.2 Residual Implementation Assumptions

1. **Smudging exactness (PB-05)**: The exact distribution of smudging noise (discrete Gaussian with σ_smudge = 2⁴⁰·σ_err) is enforced by Rust code, not cryptographically proven. Bounded shortness is enforced; exact distributional correctness is an implementation assumption.

2. **Sonobe substitution (current prototype)**: The current prototype substitutes Sonobe MicroNova for the LatticeFold+ folding layer. When the real LatticeFold+ implementation ships, the soundness budget must be re-evaluated.

3. **FHE backend trust**: The `gnosisguild/fhe.rs` BFV implementation is assumed correct per upstream community review. No independent audit of the FHE library has been performed within this project.

4. **Post-quantum vs classical**: The BN254 pairing layer (P3, on-chain verifier) is NOT post-quantum secure. The lattice layers (P1, P2, FHE) are PQ. An attacker with a quantum computer could forge proofs accepted by the on-chain verifier, even if the underlying FHE ciphertexts remain secure.

5. **ROM vs QROM**: All Fiat-Shamir transforms are proven in the Random Oracle Model (ROM). Quantum Random Oracle Model (QROM) is a stretch goal, not part of the baseline claim.

6. **No production smudging in current pipeline**: Partial-decryption paths in the current prototype do not add σ_smudge (F21). The noise-budget analysis assumes this will be added in the rebuilt pipeline.

7. **Replay protection off-chain only**: Session binding (SEC-7) is enforced by the Rust aggregator, not by the on-chain verifier in the current ABI (F9/F11). An on-chain replay prevention mechanism requires ABI changes.

---

## 8. Trust Assumptions

### 8.1 Trusted Setup

| Component | Setup | Trust Model |
|-----------|-------|------------|
| KZG SRS (BN254) | One-time ceremony or transparent setup | Powers-of-Tau; assumes at least 1 honest participant |
| Ajtai commitment matrix | CRS from transparent hash-to-lattice | Transparent (if bound to epoch from chain, not prover-chosen) |
| FHE parameters | Public constants | No trust required |
| TEE attestation | Enclave root of trust | Intel SGX / AMD SEV-SNP root keys (out of scope v1) |

### 8.2 External Dependencies

| Dependency | Version | Trust Level |
|------------|---------|------------|
| `gnosisguild/fhe.rs` | rev `5f24d0b6` | Assumed correct (community-reviewed BFV) |
| `arkworks` / Sonobe folding-schemes | rev `63f2930d` | Research-grade; not audited for production |
| `bb` (Barretenberg) | 5.0.0-nightly.20260324 | Assumed correct per upstream |
| Noir compiler | 1.0.0-beta.20 | Assumed correct compilation |

---

## 9. References

| Document | Path |
|----------|------|
| Security audit (69 findings) | `.sisyphus/audit/AUDIT-2026-05-08.md` |
| Assumptions ledger | `.sisyphus/design/assumptions-ledger.md` |
| Security proofs | `.sisyphus/design/security-proofs.md` |
| Proof boundary | `.sisyphus/design/proof-boundary.md` |
| Fold soundness budget | `.sisyphus/design/fold-soundness-budget.md` |
| Noise budget | `.sisyphus/design/noise-budget.md` |
| Parameter spec | `.sisyphus/design/parameters.md` |
| Security advisory | `SECURITY-ADVISORY-001.md` |
| Production warning | `WARNING.md` |

---

*Document version*: 1.0  
*Last updated*: 2026-05-09  
*Next review*: After R2 (Cyclo rebuild) and R3 (NIZK rebuild)
