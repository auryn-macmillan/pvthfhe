# PVTHFHE Threat Model v1

> **Document version**: 1.2  
> **Date**: 2026-05-11  
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
- **Threshold convention**: FHE threshold = PVSS threshold = number of shares required for reconstruction. The parameter `t` is used consistently across all layers: PVSS shamir split requires `t` shares to reconstruct, FHE `setup_threshold(n, t)` stores `t` as the configured threshold, and `aggregate_decrypt` expects exactly `t` shares.

### 2.3 Network Model

- **Active network**: Adversary can reorder, delay, or drop messages.
- **No DDoS below protocol**: Liveness assumes bounded message delays (`Δ₁`, `Δ₂` timeouts).
- **No message insertion**: Authenticated channels assumed (out-of-band PKI or on-chain registry).

### 2.4 On-Chain Model

- **Permissionless verifier**: Anyone can submit proofs to the on-chain verifier.
- **Prover may be adversarial**: The aggregator submitting final proofs may collude with corrupted parties.
  - **Gas budget**: On-chain verification must fit within EVM block gas limits.

### 2.5 Smudging-Noise Specific Threats

The smudging-noise subsystem presents distinct attack surfaces beyond general protocol corruption. These threats arise when a party or aggregator deviates from the committed, shared, and publicly verified smudging-noise material prescribed by the DKG transcript. The following cases are in scope for the Interfold-equivalent PVSS upgrade (plan `interfold-equivalent-pvss`, Batch A.2).

**Case S1: Fresh uncommitted smudging noise.** A decrypting party samples fresh local smudging noise instead of using the committed `e_sm` share produced during DKG. Without the commitment chain, the smudging-noise term is unprovable and the threshold-decryption proof's claim that the partial decryption uses honestly-committed material is falsified. The adversary can trivially supply an unbounded error term to mask a malicious decryption share while claiming honest computation.

*Target accepted behavior:* The decryption-share proof (primary layer D, lattice NIZK) must bind the claimed noise term to a committed `e_sm` share whose commitment is present in the DKG transcript root. Fresh local smudging is rejected at proof-verification time unless run in an explicit legacy/non-equivalent mode. This is enforced by Batch F (committed-smudge decryption relation) of the Interfold-equivalent PVSS plan.

**Case S2: Smudge-slot reuse.** A party reuses the same `e_sm` slot for two distinct ciphertexts or decrypt rounds. Reusing a smudging-noise share creates correlated observations that weaken the LWE-based hiding guarantee, since an adversary sees multiple `(c1, c1·sk_i + e_sm_i)` samples with identical error. Under repeated reuse, the error term can be averaged away, progressively exposing `sk_i`.

*Target accepted behavior:* The session registry (primary layer B, Rust aggregator) must enforce one-time-use semantics for each `(session_id, party_id, slot_id)` tuple. A reused slot causes the decryption share to be rejected before proof generation. This is enforced by Batch C (smudge-slot policy) and Batch F (freshness check) of the Interfold-equivalent PVSS plan.

**Case S3: Cross-session e_sm substitution.** An adversary imports `e_sm` commitments from a different DKG session or attempts to bind an `e_sm` share produced for ciphertext A to a decryption statement for ciphertext B. The commitment appears well-formed in isolation but does not belong to the current session's transcript. The proof verifies locally but resolves to the wrong underlying key material.

*Target accepted behavior:* The decryption proof statement must include or derive the current session's DKG root, and the `e_sm` commitment must be verifiable as a member of that specific DKG transcript. The verifier (primary layer B, Rust aggregator, with public-verifier enforcement at layer C, Solidity) checks DKG root equality between the decryption statement and the stored session anchor. This is enforced by Batch C (transcript root binding) and Batch H (anchor linkage) of the Interfold-equivalent PVSS plan.

**Case S4: DKG anchor cross-session mixing by aggregator.** The aggregator provides a valid-looking decryption proof whose claimed DKG root does not match the session's actual DKG transcript. The proof may be internally consistent (well-formed shares, valid NIZKs, correct aggregation) but is bound to the wrong key material, allowing an aggregator to substitute a weaker or corrupted DKG transcript while presenting a proof that verifies against a different root.

*Target accepted behavior:* The public verifier (primary layer C, Solidity) must reject proofs where the `dkg_root` public input of the decryption proof does not equal the registered DKG root for the claimed session. The aggregator (layer B) also rejects such mismatches during pre-submission checks as secondary defense. This is enforced by Batch H (verifier anchor checks) of the Interfold-equivalent PVSS plan.

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
| SEC-PB-SMUDGE-1 (Committed smudge binding) | **Missing** | Interfold-equivalent PVSS plan Batch F |
| SEC-PB-SMUDGE-2 (Smudge slot freshness) | **Missing** | Interfold-equivalent PVSS plan Batch C |

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
| **P1** | Lattice NIZK well-formedness soundness for folded RLWE is not formally proven | SEC-3, SEC-5 broken; PB-01, PB-02 OPEN | Conditional on resolution of open problem. Sigma masking seeds now fresh per proof (OsRng, non-deterministic; deep-audit Batch A.1 fix). Joint extractor proof (T2) remains a skeleton. D.1 BFV encryption verifier relation still blocked (C3 structural gap — algebraic sigma proves hash-preimage, not BFV encryption structure). |
| **P2** | LatticeFold+ over RLWE folding argument is not formally proven (Lemma 9 heuristic) | SEC-5 broken; PB-04 OPEN | Conditional on resolution of Lemma 9 invertibility heuristic. Challenge space locked at \|C\|=2^16 with T=10 rounds, giving ε_fold ≤ 2^(-160) exponential bound from |C|^(-T). The linear (conservative) bound is 1.5×10^(-4). Nova Nova currently substitutes for lattice-native folding. |
| **P3** | MicroNova-lattice-encoding soundness is an open research conjecture | PB-03, PB-06 conditional | Research conjecture; treat as gap. Nova Nova IVC (CycloFoldStepCircuit) folds 3 hashed field elements (commitment_hash, norm, fold_count) via SHA-256 digest of Cyclo accumulator state — not full Ajtai commitment folding, range-check, or sum-check over raw R_{q_commit} elements. |

### 7.2 Residual Implementation Assumptions

1. **Smudging exactness (PB-05)**: The exact distribution of smudging noise (discrete Gaussian with σ_smudge = 2⁴⁰·σ_err) is enforced by Rust code, not cryptographically proven. Bounded shortness is enforced; exact distributional correctness is an implementation assumption.

2. **Nova substitution (current prototype)**: The current prototype substitutes Nova MicroNova for the LatticeFold+ folding layer. When the real LatticeFold+ implementation ships, the soundness budget must be re-evaluated.

3. **FHE backend trust**: The `gnosisguild/fhe.rs` BFV implementation is assumed correct per upstream community review. No independent audit of the FHE library has been performed within this project.

4. **Post-quantum vs classical**: The BN254 pairing layer (P3, on-chain verifier) is NOT post-quantum secure. The lattice layers (P1, P2, FHE) are PQ. An attacker with a quantum computer could forge proofs accepted by the on-chain verifier, even if the underlying FHE ciphertexts remain secure.

5. **ROM vs QROM**: All Fiat-Shamir transforms are proven in the Random Oracle Model (ROM). Quantum Random Oracle Model (QROM) is a stretch goal, not part of the baseline claim.

6. **No production smudging in current pipeline**: Partial-decryption paths in the current prototype do not add σ_smudge (F21). The noise-budget analysis assumes this will be added in the rebuilt pipeline.

7. **Replay protection off-chain only**: Session binding (SEC-7) is enforced by the Rust aggregator, not by the on-chain verifier in the current ABI (F9/F11). An on-chain replay prevention mechanism requires ABI changes.

8. **Logging hygiene**: FHE encode/decode and aggregate-decrypt slot logging (`eprintln!` statements in `fhers.rs`) is gated behind the Cargo feature `trace-decrypt` (off by default). All plaintext-slot content is restricted to this trace feature, which is intended for debugging only and must never be enabled in production builds or in any environment where plaintext confidentiality is required. See `SECURITY.md` for the full logging hygiene policy.

9. **Memory hygiene (`Secret<T>` + `ZeroizeOnDrop`)**: All secret witness fields in the PVSS crate are wrapped in `Secret<T>` (from the `secrecy` crate via `pvthfhe_types`) or the crate-local `ShareSecret` wrapper, which suppresses `Debug`/`Display` output to prevent accidental leakage of secret key material to logs, panic messages, or serialized trace output. Additionally, `FhersBackend::PartyState` (which holds aggregated Shamir secret-key shares) derives `Zeroize` + `ZeroizeOnDrop` to ensure key material is zeroed from memory on deallocation. Enforcement points:
   - `nizk_decrypt.rs`: `secret_key_bytes: Secret<Vec<u8>>`, `decryption_noise: Secret<Vec<u8>>`
   - `nizk_share.rs`, `encrypt.rs`, `lib.rs`: `share_bytes: ShareSecret` (opaque wrapper)
   - `fhers.rs`: `PartyState` derives `Zeroize, ZeroizeOnDrop`
   - All `Debug` implementations for witness structs are manually implemented to print `***SECRET***`

10. **Sigma ZK masking seeds fresh per proof**: As of the deep-audit remediation (Batch A.1), both the algebraic sigma proof (`build_algebraic_proof` in `nizk_share.rs`) and the BFV encryption sigma proof (`build_bfv_encryption_proof` in `nizk_share.rs`) use fresh, non-deterministic randomness seeded from `OsRng` (`ChaCha20Rng::from_rng(&mut OsRng)`) for each proof generation call. The previous hardcoded/commented-out fixed seeds have been removed. This is critical for zero-knowledge: reusing masking randomness across proofs breaks the sigma protocol's honest-verifier ZK property (soundness is unaffected). Verification: `nizk_share.rs` lines 413 and 668 — both proof-rng instances use `ChaCha20Rng::from_rng(&mut OsRng)`.

11. **Aggregate key consistency (PB-08 enforcement)**: The DKG transcript's aggregate public key MUST equal the FHE backend's aggregate key used for encryption. After keygen, the aggregator recomputes `pk_agg = Σ pk_i` over the accepted participant set and asserts equality with the FHE backend's stored aggregate key. A mismatch aborts the pipeline before any decryption share is processed. This prevents an adversary from substituting a weaker or corrupted key while presenting a compatible DKG transcript. Enforced in `full_pipeline.rs` via the `aggregate_pk` consistency assertion (deep-audit remediation Batch A.3). Primary enforcement layer: B (Rust aggregator), per `proof-boundary.md` PB-08.

12. **Encryption correctness is trusted (C2 gap)**: `backend.encrypt()` at pipeline step 3 produces a ciphertext, but there is no verifiable proof that the ciphertext faithfully encrypts the claimed plaintext under the aggregate public key. The encryption step is trusted; a malicious encryptor can produce a well-formed but semantically incorrect ciphertext. Mitigation: the semantic roundtrip check (step 9, `verify_plaintext_roundtrip`) detects plaintext mismatches at the aggregate level, but cannot identify which party or which step introduced the corruption. A fully verifiable encryption step would require a NIZK proving `ct = Enc(pk_agg, pt)` without revealing the plaintext, which is an open design problem. See `interfold-equivalence.md` §C2 and `SECURITY.md` §Known Limitations for tracking.

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
| `arkworks` / Nova folding-schemes | rev `63f2930d` | Research-grade; not audited for production |
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

*Document version*: 1.2  
*Last updated*: 2026-05-12  
*Next review*: After R2 (Cyclo rebuild) and R3 (NIZK rebuild)
