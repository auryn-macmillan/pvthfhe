# PVTHFHE Parameter Freeze — v1

**Status:** FROZEN  
**Date:** 2026-05-09  
**Scope:** Concrete cryptographic parameters for Architecture B (threshold BFV + Cyclo folding + MicroNova + UltraHonk).  
**Authority:** This freeze supersedes all prior ad-hoc parameter defaults. All downstream implementation, noise-budget analysis, SRS generation, and NIZK construction MUST reference this document.

---

## 1. BFV Parameters (RLWE Ring)

**Source:** `.sisyphus/design/parameters.toml` ([rlwe] table, lines 1–12); `.sisyphus/design/parameters.md` (line 15–25).

| Parameter | Value | Notes |
|-----------|-------|-------|
| Ring dimension `n` | 8192 | Cyclotomic ring `R_q = Z[X]/(X^{8192} + 1) mod q` |
| Ciphertext modulus `log₂ Q` | 174 | `Q = q₀ · q₁ · q₂` |
| Plaintext modulus `t` | 65536 (2¹⁶) | BFV plaintext space |
| RNS limbs `L` | 3 | |
| `q₀` | 288230376173076481 | 58-bit NTT-friendly (`≡ 1 mod 16384`) |
| `q₁` | 288230376167047169 | 58-bit NTT-friendly (`≡ 1 mod 16384`) |
| `q₂` | 288230376161280001 | 58-bit NTT-friendly (`≡ 1 mod 16384`) |
| Secret distribution `χ_key` | Uniform ternary `{−1, 0, 1}` | Keygen-share secret coefficients |
| Error distribution `χ_err` | Discrete Gaussian, `σ = 3.19` | Encryption + keygen error model |
| Security target | ≥128 classical / ≥128 PQ | Per Enclave secure BFV preset |

**NTT/RNS Layout:**

| Limb | Prime | Bits | `qᵢ mod 2n` |
|------|-------|------|-------------|
| 0 | 288230376173076481 | 58 | 1 |
| 1 | 288230376167047169 | 58 | 1 |
| 2 | 288230376161280001 | 58 | 1 |

**Derived Sizes:**

| Artifact | Packed (bytes) | Limb-aligned (bytes) |
|----------|---------------|----------------------|
| Keygen share | 178176 | 196608 |
| Ciphertext `(c₀, c₁)` | 356352 | 393216 |

---

## 2. SRS Derivation

**Source:** Task definition; R3.2 NIZK construction requirements.

The structured reference string (SRS) for the transparent Pedersen commitment scheme is derived via a domain-separated hash-to-curve procedure:

```
srs_bytes = H(epoch ‖ "pvthfhe-srs-v1")
```

where:
- `H` is a cryptographically secure hash function (SHA-256 or SHAKE-256, TBD at SRS generation time).
- `epoch` is a canonical bootstrap seed (genesis block hash, chain-id + block-number tuple, or explicit 256-bit random seed — exact source TBD per deployment context).
- `‖` denotes concatenation.

The output `srs_bytes` is expanded deterministically via a CSPRNG (e.g., ChaCha12) into a Pedersen SRS `(G, H₁, …, Hₙ)` over a pairing-friendly curve, consuming each 32-byte block as a scalar to multiply the base point.

| Property | Value |
|----------|-------|
| Domain tag | `pvthfhe/sonobe/srs/v1` (Tag::SonobeSrs) |
| SRS type | Transparent Pedersen (hash-to-curve, no trusted setup) |
| Curve | TBD (pairing-friendly; referenced by `SonobeSrs` tag) |
| Derivation | Deterministic from `epoch` seed |

---

## 3. DKG (n, t) Bounds

**Source:** Task definition; DKG secrecy adversary model (R1.5).

| Parameter | Value | Notes |
|-----------|-------|-------|
| Default `(n, t)` | `(10, 7)` | Operational default for demo/e2e |
| Maximum `n` | 256 | Hard ceiling; higher values not tested |
| Minimum `t` | `⌊n/2⌋ + 1` | Honest-majority threshold |
| Quorum policy | ⌈2t/3⌉ for decryption quorum | Per standard threshold-FHE practice |

**Rationale:** The `t = ⌊n/2⌋ + 1` floor ensures an honest majority of at least one party (strict majority), consistent with the passive-adversary threshold-FHE model. The default `(10, 7)` is small enough for rapid integration testing while exercising the threshold logic (7 > 10/2 = 5).

---

## 4. Ajtai Matrix Parameters

**Source:** Task definition; R3 CRS requirements for lattice-based NIZK commitments.

| Parameter | Value | Notes |
|-----------|-------|-------|
| Rows `m` | 2048 | SIS dimension — commit space |
| Columns `n` | 1024 | SIS dimension — message space |
| Modulus `q` | ≈2⁶⁰ (≈1.15 × 10¹⁸) | Approximate; concrete `q` is a ~60-bit prime |
| Domain tag | `pvthfhe/cyclo-ajtai-binding/v1` (Tag::CycloAjtaiBinding) | Domain-separated commitment binding |

**Commitment scheme:** Ajtai (SIS-based) commitment over `Z_q`:

```
Commit(m; r) = A · m + r mod q
```

where `A ∈ Z_q^{m×n}` is a structured random matrix (R3 CRS), `m ∈ Z_qⁿ` is the message, and `r ∈ Z_qᵐ` is the randomness.

**Binding security:** Relies on the Short Integer Solution (SIS) hardness over the ring modulus `q ≈ 2⁶⁰` with dimension parameters `(m=2048, n=1024)`. Concrete SIS hardness estimate to be validated in `.sisyphus/design/ajtai-hardness-v1.md` (TBD).

---

## 5. Domain Tag Table

**Source:** `crates/pvthfhe-domain-tags/src/lib.rs` (Tag enum, lines 10–76).

| Tag Variant | Domain Tag | Protocol Phase | Purpose |
|-------------|-----------|----------------|---------|
| `SonobeSrs` | `pvthfhe/sonobe/srs/v1` | Phase 0: Setup | SRS domain separator |
| `CycloAjtaiBinding` | `pvthfhe/cyclo-ajtai-binding/v1` | Phase 0: Setup | Ajtai commitment binding domain tag |
| `WireTestPayload` | `pvthfhe/wire/test-payload/v1` | Phase 0: Testing | pvthfhe-wire canonicality tests |
| `KeygenSimulatorSession` | `pvthfhe/keygen-simulator/session/v1` | Phase 1: Keygen | Keygen simulator session label |
| `WireFheKeygenShare` | `pvthfhe/wire/fhe-keygen-share/v1` | Phase 1: Keygen | FHE keygen-share wire payload |
| `WireFhePublicKey` | `pvthfhe/wire/fhe-public-key/v1` | Phase 1: Keygen | FHE public-key wire payload |
| `WirePvssShareOpenedProof` | `pvthfhe/wire/pvss-share-opened-proof/v1` | Phase 1: Keygen | PVSS share proof envelope |
| `SonobeToyStep` | `pvthfhe/sonobe/toy-step/v1` | Phase 2: Folding | Sonobe surrogate toy-step circuit |
| `SonobeCycloFold` | `pvthfhe/sonobe/cyclo-fold/v1` | Phase 2: Folding | Sonobe Cyclo fold step circuit |
| `Finalize` | `pvthfhe/finalize/v1` | Phase 2–3: Aggregation | Aggregator finalize-phase transcript |
| `ProofTag` | `pvthfhe/proof-tag/v1` | Phase 2–3: Aggregation | Aggregator e2e proof tag |
| `WireFheDecryptShare` | `pvthfhe/wire/fhe-decrypt-share/v1` | Phase 3: Decryption | FHE decrypt-share wire payload |
| `WirePvssDecryptOpenedProof` | `pvthfhe/wire/pvss-decrypt-opened-proof/v1` | Phase 3: Decryption | PVSS decrypt proof envelope |

---

## Sign-Off

This parameter freeze is binding for all Phase 1–3 implementation artifacts. No downstream code may use parameter values that deviate from this document without an approved parameter amendment (PVTHFHE-PA-###).

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Cryptography Lead | ________________ | ________________ | ________ |
| ZK Lead | ________________ | ________________ | ________ |
| Engineering Lead | ________________ | ________________ | ________ |

**Next review:** Before Phase 1 gate or at the first parameter amendment, whichever comes first.
