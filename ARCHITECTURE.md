# Architecture

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains **critical cryptographic surrogates** that provide no real security:
> - **no on-chain cryptographic verification — verifier accepts any proof bytes**
> - **Noir circuits are tautological surrogates** (assert(x == x) — no real constraints)
> - **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.

PVTHFHE targets **Architecture B** (Lattice PVSS + LatticeFold+ + MicroNova). In the current prototype, Sonobe substitutes MicroNova as the primary proof compressor due to performance considerations (see the N3a NoGo path). This change is contained within a bounded migration surface to preserve the path toward the target architecture.

## High-Level Intuition

The system allows $n$ parties to jointly manage an FHE secret key.

1.  **Key Generation**: Parties perform a 3-round Publicly Verifiable Secret Sharing (PVSS) protocol to establish an aggregate public key and private secret shares.
2.  **Encryption**: Anyone can encrypt data using the aggregate public key.
3.  **Partial Decryption**: Parties compute partial decryption shares and provide a NIZK proof of well-formedness.
4.  **Aggregation & Folding**: An untrusted aggregator collects shares and folds the proofs. In the current prototype, this uses off-chain Sonobe folding.
5.  **On-Chain Verification**: The aggregator submits a commitment to the Sonobe state on-chain. Verification combines an UltraHonk proof of the commitment with an off-chain attestation.

### Component Diagram

```text
[ Parties ] --(Partial Decrypt Shares + NIZK)--> [ Aggregator ]
                                                       |
                                             (Off-chain Sonobe Folding)
                                                       |
                                             (On-chain State Commitment)
                                                       |
                                                       v
[ Solidity Verifier ] <----------------------- [ SNARK + Attestation ]
```

## Protocol Layers

| Layer | Responsibility | Component |
| :--- | :--- | :--- |
| **Lattice Layer** | RLWE arithmetic, BFV/CKKS | `pvthfhe-fhe`, `fhe.rs` |
| **Proof Layer** | Share well-formedness, Folding | `circuits/`, `pvthfhe-circuits`, Sonobe |
| **Coordination** | DKG, Decryption rounds, Blame | `pvthfhe-core`, `pvthfhe-aggregator` |
| **Verification** | Proof binding, Gas-efficient check | `contracts/` |

## Design Specifications

- [Key Generation (T18)](.sisyphus/design/spec-keygen.md)
- [Decryption (T19)](.sisyphus/design/spec-decrypt.md)
- [Proof Boundary (T25)](.sisyphus/design/proof-boundary.md)
- [API Specification (T22)](.sisyphus/design/api-spec.md)
- [Architecture Selection Memo (T17)](.sisyphus/design/selection-memo.md)
- [Sonobe-Wrap Feasibility (N3a)](.sisyphus/research/sonobe-wrap-feasibility.md)


## RLWE Parameters

The system uses standardized secure parameters for 128-bit security:
- **N**: 8192
- **L**: 3 RNS limbs
- **log₂(Q)**: ≈174 bits
- **t_plain**: 2^17

For detailed parameter analysis, see [parameters.md](.sisyphus/design/parameters.md).

## Benchmarking

The benchmark pipeline records and republishes a fixed artifact chain under `bench/results/`.

1. `pvthfhe-e2e` writes `bench/results/e2e_timings.json` after each run.
2. `bench_comparison` reads that artifact and emits `bench/results/comparison.json`.
3. `render_comparison` renders the human-readable Markdown report (`comparison-<git-sha>.md`, i.e. the `comparison.md` report family).

The `e2e_timings.json` artifact contract is stable for this phase: it carries schema_version `1.0.0` and exactly 12 phases (`keygen`, `nizk_prove`, `nizk_verify`, `pvss_share_encrypt`, `pvss_decrypt_prove`, `cyclo_fold`, `compressor_prove`, `compressor_verify`, `partial_decrypt`, `aggregate_decrypt`, `noir_sonobe_wrap`, `onchain_verify`). The comparison renderer consumes those timings to populate all 12 Interfold-shaped comparison rows, including merged-stage notes when a single PVTHFHE pass backs multiple comparison rows.

## Formal Section

### Security Properties (Target Design Goals)

1.  **IND-CPA-PV**: Ciphertext indistinguishability under chosen-plaintext attack with public verifiability (target goal).
2.  **Decryption-Soundness**: Cryptographically verified decryption soundness is an implementation task; current prototype combines UltraHonk proofs with off-chain attestation.
3.  **Public-Verifiability**: The prototype targets public verifiability; current on-chain verification is restricted to the attestor set.
4.  **Robustness**: The protocol is designed to succeed as long as $t = \lfloor n/2 \rfloor + 1$ parties are honest (current simulation validates this for P4).

### Implementation State

The current implementation uses Sonobe substitution for the folding and compression layers:
- **P1**: Lattice NIZK well-formedness soundness (conditional, see `SECURITY.md`).
- **P2**: LatticeFold+ folding substituted by off-chain Sonobe.
- **P3**: MicroNova SNARK compression substituted by off-chain Sonobe + on-chain commitment topology.
