# Architecture

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains **critical cryptographic surrogates** that provide no real security:
> - **no on-chain cryptographic verification — verifier accepts any proof bytes**
> - **Noir circuits are tautological surrogates** (assert(x == x) — no real constraints)
> - **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.

PVTHFHE targets **Architecture B** (Lattice PVSS + LatticeFold+ + MicroNova), with the current prototype using cryptographic surrogates for the folding and on-chain verification layers.

## High-Level Intuition

The system allows $n$ parties to jointly manage an FHE secret key.

1.  **Key Generation**: Parties perform a 3-round Publicly Verifiable Secret Sharing (PVSS) protocol to establish an aggregate public key and private secret shares.
2.  **Encryption**: Anyone can encrypt data using the aggregate public key.
3.  **Partial Decryption**: Parties compute partial decryption shares and provide a NIZK proof of well-formedness.
4.  **Aggregation & Folding**: An untrusted aggregator collects shares, folds the proofs using LatticeFold+, and compresses the result into a single SNARK proof using MicroNova.
5.  **On-Chain Verification**: A Solidity verifier checks the final proof, ensuring the decryption result is correct.

### Component Diagram

```text
[ Parties ] --(Partial Decrypt Shares + NIZK)--> [ Aggregator ]
                                                       |
                                            (LatticeFold+ Aggregation)
                                                       |
                                              (MicroNova Compression)
                                                       |
                                                       v
[ Solidity Verifier ] <----------------------- [ SNARK Proof ]
```

## Protocol Layers

| Layer | Responsibility | Component |
| :--- | :--- | :--- |
| **Lattice Layer** | RLWE arithmetic, BFV/CKKS | `pvthfhe-fhe`, `fhe.rs` |
| **Proof Layer** | Share well-formedness, Folding | `circuits/`, `pvthfhe-circuits` |
| **Coordination** | DKG, Decryption rounds, Blame | `pvthfhe-core`, `pvthfhe-aggregator` |
| **Verification** | Proof binding, Gas-efficient check | `contracts/` |

## Design Specifications

- [Key Generation (T18)](.sisyphus/design/spec-keygen.md)
- [Decryption (T19)](.sisyphus/design/spec-decrypt.md)
- [Proof Boundary (T25)](.sisyphus/design/proof-boundary.md)
- [API Specification (T22)](.sisyphus/design/api-spec.md)
- [Architecture Selection Memo (T17)](.sisyphus/design/selection-memo.md)

## RLWE Parameters

The system uses standardized secure parameters for 128-bit security:
- **N**: 8192
- **L**: 3 RNS limbs
- **log₂(Q)**: ≈174 bits
- **t_plain**: 2^17

For detailed parameter analysis, see [parameters.md](.sisyphus/design/parameters.md).

## Formal Section

### Security Properties (Target Design Goals)

1.  **IND-CPA-PV**: Ciphertext indistinguishability under chosen-plaintext attack with public verifiability (target goal).
2.  **Decryption-Soundness**: Cryptographically verified decryption soundness is an open implementation task; current prototype uses a trusted signer.
3.  **Public-Verifiability**: The prototype targets public verifiability; current on-chain verification is restricted to a trusted signer.
4.  **Robustness**: The protocol is designed to succeed as long as $t = \lfloor n/2 \rfloor + 1$ parties are honest (current simulation validates this for P4).

### Open Problems

The current implementation uses surrogates for several research-frontier components:
- **P1**: Lattice NIZK well-formedness soundness.
- **P2**: LatticeFold+ folding over RLWE rings.
- **P3**: MicroNova-lattice encoding for SNARK compression.
