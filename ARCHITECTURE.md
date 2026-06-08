# Architecture

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [SECURITY.md](SECURITY.md), and [WARNING.md](WARNING.md) for threat model and caveats.

PVTHFHE targets private-verifiable threshold FHE with O(n) per-party work and O(polylog n) verifier cost. It allows n parties to jointly manage an FHE secret key, any party to encrypt, and a threshold of honest parties to decrypt while providing verifiable end-to-end correctness proofs.

## High-Level Intuition

1. **Key Generation** — Parties perform a 3-round PVSS protocol to establish an aggregate public key and private secret shares.
2. **Encryption** — Anyone encrypts data using the aggregate public key (BFV RLWE).
3. **Partial Decryption** — Parties compute partial decryption shares and provide a NIZK proof of well-formedness (Ajtaï D2 sigma + BFV sigma, k-round parallel repetition).
4. **Aggregation & Folding** — An untrusted aggregator collects shares and folds the proofs using LatticeFold+ lattice-native folding with Cyclo RLWE.
5. **On-Chain Verification** — The aggregator submits proof binding metadata on-chain. While the UltraHonk proof commits to the Nova state, the on-chain contract does **NOT** cryptographically verify the IVC proof itself. IVC mode is currently fail-closed.

```
[ Parties ] --(Partial Decrypt Shares + NIZK)--> [ Aggregator ]
                                                       |
                                              (LatticeFold+ Folding)
                                                       |
                                              (On-chain Binding)
                                                       |
                                                       v
[ Solidity Verifier ] <------------------ [ Transparent Proof + UltraHonk ]
```

The pipeline uses three proving backends: **LatticeFold+** (lattice-native folding with Cyclo RLWE), **Noir UltraHonk** (final aggregation and wrapping), and **HonkVerifier.sol** (Solidity on-chain). All step circuits implement the folding circuit trait.

## Protocol Layers

| Layer | Responsibility | Component |
| :--- | :--- | :--- |
| **Lattice Layer** | RLWE arithmetic, BFV encryption/decryption | `pvthfhe-fhe`, `fhe.rs` |
| **Proof Layer** | Share well-formedness, Cyclo RLWE folding, LatticeFold+ compression | `circuits/`, `pvthfhe-nizk`, `pvthfhe-compressor` |
| **Coordination** | DKG, decryption rounds, blame assignment | `pvthfhe-core`, `pvthfhe-aggregator` |
| **Verification** | Proof binding, gas-efficient on-chain check | `contracts/` (UltraHonkVerifier.sol) |

## RLWE Parameters

Standardized secure parameters for 128-bit security: **N** = 8192, **L** = 3 RNS limbs, **log₂(Q)** ≈ 174 bits, **t_plain** = 2¹⁷.

## Proving Backends

| Backend | Role | Technology |
| --- | --- | --- |
| LatticeFold+ (lattice-native) | IVC folding + C7 aggregation + compression | Cyclo RLWE (no EC assumptions) |
| Noir + BB UltraHonk | Final Lagrange recombination + state commitment | Noir R1CS → UltraHonk |
| HonkVerifier.sol | On-chain verification | Solidity |

**Transparent folding**: No Groth16 trusted ceremony required. LatticeFold+ accumulator state is hashed with Keccak256 and embedded for the on-chain verifier. The on-chain contract does **NOT** currently verify the LatticeFold+ proof cryptographically; it only commits to the proof metadata. Full on-chain verification is fail-closed.

**C7 Merkle aggregation**: In-circuit Poseidon R1CS (`poseidon_gadget.rs`, ~900 constraints per hash8) via `C7MerkleStepCircuit` at depth-5 (N=8192). The Noir `aggregator_final` circuit proves full Schwartz-Zippel threshold-decryption correctness (Lagrange recombination) plus in-circuit Merkle PK binding, verifying that `sum(lambda_i * d_i(r)) = pt(r)`.

## Symphony: Proof-Compression Optimization Techniques

Four optimization techniques from the Symphony paper. These were originally implemented in the Nova compressor (Track A, now removed). Their latticefold equivalents are under development.

| Technique | Description |
| --- | --- |
| **T1: High-arity folding** | Batches n iterative fold steps into a single fold via random linear combination β (Fiat-Shamir). Achieves O(1) per-step cost. |
| **T2: FS outside circuit** | Moves Fiat-Shamir hashing outside the step circuit. Witness data is committed with Keccak256 and bound to step inputs. |
| **T3: Monomial embedding** | Adaptive bit-count range checks via monomial embedding. Reduces per-coefficient constraint cost. |
| **T4: Random projection** | JL projection reduces sigma witness size ~n/256×. Verifies norms on projected vectors instead of full-dimension vectors. |

T1+T2 were enabled by default in the Nova compressor. T3+T4 enabled k=90-round repetition within practical budgets.

## LaZer: Auto-Generated Sigma Proofs (P1)

`crates/pvthfhe-lazer/` provides Rust FFI bindings to the LaZer lattice-based NIZK library (LaBRADOR protocol). When `enable-lazer` feature is active, the full pipeline loads LaZer relation specs and validates them at runtime as defense-in-depth. The integration is wired through `pvthfhe-nizk/src/lazer_bridge.rs` with relation specs in `lazer_specs/` (BFV, CKKS, TFHE).

| Spec | Relation | Ring | Witnesses | Protocol |
|------|----------|------|-----------|----------|
| `bfv_encryption.toml` | RLWE | N=8192, 3-limb RNS | u, e0, e1, m | LaBRADOR |
| `ckks_encryption.toml` | RLWE | N=8192, 3-limb RNS | s, e | LaBRADOR |
| `tfhe_bootstrap.toml` | LWE | N=1, scalar | s, bsk_noise | LaBRADOR |

LaZer is the default sigma backend.

## Greyhound: Lattice Polynomial Commitments

Greyhound provides lattice-based polynomial commitment schemes with 53KB proof sizes and no elliptic curve assumptions. It replaces KZG-based commitments throughout the protocol stack, enabling a fully post-quantum commitment layer.

## LatticeFold+: Lattice-Native Folding

LatticeFold+ provides lattice-native folding over RLWE without elliptic curve assumptions, replacing the Nova IVC folding path. It uses Cyclo-based folding with M-SIS hardness, Cyclo Theorem 3 soundness, and Lemma 9 invertibility guarantees. This is the default folding backend for the proving pipeline.

## Greco: BFV Quotient-Witness Verification

`bfv_greco.rs` strengthens BFV encryption NIZK soundness from "sigma equation holds modulo q_ℓ" to "valid BFV witness exists with small coefficients." For each RNS limb ℓ, Greco computes quotient witnesses q0,q1 by lifting the sigma equations to the integers and verifies boundedness (`|q0[ℓ]|_∞ ≤ GRECO_BOUND_Q = 2^48`). NTT-accelerated RNS convolution with Garner CRT reconstruction recovers exact integer coefficients. If sigma equations hold AND quotients are bounded, a valid BFV witness exists.

## Compute Provider: Verifiable FHE Operations

`FheComputeStepCircuit` (`fhe_compute_circuit.rs`) proves that a sequence of FHE **Add** and **Mul** operations over Merkle-committed input ciphertexts produces a given output ciphertext. The circuit performs in-circuit FHE coefficient addition/multiplication with Merkle inclusion proofs, chaining output coefficients through Nova state. Uses production BFV parameters N=8192, L=3 RNS limbs by default. Fast testing at N=4 is available via `--features bfv-n4`.

**FHE Multiplication** is proven at the native step circuit level via BFV constraint system. At production scale (N=8192), both Add and Mul operations are fully verified in the LatticeFold+ chain. The on-chain verifier currently cannot re-verify the LatticeFold+ chain directly — proof verification is deferred to P4 (on-chain decider). Fast testing at N=4 demo scale is available via `--features bfv-n4`.

## Benchmarking

The benchmark pipeline records artifacts under `bench/results/`:

1. `pvthfhe-e2e` writes `e2e_timings.json` (schema 1.0.0, 14 phases).
2. `bench_comparison` reads that artifact and emits `comparison.json`.
3. `render_comparison` renders human-readable Markdown reports.

Per-node (`pvthfhe-per-node`) and per-aggregator (`pvthfhe-per-aggregator`) binaries benchmark individual party and aggregator costs across N=128 to 8192.

## End-to-End Verifiability (CAVEATS)

Each protocol step produces verifiable artifacts. Publicly verifiable steps include: share-encryption NIZK, Cyclo fold accumulator (transcript verification is RESOLVED — versioned codec + real verify dispatch), LatticeFold+ compressed proof (transparent IVC, on-chain binding only), on-chain UltraHonk verification of the state commitment, and aggregate public-key formation proof (C5 — RESOLVED with PoP + on-chain binding). Full aggregate-decrypt verification (C7) is RESOLVED — Schwartz-Zippel Lagrange recombination with G3/G4 plaintext and PK binding, 18 Noir tests passing.

## Design Specifications

- [Key Generation](.sisyphus/design/spec-keygen.md)
- [Decryption](.sisyphus/design/spec-decrypt.md)
- [Proof Boundary](.sisyphus/design/proof-boundary.md)
- [Parameters](.sisyphus/design/parameters.md)

## Performance Ceiling

demo-e2e completes for n ≤ 128. At n ≥ 150, setup_threshold (O(n²·degree) Shamir share generation) dominates wall time and exceeds practical demo budgets.
