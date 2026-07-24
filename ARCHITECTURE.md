# Architecture

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> See [SECURITY.md](SECURITY.md) and [WARNING.md](WARNING.md) for the threat model and caveats.

PVTHFHE targets private-verifiable threshold FHE with O(n) per-party work and O(polylog n) verifier cost. n parties jointly manage an FHE secret key, any party can encrypt, and a threshold of honest parties can decrypt — with verifiable end-to-end correctness proofs.

## High-Level Intuition

1. **Key Generation** — Parties perform a 3-round PVSS protocol to establish an aggregate public key and private secret shares.
2. **Encryption** — Anyone encrypts data using the aggregate public key (BFV RLWE).
3. **Partial Decryption** — Parties compute partial decryption shares and provide a NIZK proof of well-formedness (Ajtaï D2 sigma + BFV sigma, k-round parallel repetition).
4. **Aggregation & Folding** — An untrusted aggregator collects shares and folds the proofs using LatticeFold+ lattice-native folding with Cyclo RLWE.
5. **On-Chain Verification** — The aggregator submits proof-binding metadata on-chain. The UltraHonk proof commits to the IVC state, but the on-chain contract does **NOT** cryptographically verify the IVC proof itself. IVC mode is currently fail-closed (open problem P4).

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

The pipeline uses three proving backends: **LatticeFold+** (lattice-native folding with Cyclo RLWE), **Noir UltraHonk** (final aggregation and wrapping), and **HonkVerifier.sol** (Solidity on-chain). The on-chain commitment binds the accumulator state hash and public inputs; full cryptographic verification of the folding proof on-chain is the open P4 problem.

## Workspace Crate Map (14 crates)

| Crate | Responsibility |
| :--- | :--- |
| `pvthfhe-foundations` | Shared leaf layer: `types` (byte newtypes, verification statement), `domain_tags` (single source of domain separators), `wire` (versioned envelope), `rng` (OsRng facade, seeded-RNG enforcement point) |
| `pvthfhe-cyclo` | LatticeFold+ folding backend: fold driver, NIFS, decomposition, Ajtai commitments, ring/NTT, CCS relations |
| `pvthfhe-nizk` | `NizkAdapter` trait + sigma protocols (Ajtai D2, BFV sigma, schnorr), Fiat-Shamir, LaZer bridge |
| `pvthfhe-fhe` | `FheBackend` trait + `fhers` (gnosisguild/fhe.rs BFV — the F1-locked backend) + mock backend for tests |
| `pvthfhe-pvss` | PVSS/DKG home: dealing, share computation, DKG aggregation, key escrow, AVID, shamir, keygen adapter + frozen keygen spec types, decrypt/share/keygen NIZKs |
| `pvthfhe-non-equiv` | NonEquiv protocol (ePrint 2026/1159 §4.1) |
| `pvthfhe-aggregator` | Aggregation protocol node: decrypt rounds, folding orchestration, keygen simulator, leader election |
| `pvthfhe-compressor` | P2→P3 compression boundary: LatticeFold+ prover/verifier, Merkle, witness encoding |
| `pvthfhe-lazer` | FFI bindings to the LaZer C library (LaBRADOR sigma proofs) |
| `pvthfhe-cli` | Binaries + full pipeline orchestration (demo, e2e, per-node, per-aggregator) |
| `pvthfhe-bench` | Benchmark harness binaries |
| `pvthfhe-circuit-tests` | Noir/bb test harness + witness generators |
| `pvthfhe-tests` | Cross-crate adversarial + audit regression suites + shared golden vectors |
| `pvthfhe-fuzz` | Deterministic seeded fuzz harnesses |

## RLWE Parameters

Standardized secure parameters for 128-bit security: **N** = 8192, **L** = 3 RNS limbs, **log₂(Q)** ≈ 174 bits, **t_plain** = 2¹⁷. Fast-test path at N=4 via `--features bfv-n4`; Noir circuits currently run at N=256 (Noir beta.22 ACIR OOM at N=8192 — see WARNING.md).

## Proving Backends

| Backend | Role | Technology |
| --- | --- | --- |
| LatticeFold+ (lattice-native) | IVC folding + C7 aggregation + compression | Cyclo RLWE (no EC assumptions) |
| Noir + BB UltraHonk | Final Lagrange recombination + state commitment | Noir R1CS → UltraHonk |
| HonkVerifier.sol | On-chain verification | Solidity |

**Transparent folding**: No Groth16 trusted ceremony required. LatticeFold+ accumulator state is hashed and embedded for the on-chain verifier. The on-chain contract commits to the proof metadata but does **NOT** currently verify the LatticeFold+ proof cryptographically — verification is fail-closed.

**C7 Merkle aggregation**: In-circuit Poseidon R1CS via the Merkle step circuit at depth-5 (N=8192). The Noir `aggregator_final` circuit proves full Schwartz-Zippel threshold-decryption correctness (Lagrange recombination) plus in-circuit Merkle PK binding, verifying that `sum(lambda_i * d_i(r)) = pt(r)`.

## Symphony: Proof-Compression Optimization Techniques

Four optimization techniques from the Symphony paper, implemented in the LatticeFold+ compressor path. The compressor is enabled with the `real-compressor` feature (formerly named `nova-compressor` — a Track A leftover).

| Technique | Description |
| --- | --- |
| **T1: High-arity folding** | Batches n iterative fold steps into a single fold via random linear combination β (Fiat-Shamir). Achieves O(1) per-step cost. |
| **T2: FS outside circuit** | Moves Fiat-Shamir hashing outside the step circuit. Witness data is committed and bound to step inputs. |
| **T3: Monomial embedding** | Adaptive bit-count range checks via monomial embedding. Reduces per-coefficient constraint cost. |
| **T4: Random projection** | JL projection reduces sigma witness size ~n/256×. Verifies norms on projected vectors. |

## LaZer: Auto-Generated Sigma Proofs (P1)

`crates/pvthfhe-lazer/` provides Rust FFI bindings to the LaZer lattice-based NIZK library (LaBRADOR protocol). When the `enable-lazer` feature is active, the pipeline loads LaZer relation specs and validates them at runtime as defense-in-depth, wired through `pvthfhe-nizk/src/lazer_bridge.rs`. LaZer is the default sigma backend.

## Greyhound: Lattice Polynomial Commitments

Greyhound provides lattice-based polynomial commitments with 53KB proofs and no elliptic-curve assumptions, replacing KZG-based commitments across the stack.

## LatticeFold+: Lattice-Native Folding

LatticeFold+ provides lattice-native folding over RLWE without elliptic-curve assumptions (the Nova IVC path was removed with Track A). It uses Cyclo-based folding with M-SIS hardness, Cyclo Theorem 3 soundness, and Lemma 9 invertibility (an accepted assumption — see `docs/security-proofs/lemma9.md`). This is the sole folding backend.

## Greco: BFV Quotient-Witness Verification

The Greco module strengthens BFV encryption NIZK soundness from "sigma equation holds modulo q_ℓ" to "valid BFV witness exists with small coefficients": quotient witnesses are computed by lifting the sigma equations to the integers and boundedness is verified. NTT-accelerated RNS convolution with Garner CRT reconstruction recovers exact integer coefficients.

## Compute Provider: Verifiable FHE Operations

The compute step circuit proves that a sequence of FHE **Add** and **Mul** operations over Merkle-committed input ciphertexts produces a given output ciphertext, with in-circuit coefficient arithmetic and Merkle inclusion proofs. Production BFV parameters N=8192 by default; fast testing at N=4 via `--features bfv-n4`. The on-chain verifier cannot yet re-verify the LatticeFold+ chain directly — that is open problem P4.

## Benchmarking

The benchmark pipeline records artifacts under `bench/results/`:

1. `pvthfhe-e2e` writes `bench/results/e2e_timings.json` (versioned schema).
2. `bench_comparison` reads that artifact and emits `comparison.json`.
3. `render_comparison` renders human-readable Markdown reports (`comparison.md` / `comparison-<hash>.md`).

Per-node and per-aggregator binaries benchmark individual party and aggregator costs. `just bench-scaling` produces the scaling envelopes consumed by `phase3-gate`.

## End-to-End Verifiability (CAVEATS)

Each protocol step produces verifiable artifacts. Publicly verifiable: share-encryption NIZK, Cyclo fold accumulator transcript (A1 — RESOLVED, versioned codec + real verify dispatch), LatticeFold+ compressed proof (transparent IVC, on-chain binding only), on-chain UltraHonk verification of the state commitment, aggregate public-key formation proof (C5 — RESOLVED), threshold-decryption correctness (C7 — RESOLVED, Schwartz-Zippel Lagrange recombination). Open: P1 (NIZK soundness reduction), P2 (folding linearity/soundness — contingent on Lemma 9), P4 (on-chain IVC decider).

## Design Specifications

- [Key Generation](.sisyphus/design/spec-keygen.md)
- [Decryption](.sisyphus/design/spec-decrypt.md)
- [Proof Boundary](.sisyphus/design/proof-boundary.md)
- [Parameters](.sisyphus/design/parameters.md)
- [Non-Equivocation](.sisyphus/design/spec-non-equiv.md)
- [Provable AVID](.sisyphus/design/spec-avid.md)
- [Committee PVSS](.sisyphus/design/spec-committee-pvss.md)
- [Key Escrow](.sisyphus/design/spec-key-escrow.md)
- [Leader Election](.sisyphus/design/spec-leader-election.md)

All DKG subprotocols (NonEquiv, AVID, Leader Election) bind `session_id` in their hash constructions to prevent cross-session replay (MPC-AUDIT-2026-06-12, findings F1-F3).

## Performance Ceiling

The protocol supports 1 ≤ t ≤ n ≤ 255 (Shamir over GF(256)). demo-e2e completes for n ≤ 128 within practical wall-time budgets; at n ≥ 150, the O(n²·degree) setup dominates and exceeds demo budgets.
