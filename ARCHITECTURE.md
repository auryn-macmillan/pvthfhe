# Architecture

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [SECURITY.md](SECURITY.md), and [WARNING.md](WARNING.md) for threat model and caveats.

PVTHFHE targets private-verifiable threshold FHE with O(n) per-party work and O(polylog n) verifier cost. It allows n parties to jointly manage an FHE secret key, any party to encrypt, and a threshold of honest parties to decrypt while providing verifiable end-to-end correctness proofs.

## High-Level Intuition

1. **Key Generation** — Parties perform a 3-round PVSS protocol to establish an aggregate public key and private secret shares.
2. **Encryption** — Anyone encrypts data using the aggregate public key (BFV RLWE).
3. **Partial Decryption** — Parties compute partial decryption shares and provide a NIZK proof of well-formedness (Ajtaï D2 sigma + BFV sigma, k-round parallel repetition).
4. **Aggregation & Folding** — An untrusted aggregator collects shares and folds the proofs using nova-snark Nova IVC with Cyclo RLWE folding.
5. **On-Chain Verification** — The aggregator submits proof binding metadata on-chain. Verification uses an UltraHonk proof on the Nova state commitment with transparent IVC binding (`ivc_verify_result`).

```
[ Parties ] --(Partial Decrypt Shares + NIZK)--> [ Aggregator ]
                                                       |
                                             (Off-chain Nova IVC Folding)
                                                       |
                                             (On-chain IVC Binding)
                                                       |
                                                       v
[ Solidity Verifier ] <------------------ [ Transparent IVC + UltraHonk ]
```

The pipeline uses three proving backends: **nova-snark** (Microsoft Nova IVC with Cyclo RLWE folding), **Noir UltraHonk** (final aggregation and wrapping), and **HonkVerifier.sol** (Solidity on-chain). All step circuits implement `nova_snark::traits::circuit::StepCircuit`.

## Protocol Layers

| Layer | Responsibility | Component |
| :--- | :--- | :--- |
| **Lattice Layer** | RLWE arithmetic, BFV encryption/decryption | `pvthfhe-fhe`, `fhe.rs` |
| **Proof Layer** | Share well-formedness, Cyclo RLWE folding, Nova IVC compression | `circuits/`, `pvthfhe-nizk`, `pvthfhe-compressor` |
| **Coordination** | DKG, decryption rounds, blame assignment | `pvthfhe-core`, `pvthfhe-aggregator` |
| **Verification** | Proof binding, gas-efficient on-chain check | `contracts/` (UltraHonkVerifier.sol) |

## RLWE Parameters

Standardized secure parameters for 128-bit security: **N** = 8192, **L** = 3 RNS limbs, **log₂(Q)** ≈ 174 bits, **t_plain** = 2¹⁷.

## Proving Backends

| Backend | Role | Technology |
| --- | --- | --- |
| nova-snark v0.71 | IVC folding + C7 aggregation + compression | R1CS Nova (Bn256EngineKZG + GrumpkinEngine cycle) |
| Noir + BB UltraHonk | Final Lagrange recombination + state commitment | Noir R1CS → UltraHonk |
| HonkVerifier.sol | On-chain verification | Solidity |

**Transparent IVC**: No Groth16 trusted ceremony required. IVC proof bytes are hashed with Keccak256 and embedded via `IvcBindingData` (11-field binding: proof_hash, vk_hash, pp_hash, z0/zi commitments, steps, verification hashes, `ivc_verify_result`) for on-chain verification.

**C7 Merkle aggregation**: In-circuit Poseidon R1CS (`poseidon_gadget.rs`, ~900 constraints per hash8) via `C7MerkleStepCircuit` at depth-5 (N=8192).

## Symphony: Proof-Compression Optimization Techniques

Four optimization techniques from the Symphony paper, all compiled unconditionally (S8):

| Technique | File | Description |
| --- | --- | --- |
| **T1: High-arity folding** | `high_arity_fold.rs` | Batches n iterative `prove_step` calls into a single fold via random linear combination β (Fiat-Shamir). `prove_steps_high_arity()` folds up to n=128 instances into one IVC step, achieving O(1) per-step cost. |
| **T2: FS outside circuit** | `nova_gadgets.rs` | Moves Fiat-Shamir hashing outside the Nova step circuit. Witness data is committed with Keccak256 and bound to step inputs via identity circuits. |
| **T3: Monomial embedding** | `monomial_range.rs` | Adaptive bit-count range checks via monomial embedding. Uses `ceil(log₂(bound))` bits, reducing per-coefficient constraint cost from ~93 to ~3·ceil(log₂(bound)). |
| **T4: Random projection** | `nova_gadgets.rs` | JL projection J∈{0,±1}^{256×n} reduces sigma witness size ~n/256×. Verifies norms on projected 256-dim vectors instead of full 8192-dim vectors. |

T1+T2 are enabled by default. T3+T4 enable k=90-round repetition (~46M constraints) within practical budgets.

## LaZer: Auto-Generated Sigma Proofs (P1)

`crates/pvthfhe-lazer/` provides Rust FFI bindings to the LaZer lattice-based NIZK library (LaBRADOR protocol). When `enable-lazer` feature is active, the full pipeline loads LaZer relation specs and validates them at runtime as defense-in-depth. The integration is wired through `pvthfhe-nizk/src/lazer_bridge.rs` with relation specs in `lazer_specs/` (BFV, CKKS, TFHE).

| Spec | Relation | Ring | Witnesses | Protocol |
|------|----------|------|-----------|----------|
| `bfv_encryption.toml` | RLWE | N=8192, 3-limb RNS | u, e0, e1, m | LaBRADOR |
| `ckks_encryption.toml` | RLWE | N=8192, 3-limb RNS | s, e | LaBRADOR |
| `tfhe_bootstrap.toml` | LWE | N=1, scalar | s, bsk_noise | LaBRADOR |

LaZer is opt-in via `--features enable-lazer`. Legacy sigma protocols (`sigma.rs`, `bfv_sigma.rs`, `bootstrap_sigma.rs`) remain the default until LaZer FFI state population (lin_params_init) is completed.

## Greco: BFV Quotient-Witness Verification

`bfv_greco.rs` strengthens BFV encryption NIZK soundness from "sigma equation holds modulo q_ℓ" to "valid BFV witness exists with small coefficients." For each RNS limb ℓ, Greco computes quotient witnesses q0,q1 by lifting the sigma equations to the integers and verifies boundedness (`|q0[ℓ]|_∞ ≤ GRECO_BOUND_Q = 2^48`). NTT-accelerated RNS convolution with Garner CRT reconstruction recovers exact integer coefficients. If sigma equations hold AND quotients are bounded, a valid BFV witness exists.

## Compute Provider: Verifiable FHE Operations

`FheComputeStepCircuit` (`fhe_compute_circuit.rs`) proves that a sequence of FHE Add operations over Merkle-committed input ciphertexts produces a given output ciphertext. The circuit performs in-circuit FHE coefficient addition with Merkle inclusion proofs, chaining output coefficients through Nova state. Supports BFV parameters N=4 (demo) / N=8192 (production), L=3 RNS limbs.

## Benchmarking

The benchmark pipeline records artifacts under `bench/results/`:

1. `pvthfhe-e2e` writes `e2e_timings.json` (schema 1.0.0, 14 phases).
2. `bench_comparison` reads that artifact and emits `comparison.json`.
3. `render_comparison` renders human-readable Markdown reports.

Per-node (`pvthfhe-per-node`) and per-aggregator (`pvthfhe-per-aggregator`) binaries benchmark individual party and aggregator costs across N=128 to 8192.

## End-to-End Verifiability

Each protocol step produces verifiable artifacts. Publicly verifiable steps include: share-encryption NIZK, Cyclo fold accumulator, nova-snark compressed proof (transparent IVC, dual verification path), and on-chain UltraHonk verification with IVC binding. Full aggregate-decrypt verification uses in-circuit C7MerkleStepCircuit with Poseidon R1CS.

## Design Specifications

- [Key Generation](.sisyphus/design/spec-keygen.md)
- [Decryption](.sisyphus/design/spec-decrypt.md)
- [Proof Boundary](.sisyphus/design/proof-boundary.md)
- [Parameters](.sisyphus/design/parameters.md)

## Performance Ceiling

demo-e2e completes for n ≤ 128. At n ≥ 150, setup_threshold (O(n²·degree) Shamir share generation) dominates wall time and exceeds practical demo budgets.
