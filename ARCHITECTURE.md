# Architecture

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
- on-chain verification: UltraHonk verifier (Track A: DEPRECATED — Sonobe hash-then-fold. Track B: Default production path — norm enforcement, tree-based C7, on-chain UltraHonk)
- Noir circuits: real aggregation and wrapping logic
- **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.
> See `SECURITY.md` and `WARNING.md` for the canonical list of surrogates.

PVTHFHE targets **Architecture B** (Lattice PVSS + LatticeFold+ + MicroNova). In the current prototype, Sonobe substitutes MicroNova as the primary proof compressor due to performance considerations (see the N3a NoGo path). The primary C7 verification path now uses a tree-based CompressionTree (Poseidon R1CS) rather than flat Nova folding. This change is contained within a bounded migration surface to preserve the path toward the target architecture.

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

The pipeline uses four proving backends: Cyclo (ring/sigma), Sonobe Nova (folding), Noir UltraHonk (final aggregation), and HonkVerifier.sol (on-chain).

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
2.  **Decryption-Soundness**: Full decryption soundness is a design goal; the current prototype uses conditional NIZK soundness (see SECURITY.md §P1).
3.  **Public-Verifiability**: The prototype targets public verifiability; current on-chain verification is restricted to the attestor set.
4.  **Robustness**: The protocol is designed to succeed as long as $t = \lfloor n/2 \rfloor + 1$ parties are honest (current simulation validates this for P4).

## End-to-End Verifiability Chain (R4 Audit)

Each protocol step produces verifiable artifacts. A third-party verifier with only public data can verify:

| Step | Artifact | Publicly Verifiable? | Notes |
|------|----------|---------------------|-------|
| Keygen (DKG) | Aggregate PK, shares | **Partial** | AggregateKeygen is deterministic from shares but no compact PK-correctness proof |
| NIZK share-encryption | ShareNizkProof | **Yes** (R4 fix) | Algebraic sigma equation `c*z_s+z_e == t+ch*d_i` enforced since `2fd44e5` |
| NIZK share-decryption | DecryptNizkProof | **Partial** | Statement-bound `expected_sk_agg_share` since `5dee0f8`; inner CycloNizkAdapter assume sound |
| BFV encryption relation | BfvSigmaProof | **Partial** (R4 fix) | Plaintext domain `|z_m_i| < t/2` enforced since `5dee0f8`; full BFV containment D.1-deferred |
| Cyclo folding | Fold accumulator | **Yes** (conditional) | `verify_fold()` recomputes accumulator deterministically; soundness conditional on P1/P2 |
| Sonobe compressor | Compressed proof | **Yes** | Dual verification path (in-process + external re-parse from bytes) |
| Aggregate decrypt | Plaintext | **Partial** (C7 prototype) | Sonobe C7DecryptAggregationCircuit (N=8 prototype via Nova IVC; Phase 2 N=8192 off-circuit Merkle verification complete; Phase 3 in-circuit Merkle verification with real Poseidon R1CS (`poseidon_gadget.rs`, ~900 constraints per hash8)). Complementary Noir aggregator_final path exists (N=8, standalone verification). |
| On-chain verify | UltraHonk proof | **No** (not run by demo) | Requires separate `bench-comparison` invocation |

Key R4 improvements:
- **Sigma equation**: `verify_algebraic_relation` now verifies `c*z_s+z_e == t+ch*d_i` (was missing, now identical to `sigma.rs:220-233`).
- **BFV plaintext domain**: `bfv_sigma::verify` checks `|z_m_i| < t/2` (was only checking masking bound).
- **Dealer identity binding**: `dealer_index` derived from session context, no longer hardcoded 0.
- See `.sisyphus/plans/round4-deep-audit-remediation.md` for full audit findings and remediation details.

### Implementation State

The current implementation uses Sonobe substitution for the folding and compression layers:
- **P1**: Lattice NIZK well-formedness soundness (conditional, see `SECURITY.md`). D.2 batched share-encryption proof covers sk+esm tracks with independent commitments; D.3 domain separation prevents cross-track replay.
- **P2**: LatticeFold+ folding substituted by off-chain Sonobe. E.1/E.2 pipeline verifier wiring covers batched Shamir share-computation and DKG aggregation relations.
- **P3**: MicroNova SNARK compression substituted by off-chain Sonobe + on-chain commitment topology. G.1 aggregator_final Noir circuit (N=8, 8 adversarial tests pass) verifies Lagrange recombination of decryption shares.
- **C6**: CommittedSmudge mode enforces DKG-bound smudging; F.2 smudge-slot freshness enforced via public SlotRegistry.
- **C7**: Sonobe C7DecryptAggregationCircuit (N=8 via Nova IVC, P1.3-P1.5) folds per-participant Lagrange recombination into Nova accumulator. Complementary Noir aggregator_final path (N=8) provides standalone verification. Phase 2 N=8192 off-circuit Merkle verification complete (8-ary Keccak256 Merkle tree, 9 RED tests pass). Phase 3 C7MerkleStepCircuit adds in-circuit Merkle verification with Poseidon placeholder (linear-combination check); Phase B: Real Poseidon R1CS in-circuit. `C7MerkleStepCircuit` at depth-5 (N=8192) uses real Poseidon hashing (~900 constraints per hash8).

### End-to-End Verifiability Chain

This section documents which verification steps in the pipeline are publicly verifiable
(i.e., can be checked by a third party with only public data) versus prover-internal.

#### Publicly Verifiable Today

| Step | Verifier | Input | Wired in Pipeline? |
|------|----------|-------|--------------------|
| Share-encryption NIZK | `RealNizkAdapter::verify` | Public statement + ZK proof | ✅ Yes (in-process) |
| Cyclo fold accumulator | `fold::verify_fold` | Public accumulator + instances | ✅ Yes (in-process) |
| Sonobe compressor | `Compressor::verify` | Public compressed proof + fold report | ✅ Yes (in-process) |
| Decrypt NIZK | `DecryptNizkVerifier::verify` | Public statement + ZK proof | ✅ Yes (in-process) |
| Aggregate key binding | `aggregate_pk == aggregate_key` | Public key bytes | ✅ Yes (in-process) |
| Plaintext roundtrip | `plaintext_compare_exact` | Original + decrypted plaintext | ✅ Yes (in-process) |

**Note on "in-process"**: All verifications currently run inside `run_full_pipeline()` —
the same process that generates the data. There is no standalone verifier binary that
reads serialized public artifacts and runs only verification. A `--verify-only` mode
is planned (see `crates/pvthfhe-cli/src/main.rs` — `Commands::Verify`).

#### Not Yet Wired (Verifiers Exist, Not Called)

| Step | Verifier | Public-Input-Only? |
|------|----------|--------------------|
| On-chain Solidity verification | `contracts/` UltraHonk verifier | ✅ Yes |

These verifiers exist and accept only public inputs, but are not called from
`run_full_pipeline()`. Wiring them is planned as optional feature-gated additions (Batch D.2).

#### NOT Verifiable (Prover-Only)

| Aspect | Why |
|--------|-----|
| BFV encryption witness correctness | The NIZK proves over secret key material; the verifier cannot check the encryption was correct — only that the proof is well-formed relative to the public statement. |
| Demo-derived error polynomials (F10) | NIZK witnesses use `derive_demo_error_poly` modulo-3 mapping, not real BFV encryption error from `encrypt_with_witness()`. |

#### Architectural Improvements (R4 Audit)

- **F1 — Sigma equation check** (Batch A): `verify_algebraic_relation` now checks
  `c*z_s + z_e == t + ch*d_i (mod Q)`, closing a gap where forged proofs were accepted.
  Previously, the function checked challenge derivation and norm bounds but omitted the
  core sigma equation, making share-encryption algebraic proofs completely unsound.
- **F4 — Dealer identity binding** (Batch B): `dealer_index` is now derived
  cryptographically from the session ID and bound into all NIZK statements and share
  commitments, preventing cross-session share replay by malicious dealers.

### Folding and On-Chain Status

This section documents the current implementation status of the folding and on-chain
verification layers. Track A (Sonobe hash-then-fold) is DEPRECATED. Track B (norm enforcement,
tree-based C7, on-chain UltraHonk) is the default production path.

| Component | Track | Status | Details |
|-----------|-------|--------|---------|
| **P2 — LatticeFold+** | B | Research-blocked | Depends on unresolved Lemma 9 / Cyclo RLWE folding theorem. No implementation exists; Sonobe Nova substitutes in Track B. |
| **P3 — MicroNova** | B | Deferred | Target architecture only. Sonobe Nova IVC with CycloFoldStepCircuit substitutes in Track B (see `spec-real-p2p3.md` §5.1). |
| **Sonobe Nova norm-enforced** | B | Benchmarkable | G7b norm enforcement with state_len=7, z_s_sq_acc/z_e_sq_acc accumulators. Phase timings (`cyclo_fold`, `compressor_prove`, `compressor_verify`) are populated in the benchmark pipeline. |
| **Noir aggregator_final circuit** | B | Benchmark-gated | Noir circuit (`circuits/aggregator_final`) runs the canonical nargo+bb flow when `PVTHFHE_RUN_NOIR_CIRCUIT=1` is set. Phase timing is recorded in `e2e_timings.json`. Uses MAX_PARTICIPANTS=128. |
| **On-chain verifier** | B | Compiles, not run | The Solidity UltraHonk verifier compiles (`contracts/`) but is not invoked during the demo. The `onchain_verify` phase in the benchmark is a timing-only marker. A separate `bench-comparison` invocation is required for on-chain verification measurement. |
| **Track A — Sonobe hash-then-fold** | A | DEPRECATED | The original Track A path (hash-accumulate compression, ecrecover attestation) is deprecated. All new development targets Track B only. |

Note: runtime `PVTHFHE_TRACK` flag: A = DEPRECATED Sonobe hash-then-fold, B = norm-enforced production path (default).

#### Track Summary

- **Track A (DEPRECATED)**: Sonobe Nova folding + hash-accumulate compression + ecrecover attestation. This track is deprecated and no longer the target path.
- **Track B (Default Production)**: Norm-enforced Sonobe Nova folding + tree-based C7 verification + Noir UltraHonk circuit proofs + on-chain UltraHonk. This is the sole production path. All new development targets Track B only.

The migration from Track A to Track B is complete: the pipeline uses G7b norm enforcement,
tree-based CompressionTree (Poseidon R1CS), and on-chain UltraHonk as the sole production path.

## Track Selection

The end-to-end demo (`just demo-e2e`) supports two architectural tracks, selected at
runtime via the `PVTHFHE_TRACK` environment variable:

- **Default: Track B — norm-enforced Sonobe Nova path with tree-based C7 and on-chain
  UltraHonk. This is the sole production path.** Activated by default or with
  `PVTHFHE_TRACK=B`.
- **Track A (DEPRECATED — Sonobe Nova/hash-then-fold)** — the deprecated Track A
  path with hash-accumulate compression. Retained only for legacy comparison.
  Activated with `PVTHFHE_TRACK=A` or `just demo-e2e-track-a`.
- Track B is the default and recommended path. Track A passes `just demo-e2e` for
  legacy validation only.

## MicroNova Heterogeneous IVC

PVTHFHE_COMPRESSOR=micronova enables heterogeneous incremental
verifiable computation. Different step circuits handle different tree
levels (leaf ring-equation verifier vs internal fold verifier).

Same SonobeCompressor handles the full tree via
HeterogeneousStepCircuit<LatticeFoldTreeCircuitFamily>.

See `.sisyphus/plans/micronova-heterogeneous-ivc.md` for full design.

### Tree-Based C7 Verification

The primary C7 verification path uses a tree-based CompressionTree (Poseidon R1CS)
rather than flat Nova folding:

- **Leaf nodes**: `state += share_eval * lagrange_coeff` — each leaf accumulates one
  Lagrange-weighted decryption share evaluation into the running state.
- **Internal nodes**: `parent = Poseidon(left, right)` — Poseidon R1CS hashing
  (~900 constraints per hash8) combines child accumulators up the tree.
- **Depth**: configurable; depth-5 supports N=8192 participants.
- **Circuit**: `C7MerkleStepCircuit` implements the full tree step in R1CS, providing
  in-circuit verifiable C7 aggregation.

This replaces the Phase 2 off-circuit Merkle verification with fully constrained
in-circuit Merkle proofs.

### Nova Commitment Scheme: KZG

The Sonobe Nova IVC compressor uses `KZG<'static, Bn254>` for main-curve commitments (CS1)
and `Pedersen<G2>` for CycleFold-curve commitments (CS2). This enables Sonobe's `DeciderEth`
Groth16 SNARK wrapping for on-chain IVC verification.

- **Switch**: `Pedersen<G1>` → `KZG<'static, Bn254>` (rev `63f2930d`). The `'static` lifetime
  is valid because `KZG::setup` uses `Cow::Owned` (fully-owned SRS).
- **KZG trusted setup**: Generated at runtime via `KZG::<Bn254>::setup(rng, 1 << 17)`.
  The file `bench/srs/bn254.srs` is a text-only stub (52 bytes). Production requires a
  real MPC ceremony output.
- **SNARK bridge**: `snark_bridge.rs` provides `wrap_nova_instance()` (feature-gated on
  `sonobe-snark`) and `serialize_wrapped_proof()` for the extended `CompressedProof` format.
- **Proof format**: Extended with optional SNARK trailer: `[snark_len: u32 BE][snark_bytes]`.
  `parse_proof()` handles both v1 (76+ivc_len) and v2 (80+ivc_len+snark_len) formats.
- **Noir circuit**: `sonobe_state_commitment` is dual-mode: `ivc_snark_proof_hash == 0` uses
  legacy Poseidon hash preimage; `!= 0` uses Poseidon binding of all 6 public inputs.
- **Dependency**: `ark-groth16` (optional, gated behind `sonobe-snark` feature).

### Per-Node / Per-Aggregator Scaling

Scaling simulation binaries (`pvthfhe-per-node`, `pvthfhe-per-aggregator`) benchmark
per-party and per-aggregator costs across participant counts (N=128 to 8192). These
binaries validate the O(n) per-party / O(polylog n) verifier cost targets:

- `pvthfhe-per-node`: measures per-party DKG, NIZK proving, and partial decryption costs.
- `pvthfhe-per-aggregator`: measures aggregator folding, compression, and on-chain
  verification costs.

Results are published under `bench/results/`. See `REPRODUCING.md` for run instructions.

### Performance Ceiling

demo-e2e completes for n ≤ 128. At n ≥ 150, setup_threshold (O(n²·degree) Shamir share generation) dominates wall time and exceeds practical demo budgets. See fhers.rs:331 compute_party_sk_sums.
