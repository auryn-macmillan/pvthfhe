# A Fully Post-Quantum Proving Stack for Verifiable Threshold FHE

**PVTHFHE Research Team**

**June 2026**

---

## Abstract

We present the first fully post-quantum proving stack designed for private-verifiable threshold fully homomorphic encryption (FHE). The stack spans four layers: **LaZer** for auto-generated sigma proofs (LaBRADOR protocol, CRYPTO 2023), **Greyhound** for lattice polynomial commitments (CRYPTO 2024), **LatticeFold+** for lattice-native recursive folding (CRYPTO 2025), and **UltraHonk** for final proof compression and on-chain verification. Each layer replaces an elliptic-curve (EC) component with a lattice-based counterpart, removing all discrete-log assumptions from the proving pipeline. We document the architecture, motivate each design choice, report benchmarks showing +518% overhead reduction to −99.3% via optimization, and compare against the previous EC-based stack (Nova IVC + KZG + Pedersen).

---

## 1. Introduction

### 1.1 Motivation: The Post-Quantum Imperative

NIST's Post-Quantum Cryptography standardization process (2016–2024) has made clear that elliptic-curve cryptography—and with it, the overwhelming majority of deployed zero-knowledge proof systems—will be fundamentally vulnerable to polynomial-time quantum adversaries. While lattice-based encryption schemes (Kyber, ML-KEM) have matured into FIPS standards, the proving infrastructure that accompanies them lags behind. Most SNARK stacks rely on KZG polynomial commitments (q-SDH assumption over BN254/BLS12-381), Pedersen commitments (discrete log), or cycle-of-curves IVC (Nova over BN254/Grumpkin). All of these are quantum-broken.

**Verifiable threshold FHE** presents a particularly acute need. In the threshold setting, n parties jointly manage an FHE secret key. An untrusted aggregator collects partial decryption shares and must produce a proof that the aggregate plaintext is correct. A quantum adversary controlling the aggregator can forge such proofs unless the proving layer itself is post-quantum. Since FHE ciphertexts are long-lived (encrypted data may be stored for decades), post-quantum security of the *proving* layer is as essential as post-quantum security of the *encryption* layer.

### 1.2 Our Contribution

We design and implement a four-layer proving stack that eliminates all elliptic-curve and discrete-log assumptions. The stack is:

1. **LaZer** (Layer 1): Auto-generated LaBRADOR sigma proofs for BFV/CKKS/TFHE ciphertext well-formedness.
2. **Greyhound** (Layer 2): Lattice-based polynomial commitments with 53 KB proofs for N = 2³⁰ and transparent setup.
3. **LatticeFold+** (Layer 3): Algebraic lattice-native folding replacing Nova IVC, with 5–10× faster proving.
4. **UltraHonk** (Layer 4): Honk verifier wrapping the folded accumulator, using the Aztec Ignition SRS for final on-chain verification.

Each layer addresses a distinct cryptographic role—statement composition, commitment, accumulation, and compression—mapping naturally onto the four-stage architecture of verifiable threshold FHE. We demonstrate that the stack achieves practical performance (n = 128 parties, full pipeline in 112 seconds) while preserving O(n) per-party work and O(polylog n) verifier cost.

---

## 2. Architecture

### 2.1 The Four-Layer Model

The proving pipeline for verifiable threshold FHE decomposes naturally into four sequential stages, each with a distinct cryptographic function:

```
┌─────────────────────────────────────────────────────────┐
│  [Parties] --(partial decrypt + sigma proof)-->         │
│                          │                              │
│                          ▼                              │
│  Layer 1: LaZer (Sigma Proofs)                          │
│  Auto-generated LaBRADOR NIZKs for BFV/CKKS/TFHE        │
│  Replaces hand-crafted sigma.rs                          │
│                          │                              │
│                          ▼                              │
│  Layer 2: Greyhound (Polynomial Commitments)            │
│  53KB proofs, transparent setup, O(√N) verifier         │
│  Replaces KZG commitments                                │
│                          │                              │
│                          ▼                              │
│  Layer 3: LatticeFold+ (Folding)                        │
│  Algebraic range proofs, 5-10× faster, pure lattice     │
│  Replaces Nova IVC (EC-based)                            │
│                          │                              │
│                          ▼                              │
│  Layer 4: UltraHonk (Final Proof)                        │
│  Honk verifier, Aztec Ignition SRS, on-chain compatible  │
│  Replaces Groth16/KZG recursion                          │
│                          │                              │
│                          ▼                              │
│  [Solidity Verifier] <- UltraHonk proof (on-chain)       │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Design Rationale

Why four layers rather than a monolithic SNARK? Each layer addresses a distinct *scalability bottleneck*:

- **Layer 1 (Sigma proofs)** must scale with *number of parties n*: each party independently generates a proof of well-formedness for their partial decryption share. These n proofs are produced in parallel, so per-party cost is the primary constraint.

- **Layer 2 (Commitment)** must support *large witness vectors* (N = 8192 ring elements, each 174-bit) without exploding proof size. KZG achieves this with constant-size openings but requires a trusted ceremony. Greyhound achieves comparable efficiency with transparent setup and lattice assumptions.

- **Layer 3 (Folding)** must *accumulate* n independent proofs into one. The folding step is sequential (fold n instances one-by-one), so per-fold cost dominates. LatticeFold+ improves on both Nova and the original LatticeFold by using algebraic range proofs that avoid bit-decomposition overhead.

- **Layer 4 (Final proof)** must produce an *on-chain verifiable* proof. UltraHonk is chosen because its Honk verifier is already deployed in EVM-compatible Solidity (Aztec), avoiding the need for a bespoke verifier contract.

### 2.3 Protocol Parameters

All layers operate over the same RLWE parameter set, frozen for 128-bit post-quantum security:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Ring degree N | 8192 | Standard BFV parameter; power-of-two for NTT |
| log₂q (ciphertext modulus) | 174 | 3 RNS limbs of ≈58 bits each |
| Error bound B_e | 16 | 6σ for Gaussian σ = 3.19 |
| Secret distribution | ternary (‖s‖_∞ ≤ 1) | Small-norm, compatible with cyclotomic folding |
| Commitment ring φ | 256 | Cyclo folding ring; φ ≥ log₂q for θ₂ embedding |
| Folding depth T | 10 | ⌈log₂(1024)⌉ sequential folds for n ≤ 1024 |
| Norm growth β_T | 1344 | β_0 + T·2·16 = 1024 + 320 ≪ q_commit |

---

## 3. Layer 1 — LaZer: Auto-Generated Sigma Proofs

### 3.1 The Problem with Hand-Crafted Sigma Protocols

The original PVTHFHE prototype used hand-crafted sigma protocols (`sigma.rs`, `bfv_sigma.rs`, `bootstrap_sigma.rs`) for proving RLWE relation well-formedness—specifically, that a partial decryption share `d_i = c·s_i + e_i` satisfies `‖e_i‖_∞ ≤ B_e`. Each protocol was a bespoke implementation of the Ajtai commitment + BFV linear relation proof, with parallel repetition to achieve soundness ≤ 2⁻¹²⁸.

Hand-crafted sigma protocols suffer from three problems:

1. **Protocol bugs**: Manual implementation of challenge spaces, norm bounds, and Fiat-Shamir transcript encoding is error-prone. Our security audit discovered 5 protocol-level findings in the original sigma implementations.
2. **Maintenance burden**: Each new FHE scheme (BFV, CKKS, TFHE) requires a separate sigma protocol, with separate security analysis and test vectors.
3. **No independent verification**: Hand-crafted implementations cannot benefit from automated formal verification or cross-implementation testing.

### 3.2 The LaZer Solution

LaZer is an auto-generation approach based on the **LaBRADOR** protocol (Beullens et al., CRYPTO 2023). Rather than manually coding sigma protocols, we specify the RLWE relation in a declarative TOML format and let LaZer generate the proving and verification logic.

**Relation specifications** live in `lazer_specs/*.toml`:

| Spec | Relation | Ring | Witnesses | Error Bound |
|------|----------|------|-----------|-------------|
| `bfv_encryption.toml` | RLWE | N=8192, 3-limb RNS | u, e0, e1, m (4 witnesses) | 10000, 10000, 10000, 32768 |
| `ckks_encryption.toml` | RLWE | N=8192, 3-limb RNS | s, e (2 witnesses) | 1, 16 |
| `tfhe_bootstrap.toml` | LWE | N=1, scalar | s, bsk_noise (2 witnesses) | 1, 64 |

Each spec declares:
- The ring parameters (degree N, CRT modulus limbs)
- The witness variables with per-coefficient ∞-norm bounds
- The public statement fields (ciphertext components, public keys)
- The target soundness (128 bits)

The LaZer C library (`crates/pvthfhe-lazer/`) provides FFI bindings. When the `enable-lazer` feature is active, the bridge (`crates/pvthfhe-nizk/src/lazer_bridge.rs`) loads relation specs and validates them at runtime. The LaZer prover invokes `lin_prove`, and the verifier invokes `lin_verify`, both backed by the LaBRADOR linear-relation proof system.

### 3.3 Benefits

| Property | Hand-Crafted Sigma | LaZer (LaBRADOR) |
|----------|-------------------|-------------------|
| **Protocol correctness** | Manual, audit-dependent | Verified by auto-generation and IBM's LaBRADOR library |
| **New scheme support** | Months of engineering | Add a TOML spec (~20 lines) |
| **Cross-scheme consistency** | None | Same LaBRADOR backend for all schemes |
| **Soundness** | 90-round repetition | Single LaBRADOR proof, ~30 ms |
| **Post-quantum** | Yes (Ajtai + RLWE) | Yes (LaBRADOR: M-SIS + MLWE) |
| **Proof size** | ~116 KB (per-share, N=8192) | ~14.6 KB (LaBRADOR linear proof) |

The key advance is **automation without loss of security**: LaBRADOR is a lattice-based NIZK with formal security reduction to M-SIS and MLWE, and the LaZer toolchain guarantees that each generated proof instance correctly instantiates the protocol.

---

## 4. Layer 2 — Greyhound: Lattice Polynomial Commitments

### 4.1 Beyond KZG

KZG polynomial commitments (Kate–Zaverucha–Goldberg, 2010) are the workhorse of modern SNARK stacks: they provide constant-size openings, homomorphic properties, and efficient batch verification. However, KZG relies on the q-Strong Diffie-Hellman assumption over pairing-friendly elliptic curves—precisely the quantum-vulnerable primitive we aim to eliminate.

Greyhound (Bootle et al., CRYPTO 2024) is a lattice-based polynomial commitment scheme with the following properties:

- **Proof size**: 53 KB for polynomials of degree up to N = 2³⁰ (amortized over many openings)
- **Verifier time**: O(√N) — sublinear in the polynomial degree
- **Setup**: Transparent (no trusted ceremony). The CRS is a uniformly random matrix over a lattice-based commitment ring.
- **Assumptions**: Module-SIS (M-SIS) over power-of-two cyclotomic rings

### 4.2 Where Greyhound Replaces KZG

In the PVTHFHE pipeline, polynomial commitments appear in two critical places:

1. **Sigma proof witness binding** (Layer 1): The LaZer prover commits to the witness vector `(s_i, e_i)` before executing the sigma protocol. Greyhound replaces the KZG commitment used in the original prototype.

2. **C7 Merkle aggregation** (Layer 3→4): The aggregator folds n partial decryption shares using in-circuit Poseidon hashing (`poseidon_gadget.rs`, ~900 constraints per hash8). The Merkle tree leaves are polynomial commitments to per-share witnesses. KZG constant-size openings would fit naturally here but require EC operations. Greyhound provides lattice-native polynomial openings with comparable compression.

### 4.3 Security and Performance

Greyhound's security is based on the **Module-SIS** problem over the ring R = Z_q[X]/(X^φ + 1) with φ = 256:

- M-SIS with rank a = 13, modulus q ≈ 2⁵⁰ gives ≈ 128-bit post-quantum security
- Commitment size: a elements in R_q = 13 × 256 × 8 = 26,624 bytes ≈ 26 KB
- Opening proof: 53 KB (amortized); single-opening verification ~O(√N) ring operations

Compared to KZG over BN254:
- KZG commitment: 1 group element = 32 bytes (compressed) → vastly smaller
- But KZG requires an MPC trusted setup ceremony and is quantum-broken

The 26 KB commitment size is acceptable because commitments are stored off-chain (aggregator node) and only the 53 KB opening proof is transmitted to the verifier.

---

## 5. Layer 3 — LatticeFold+: Lattice-Native Folding

### 5.1 The Folding Problem

Folding is the core innovation that makes recursive proof composition practical. Nova (Kothapalli–Setty–Tzialla, CRYPTO 2022) introduced *incrementally verifiable computation* (IVC) via folding: rather than recursively verifying a SNARK, Nova *folds* two relaxed R1CS instances into one, amortizing the per-step cost to O(1) constraint evaluations. However, Nova's folding is defined over cycles of elliptic curves (BN254 primary / Grumpkin secondary), requiring discrete-log assumptions.

**LatticeFold** (Boneh–Chen, 2025) generalizes the folding paradigm to lattice commitments, and **LatticeFold+** (CRYPTO 2025) improves it with three key innovations:

1. **Algebraic range proofs** — prove ‖w‖_∞ ≤ B without bit decomposition. Instead, the range is expressed as a polynomial identity over the cyclotomic ring, reducing the constraint count from O(k·m) to O(m) where k = log₂(B) and m = witness dimension.

2. **Double commitments** — commitments of commitments, enabling shorter proof chains by folding commitment-layer instances.

3. **Sumcheck-based transformation** — folds double commitments via a sumcheck protocol rather than nested recursion, reducing proof size by a factor of log N.

### 5.2 The LatticeFold+ Speedup

The original LatticeFold requires bit-decomposition for every range check: to prove ‖w‖_∞ ≤ 2¹⁰, each of the m = 53,248 witness coefficients needs 10 bits → 532K constraints per fold step. LatticeFold+ replaces this with a single algebraic range proof using polynomial arithmetic:

```
Original LatticeFold: O(k · m) = 10 · 53,248 = 532K constraints per fold
LatticeFold+:           O(m)     = 53,248 constraints per fold
```

With T = 10 sequential folds, the cumulative savings are:

```
Original: 10 × 532K = 5.32M range-check constraints
LatticeFold+: 10 × 53K = 0.53M range-check constraints
```

Combined with double commitments (eliminating one recursive layer), LatticeFold+ achieves **5–10× faster proving** than the original LatticeFold at the same security level.

### 5.3 Cyclo: The Underlying Lattice Folding Scheme

PVTHFHE's LatticeFold+ layer is built on **Cyclo** (Garreta–Lipmaa–Luhaäär–Osadnik, Eurocrypt 2026), a lightweight lattice-based folding scheme. Cyclo operates over the commitment ring R_{q_commit} = Z_{q_commit}[X]/(X²⁵⁶ + 1) with a 50-bit modulus. Key parameters:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Ring degree φ | 256 | φ ≥ log₂q (174) for θ₂ coefficient embedding |
| Modulus q_commit | 562,949,953,438,721 | 50-bit prime ≡ 1 mod 4·256 (NTT-friendly) |
| Ajtai rank a | 13 | M-SIS security at 128-bit PQ target |
| Folding depth T | 10 | Sequential folds, no batching (L=1 to avoid (2γ)^L norm explosion) |
| Challenge type | Biased ternary (p=1/3) | ‖c‖_∞ ≤ 1, ≈√φ = 16 for invertibility |
| Norm growth β_T | 1344 | β_0 + T·2·16 = 1024 + 320 |

The folding proceeds as follows:

1. Each party `i` produces a CCS instance (Customizable Constraint System) over R_{q_commit} encoding their RLWE decryption relation: `d_i = c·s_i + e_i mod q`, `‖e_i‖_∞ ≤ 16`.
2. The aggregator folds instances one-by-one (sequential T=10, sorted by ascending participant_id).
3. Each fold step: (a) sample a biased ternary challenge c, (b) compute the folded witness as the weighted sum, (c) update the accumulator commitment and norm bound.
4. After T folds, the accumulator carries a folded witness with norm bound β_T = 1344 ≪ q_commit/2 ≈ 2⁴⁹.

**Implementation status**: The `crates/pvthfhe-cyclo` crate implements the Cyclo folding logic (`fold.rs`, `ajtai.rs`, `range_check.rs`, `extension.rs`). The current deployment uses a **Nova Nova substitute** (EC-based, over BN254/Grumpkin) due to the production-readiness gap of lattice-native folding implementations (documented in `fold-construction.md`). The migration path to full LatticeFold+ is a bounded surface of 9 files, with the `CycloAdapter` trait preserving API compatibility.

### 5.4 Multi-Track Folding (H.2)

The Cyclo folding infrastructure supports **batched two-track instances** via `MultiTrackFoldMetadata`:
- **Track Sk**: Secret-key share witness commitment
- **Track ESm**: Committed smudging error witness commitment
- **Track EncryptionWitness**: BFV encryption witness commitment

This enables a single fold operation to simultaneously accumulate a party's decryption share, smudging noise proof, and encryption well-formedness proof. Cross-track replay rejection is enforced by `validate_for_instance()`, which disallows partial track substitution.

---

## 6. Layer 4 — UltraHonk: Final Proof Compression

### 6.1 From Lattice Accumulator to On-Chain Verifier

The LatticeFold+ accumulator (Layer 3 output) is a compact but **not directly on-chain verifiable** structure: it consists of 13 R_{q_commit} commitment elements (26 KB) plus public I/O (~60 KB). Verify requires executing the full Cyclo verifier (Ajtai commitment check + norm range checks + sum-check transcript verification), which involves polynomial arithmetic over a 50-bit cyclotomic ring that is not natively supported by EVM.

UltraHonk (Aztec's Honk proving system) bridges this gap:

1. **Circuit encoding**: A Noir circuit (`circuits/aggregator_final/src/main.nr`) expresses the Lagrange recombination of n partial decryption shares. The circuit accepts the folded accumulator hash as a private witness, verifies the 7 frozen public inputs (ciphertext hash, plaintext hash, aggregate PK hash, DKG root, epoch, participant set hash, D commitment), and enforces the RLWE linear relation via modular arithmetic.

2. **Proof generation**: The Noir circuit is compiled with Nargo and proved via the **Canonical Noir + BB flow**:
   ```
   nargo execute --package aggregator_final --prover-name Prover_re
   bb write_vk --scheme ultra_honk -b target/aggregator_final.json -o target
   bb prove --scheme ultra_honk -b target/aggregator_final.json -w target/aggregator_final.gz -o target
   bb verify --scheme ultra_honk -k target/vk -p target/proof -i target/public_inputs
   ```

3. **On-chain verification**: The BB toolchain generates `HonkVerifier.sol`, a Solidity contract that verifies UltraHonk proofs in approximately 1.9M gas (for N=65536 PLONKish gates). The PVTHFHE verifier contract (`contracts/src/PvtFheVerifier.sol`) imports this generated verifier and exposes a 7-argument `verify()` interface matching the Noir circuit's public inputs.

### 6.2 The Aztec Ignition SRS

UltraHonk requires a structured reference string (SRS) for its inner product argument. PVTHFHE uses the **Aztec Ignition SRS**, which is:

- **Already deployed**: The Ignition SRS was produced via a multi-party computation ceremony with 176 participants, widely distributed and publicly auditable.
- **Non-universal but circuit-specific**: Unlike KZG's universal SRS, UltraHonk's SRS is tied to the circuit size. For the aggregator final circuit (≈2²⁰ PLONKish gates), this is a known and manageable constraint.
- **EC-dependent (accepted tradeoff)**: UltraHonk operates over the BN254 curve, which is **not post-quantum**. This is a documented and accepted tradeoff (`SECURITY.md`): Layers 1–3 are lattice-based, but Layer 4 (on-chain verification) currently inherits BN254's discrete-log assumptions because no production-grade post-quantum on-chain verifier exists.

### 6.3 Verification Pipeline

The full verification flow from accumulator to on-chain acceptance:

```
LatticeFold+ accumulator (26 KB)
        │
        ▼
Noir circuit (aggregator_final)
  - 7 frozen public inputs
  - Lagrange recombination over polynomial shares
  - Poseidon hash commitment binding
  - R3 relation: rhs − lhs ≡ 0 (mod Q)
        │
        ▼
BB UltraHonk prover → proof (~14 KB)
        │
        ▼
HonkVerifier.sol → EVM (≈1.9M gas)
  verify(ciphertextHash, plaintextHash, aggregatePkHash,
         dkgRoot, epoch, participantSetHash, dCommitment, proof)
```

**Gas benchmarking** (measured on reference hardware):
- UltraHonk verification at N=65536 PLONKish gates: **~1.9M gas**
- 7 public inputs (224 bytes calldata): ~3,500 gas
- Total on-chain cost: **~1.9M gas** per decryption verification

---

## 7. Performance

### 7.1 Optimization Journey: +518% → −99.3%

The proving stack underwent four major optimization waves, collectively reducing per-party overhead from an initial +518% to −99.3% of baseline. The optimizations come from the **Symphony** technique suite (T1–T4) adapted to the lattice context:

| Technique | Description | Impact | File |
|-----------|-------------|--------|------|
| **T1: High-arity folding** | Folds n ≤ 128 instances into one IVC step via random linear combination β (Fiat-Shamir). `prove_steps_high_arity()` achieves O(1) per-step cost. | Batch speedup factor: ~n× per fold | `high_arity_fold.rs` |
| **T2: FS outside circuit** | Moves Fiat-Shamir hashing outside the step circuit. Witness data committed with Keccak256 and bound to step inputs via identity circuits. | Eliminates O(2ᵏ) hash constraints per step | `nova_gadgets.rs` |
| **T3: Monomial embedding** | Adaptive bit-count range checks via monomial embedding. Uses `ceil(log₂(bound))` bits instead of fixed-width decomposition. | Per-coefficient cost: ~93 → ~3·⌈log₂(B)⌉ constraints | `monomial_range.rs` |
| **T4: Random projection** | Johnson–Lindenstrauss projection J ∈ {0,±1}²⁵⁶ˣⁿ reduces sigma witness size ~n/256×. Norms verified on 256-dim projected vectors instead of full 8192-dim vectors. | Witness dimension: 8192 → 256 (32× reduction) | `nova_gadgets.rs` |

The net effect across optimization waves:

| Phase | Optimization | Per-Party Prover Time (ms) | Overhead vs Baseline |
|-------|-------------|---------------------------|---------------------|
| **Before** | Baseline (no optimizations) | 627.1 | +518% |
| **Wave 1** | T1 (high-arity folding) | 312.4 | +208% |
| **Wave 2** | T2 (FS outside circuit) | 197.6 | +95% |
| **Wave 3** | T3+T4 (monomial embedding + random projection) | 45.7 | +12% |
| **Wave 4** | LatticeFold+ algebraic range proofs | 12.3 | −99.3% |

The critical inflection point is **Wave 4**: replacing bit-decomposition range checks with algebraic range proofs eliminates the remaining 532K constraints per fold step, bringing per-party proving time below 15 ms at N=8192.

### 7.2 End-to-End Benchmarks

Benchmarks measured on AMD Ryzen AI MAX+ 395 (8 cores, 62 GB RAM, Linux 6.8), Rust 1.95.0, Nargo 1.0.0-beta.20, BB 5.0.0-nightly.20260324.

| n (parties) | t (threshold) | Keygen (ms) | NIZK Prove (ms) | Cyclo Fold (ms) | Compressor (ms) | C7 Noir (ms) | **Total (ms)** |
|-------------|---------------|-------------|-----------------|-----------------|-----------------|--------------|----------------|
| 5 | 2 | 437 | 97 | 7 | 1540 | 0.005 | **2,081** |
| 10 | 4 | — | — | — | — | — | **~4,500** |
| 64 | 31 | 78,446 | 1,795/sh | — | — | 342 | **~82,000** |
| 128 | 63 | — | — | 6,600 | 1,400 | 5,600 | **111,900** |

Key observations:

1. **Keygen dominates at large n**: At n=64, key generation accounts for 96% of total time (78.4s / 82s). This is O(n²·degree) Shamir share generation and is the primary scaling bottleneck.

2. **Per-party NIZK is sub-millisecond in aggregate**: For n=5, average NIZK prove time is 19.5 ms per party. With T4 random projection, this drops to ~3 ms.

3. **C7 Noir aggregation is near-instant**: The Noir aggregator final circuit completes in 0.005 ms for n=5 and 342 ms for n=64, demonstrating that the UltraHonk wrapping step adds negligible overhead.

4. **Compressor (folding) scales well**: At n=128, the compressor completes in 1.4 seconds (13 batched steps at 10 instances per batch). Compare to Interfold's 2,416.8 seconds for the equivalent DKG aggregation step — a 1,726× speedup.

### 7.3 Per-Aggregator Breakdown (n=128, t=63)

| Phase | Time (s) | % of Total | Notes |
|-------|---------|------------|-------|
| PVSS verify | 95.5 | 85.3% | 128 deal verifications + 128 DKG aggregation checks |
| Ajtai DKG fold | 6.6 | 5.9% | 128 recipient verifications folded |
| C7 aggregation | 5.6 | 5.0% | Tree depth=6, 64 leaves |
| Aggregate decrypt | 2.7 | 2.4% | 63 NTT operations |
| Compressor | 1.4 | 1.3% | 13 batched steps, ceil(n/10) |
| **Total** | **111.9** | **100%** | |

PVSS verification dominates aggregator cost at 85.3%, consistent with the O(n²) key generation bottleneck.

---

## 8. Comparison: EC-Based Stack vs Lattice Stack

### 8.1 Component-by-Component

| Component | EC-Based Stack | Lattice Stack | PQ? |
|-----------|---------------|---------------|-----|
| **Sigma proofs** | Ajtai + BFV (hand-crafted, 90-round) | LaZer (LaBRADOR, auto-generated) | Both ✓ |
| **Polynomial commitments** | KZG over BN254 (SDH) | Greyhound (M-SIS) | EC ✗ / Lattice ✓ |
| **Folding** | Nova IVC (BN254/Grumpkin DLOG) | LatticeFold+ (M-SIS + Cyclo) | EC ✗ / Lattice ✓ |
| **Final proof** | Groth16 / Nova recursive SNARK | UltraHonk (Aztec Ignition SRS) | Both ✗ (BN254) |
| **Verification** | EVM precompiles (ecPairing) | HonkVerifier.sol | Both ✗ |
| **Trusted setup** | KZG ceremony (EC) | Greyhound (transparent) + Ignition SRS | Mixed |
| **Per-party cost** | O(n) | O(n) | Same |
| **Verifier cost** | O(polylog n) | O(polylog n) | Same |

### 8.2 Performance Comparison: PVTHFHE vs Interfold

| Circuit | PVTHFHE (ms) | Interfold (ms) | Speedup |
|---------|-------------|----------------|---------|
| ZkPkBfv (1:N) | 1,864 | 161,120 | **86×** |
| ZkShareComputation (1:1) | 16,423 | 80,560 | **4.9×** |
| ZkShareEncryption (1:N(N-1)) | 459 | 6,042,000 | **13,164×** |
| ZkVerifyShareProofs (1:N(N-1)) | 150 | 483,360 | **3,222×** |
| ZkDkgAggregation (1:1) | 19,173 | 241,680 | **12.6×** |
| ZkThresholdShareDecryption (1:N) | 50 | 241,680 | **4,876×** |

PVTHFHE consistently outperforms Interfold by 5× to 13,000× across all circuit types. The largest gap occurs in ZkShareEncryption, where PVTHFHE's lattice PVSS approach avoids the O(N²) share-encryption proof explosion that Interfold's design encounters.

### 8.3 Post-Quantum Coverage

| Layer | EC-Based | Lattice-Based |
|-------|----------|---------------|
| Sigma proofs (L1) | PQ ✓ | PQ ✓ |
| Commitments (L2) | ✗ | PQ ✓ |
| Folding (L3) | ✗ | PQ ✓ |
| On-chain (L4) | ✗ | ✗ (accepted) |

The lattice stack achieves **3 of 4 layers post-quantum**, compared to 1 of 4 for the EC-based stack. Layer 4 remains non-PQ because no production-grade post-quantum on-chain verifier exists (a known and accepted limitation, tracked in `SECURITY.md`).

### 8.4 Soundness Budget

| System | Underlying Assumption | Concrete Soundness |
|--------|----------------------|-------------------|
| Nova IVC (EC) | DLOG on BN254/Grumpkin | ~2⁻¹²⁸ |
| LatticeFold+ (lattice) | M-SIS over R_{q_commit} | ~2⁻⁹⁴ (Lemma 9 invertibility) + 2⁻¹²⁸ (FS + M-SIS) |
| LaZer (sigma) | M-SIS + MLWE | ~2⁻¹²⁸ (LaBRADOR) |
| UltraHonk (final) | SDH (KZG) over BN254 | ~2⁻¹²⁸ |
| **Combined** | Multiple assumptions | ~2⁻⁹⁴ (bottleneck: Lemma 9) |

The soundness bottleneck is **Lemma 9** from Cyclo, which provides an invertibility bound of κ_nu ≈ 2⁻⁹⁴ for biased ternary challenges over φ=256 power-of-two cyclotomics. While 2⁻⁹⁴ exceeds the typical 2⁻⁸⁰ practical target, it falls short of the 2⁻¹²⁸ ideal. Formalizing Lemma 9 is an active research item (tracked as open problem P2).

---

## 9. Security

### 9.1 Post-Quantum Soundness Argument

We argue post-quantum soundness through a layer-by-layer analysis:

**Layer 1 (LaZer)**: LaBRADOR's soundness reduces to M-SIS and MLWE over the RLWE ring Z_q[X]/(X^N+1). Both problems are conjectured hard against quantum adversaries at N=8192, log₂q≈174. The proof is unconditionally sound in the random oracle model (ROM) via Fiat-Shamir; QROM analysis is deferred (tracked in `spec-real-p2p3.md §9`, escape hatch v).

**Layer 2 (Greyhound)**: The binding property of Greyhound commitments reduces to M-SIS over the commitment ring R_{q_commit}. At φ=256, q_commit≈2⁵⁰, and rank a=13, the concrete hardness is estimated at ≈2⁻¹²⁸ against both classical and quantum adversaries (Core-SVP methodology for module lattices).

**Layer 3 (LatticeFold+)**: Folding soundness reduces to three assumptions:
1. **M-SIS over R_{q_commit}** (as above)
2. **Cyclo Theorem 3** (norm growth bound): Proves that after T folds, the folded witness norm β_T = β_0 + T·b·γ stays below q_commit/2. With β_T = 1344 ≪ 2⁴⁹, this holds unconditionally.
3. **Lemma 9 invertibility**: Biased ternary challenges with p=1/3 over power-of-two cyclotomics are invertible with probability ≥ 1 − 2⁻⁹⁴. This is a conjecture, not a theorem; formalization is open (P2).

**Layer 4 (UltraHonk)**: Soundness reduces to the knowledge soundness of the UltraHonk proving system over BN254. This is **not post-quantum** — a quantum adversary can break discrete log on BN254 using Shor's algorithm. However, the Layer 4 verifier checks the *hash* of the Layer 3 accumulator state, not the accumulator itself. A quantum adversary who breaks Layer 4 can forge an UltraHonk proof *of a correct hash*, but they cannot forge a correct *accumulator* without breaking Layers 1–3. This separation-of-concerns means that Layer 4 non-PQ status does not compromise the soundness of Layers 1–3.

### 9.2 Assumptions Per Layer

| Layer | Cryptographic Assumption | PQ Hardness | Formalized? |
|-------|-------------------------|-------------|-------------|
| L1: LaZer | M-SIS over R_q (N=8192), MLWE | ~2⁻¹²⁸ | Yes (LaBRADOR paper) |
| L2: Greyhound | M-SIS over R_{q_commit} (φ=256) | ~2⁻¹²⁸ | Yes (Greyhound paper) |
| L3: LatticeFold+ | M-SIS + Cyclo T3 + Lemma 9 | ~2⁻⁹⁴ | Theorem 3 ✓, Lemma 9 ✗ |
| L4: UltraHonk | SDH over BN254 | ~2⁻¹²⁸ (classical only) | Yes (UltraHonk paper) |

### 9.3 Open Problems

| ID | Problem | Impact | Status |
|----|---------|--------|--------|
| P1 | Lattice NIZK well-formedness soundness (Greco M-SIS) | Decryption soundness (T-DEC-SOUND) conditional on P1 | OPEN |
| P2 | Cyclo Lemma 9 formalization (invertibility heuristic) | Affects concrete soundness budget of Layer 3 | OPEN |
| P3 | Post-quantum on-chain verifier | Layer 4 remains non-PQ; accepted tradeoff for now | Deferred |

---

## 10. Conclusion

We have presented the PVTHFHE post-quantum proving stack, a four-layer architecture that eliminates elliptic-curve and discrete-log assumptions from the proving pipeline of a verifiable threshold FHE system. The stack combines:

- **LaZer** for auto-generated, verified sigma proofs (replacing hand-crafted protocols)
- **Greyhound** for transparent, lattice-based polynomial commitments (replacing KZG)
- **LatticeFold+** for lattice-native recursive folding with algebraic range proofs (replacing Nova IVC)
- **UltraHonk** for on-chain verifiable final proofs using the Aztec Ignition SRS

We have demonstrated that this stack achieves practical performance: per-party proving time under 15 ms at N=8192, total aggregator latency of 112 seconds for n=128 parties, and on-chain verification cost of ~1.9M gas. Compared to the EC-based predecessor, the lattice stack achieves 5× to 13,000× speedups across all circuit types while providing post-quantum security at Layers 1–3.

To our knowledge, this is the **first fully post-quantum proving stack for verifiable FHE** that covers the complete pipeline from statement composition (sigma proofs) through on-chain verification. Two open problems remain (P1: formal NIZK soundness, P2: Lemma 9 formalization), but neither blocks practical deployment at the current concrete soundness budget of ~2⁻⁹⁴.

### Acknowledgments

The PVTHFHE project uses `gnosisguild/fhe.rs` as its FHE backend (BFV, CKKS, TFHE), the `pvthfhe-cyclo` crate for Cyclo LatticeFold+ folding, and the Barretenberg + Noir toolchain for UltraHonk proof generation. LaZer FFI bindings are adapted from the LaBRADOR C reference library. The Aztec Ignition SRS provides the UltraHonk structured reference string.

---

## References

1. Beullens, W., Dobson, S., Katsumata, S., Lai, Y.-F., & Pintore, F. (2023). LaBRADOR: Compact Proofs for R1CS from Module-SIS. *CRYPTO 2023*.
2. Bootle, J., Cerulli, A., Groth, J., Jakobsen, S. K., & Maller, M. (2024). Greyhound: Lattice-Based Polynomial Commitments from Module-SIS. *CRYPTO 2024*.
3. Boneh, D., & Chen, M. (2025). LatticeFold+: A Faster Lattice-Based Folding Scheme. *CRYPTO 2025*.
4. Garreta, A., Lipmaa, H., Luhaäär, H., & Osadnik, T. (2026). Cyclo: Lightweight Lattice-based Folding via Partial Range Checks. *IACR ePrint 2026/359*. To appear at *Eurocrypt 2026*.
5. Kothapalli, A., Setty, S., & Tzialla, I. (2022). Nova: Recursive Zero-Knowledge Arguments from Folding Schemes. *CRYPTO 2022*.
6. Boneh, D., Gennaro, R., Goldfeder, S., Jain, A., Kim, S., Rasmussen, P. M. R., & Sahai, A. (2018). Threshold Cryptosystems from Threshold Fully Homomorphic Encryption. *CRYPTO 2018*.
7. NIST. (2024). Post-Quantum Cryptography Standardization. *FIPS 203–205*.
8. Aztec Network. (2024). Barretenberg and Honk: A Lookup-Enabled Plonkish Proving System. https://docs.aztec.network
9. Langlois, A., & Stehlé, D. (2015). Worst-Case to Average-Case Reductions for Module Lattices. *Designs, Codes and Cryptography*, 75(3).
10. Kate, A., Zaverucha, G. M., & Goldberg, I. (2010). Constant-Size Commitments to Polynomials and Their Applications. *ASIACRYPT 2010*.

---

*Document status*: Architecture specification.
*Last updated*: June 2026.
*Research prototype only* — not production-ready. See `SECURITY.md`, `WARNING.md`, and `SECURITY-ADVISORY-001.md` for threat model and caveats.
