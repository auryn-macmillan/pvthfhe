# Fold Construction — Nova-Only Folding Path (R2.0)

> **Status**: R2.0 design freeze. Documents the Nova Nova substitution for the
> P2 folding layer. Read-only; updates only via plan amendment or escape hatches
> in `spec-real-p2p3.md §9`.
>
> **R3.0 update (2026-07-14)**: The `NethermindEth/latticefold` repository (verified
> as of 2026-07-14 with 221 commits, 129 stars, EF ZK grant) provides a working
> Rust implementation of the base LatticeFold protocol. The `pvthfhe-cyclo` crate
> now implements a spec-driven LatticeFold NIFS decomposition+folding pipeline
> over the native `R_q` cyclotomic ring (`decompose/`, `nifs/` modules), replacing
> the simplified scalar-challenge Ajtai folding with proper random-linear-combination
> folding. When witness norm exceeds the per-step budget, the pipeline decomposes
> the witness into base-B digit parts and folds them via NIFS before the commitment
> layer processes them. The Nova Nova surrogate remains in the compressor path;
> full LatticeFold+ integration (algebraic range proofs, double commitments) is
> deferred pending the `latticefold-plus` crate's CCS support maturation.
> See `.sisyphus/plans/latticefold-plus.md` for the full migration plan.

---

## 1. Context

PVTHFHE uses a folding-based aggregation layer (P2) to combine up to n=1024
per-party decryption-share NIZK proofs into a single accumulator that is then
compressed by the P3 on-chain SNARK verifier.

The original architecture selection (`selection-memo.md`, 2026-05-04) chose
Architecture B: **Lattice PVSS + LatticeFold+ + MicroNova**. Under this vision,
the P2 folding layer would use **Cyclo** (ePrint 2026/359), a lattice-native
folding scheme that operates over the cyclotomic commitment ring R_{q_commit} and
folds CCS instances through sequential T=10 rounds, preserving post-quantum
security at the folding layer.

**Reality at R2.0 time**:

- Cyclo has no production-grade reference implementation. The authors provide a
  research codebase that demonstrates the core folding relation in Python/Sage,
  not a Rust library ready for integration.
- Lemma 9 (the invertibility heuristic for challenge sampling in power-of-two
  cyclotomics) is formalized in the paper but has not been independently
  re-implemented or audited; closing the formal gap exceeds the PVTHFHE budget.
- LatticeFold+ (ePrint 2025/247, Boneh–Chen) likewise has no production
  reference implementation. The closest Rust artifact is
  `NethermindEth/latticefold`, which is a research prototype not audited for
  production use.
- Both schemes require a **full CCS encoder** for the RLWE decryption-share
  relation over R_{q_commit} (φ=256, q≈2^50). Designing and hardening this
  encoder is a multi-engineer-month effort that does not fit the current phase
  budget.

**Decision**: The P2 folding layer uses **Nova Nova** (an R1CS-based folding
scheme over the BN254/Grumpkin elliptic-curve cycle) as a **substitute** for the
lattice-native folding that was planned. This is not a permanent decision; it is
a bounded migration surface with a documented upgrade path (§4).

The Nova substitution is **not** claimed to provide post-quantum security at
the P2 layer. The P1 NIZK layer remains lattice-based and post-quantum. The P3
on-chain layer is already non-post-quantum (BN254/UltraHonk) by design. The P2
Nova substitution effectively reduces the post-quantum coverage of the folding
layer from "lattice-native" to "non-PQ, like P3."

---

## 2. Construction

### 2.1 Nova Nova Over BN254/Grumpkin

The folding engine is **Nova Nova**, an implementation of the Nova folding
scheme (Kothapalli–Setty–Tzialla, CRYPTO 2022) that operates over a cycle of
elliptic curves:

| Component | Curve | Role |
|-----------|-------|------|
| Primary circuit | BN254 scalar field `F_p` | StepCircuit encoding the RLWE fold relation |
| Secondary circuit | Grumpkin scalar field | NIFS cross-term verifier |
| Folding rounds T | ≥ 10 | Matches the sequential fold depth planned for Cyclo |

The StepCircuit is a custom R1CS circuit that encodes the per-party RLWE
decryption-share relation:

```
d_i = c · s_i + e_i  mod q   in R_q = Z_q[X]/(X^N+1)
‖e_i‖_∞ ≤ B_e ≈ 16
```

where `c` is the ciphertext, `s_i` is party `i`'s secret-share polynomial, and
`e_i` is the noise polynomial. The StepCircuit:

1. **Accepts** the per-share witness (s_i, e_i) in coefficient-vector format
   (N=8192 elements over the BN254 scalar field, with each RLWE coefficient
   embedded via the θ₂ map to 256-bit elements).
2. **Enforces** the linear constraint `d_i = c·s_i + e_i` through R1CS
   multiplication gates over F_p.
3. **Range-checks** `‖e_i‖_∞ ≤ B_e = 16` through bit-decomposition constraints
   (5 bits per coefficient, 8192 coefficients × 5 ≈ 41K R1CS gates).
4. **Accumulates** the witness norm growth across folds via the Nova accumulator
   state, tracking `norm_bound_current` (the accumulated ∞-norm bound) and
   `fold_depth`.

The accumulator state at depth k carries:
- `acc_witness`: the folded witness (weighted sum of all k per-share witnesses)
- `acc_public_io`: the aggregated public I/O (cumulative d = Σ d_i, ciphertext
  hash binding, participant set fingerprint)
- `norm_bound_current = β_0 + k·(b_slack)`: the running norm bound
- `fold_depth = k`
- `params_digest`: SHA-256 of the canonical parameters

### 2.2 Cyclo Crate Role

The `crates/pvthfhe-cyclo` crate is **retained** for its witness representation
layer, not for its folding implementation:

- **Poly-vector format**: Defines `CycloParams`, `CcsPShareInstance`,
  `CycloAccumulator`, and `CycloAdapter` trait with locked canonical parameters
  (φ=256, q_commit≈2^50, a=13, T=10, β_10=1344).
- **∞-norm checks**: The `CycloAdapter::fold_one` and `verify_accumulator`
  methods enforce the norm bound `norm_bound_current ≤ β_at_t` on the supplied
  witness. This check is reused by the Nova StepCircuit to gate per-step
  acceptance.
- **SHA-256 binding tag**: `CcsPShareInstance::sha256_binding_bytes` ties each
  instance to the session transcript; the tag is checked by the aggregator
  (outside the folding circuit) before the fold step.

The actual folding computation in `fold_one` / `fold_all` is **not** the Cyclo
folding; it is the Nova Nova fold, invoked through the `CycloAdapter` trait
boundary. This keeps the trait surface stable while the backend is a Nova
substitute.

### 2.3 R2.1–R2.4 Implications

These R2 sub-items define the concrete requirements for the Nova substitution
to be sound:

#### R2.1 — ∞-Norm Checks

Every per-share witness `(s_i, e_i)` must satisfy `‖e_i‖_∞ ≤ B_e = 16` and
`‖s_i‖_∞ ≤ 1` (ternary secret). The Nova StepCircuit must enforce these
∞-norm bounds through:

1. **Bit-decomposition constraints** per coefficient: each e_i coefficient
   (range [-16, 16]) requires 6 bits (5 magnitude + 1 sign) = 6 × 8192 ≈ 49K
   R1CS gates.
2. **Ternary secret decomposition**: each s_i coefficient (range [-1, 1]) uses
   2 bits (sign + value) = 2 × 8192 ≈ 16K R1CS gates.

A CI lint (`forbid::bytes_iter_max_in_norm`, R2.1 learnings) scans all
production sources at build time and forbids `bytes.iter().max()` used as a
substitute for a proper L∞ norm check.

#### R2.2 — Challenge Sampling

Nova Nova's challenge sampling follows the standard Nova protocol:

- The primary circuit's Fiat-Shamir challenge is derived from Poseidon-hashing
  the current accumulator commitment + the new instance witness. The domain
  separator is `"pvthfhe/nova-nova/v1/" ∥ session_id ∥ "/" ∥ fold_depth`.
- The randomness is sourced from `pvthfhe_rng::OsRng` at the prover entry point;
  the FS transcript determinism within the fold is provided by the prover-side
  RNG stream derived from the transcript state.

This differs from Cyclo's biased-ternary challenge (p=1/3, subject to Lemma 9
invertibility). Nova Nova uses uniform random challenges in F_p, which avoids
the Lemma 9 heuristic entirely — at the cost of moving the folding soundness
from lattice assumptions (M-SIS) to discrete-log assumptions (DLOG on
BN254/Grumpkin).

#### R2.3 — CCS Encoder

The Cyclo-native plan required a **CCS (Customizable Constraint System) encoder**
to translate the RLWE fold relation into the CCS format consumed by the Cyclo
prover. Under the Nova substitution:

- **No CCS encoder is required.** The StepCircuit is expressed directly in R1CS,
  which is Nova's native constraint format.
- The per-share witness `(s_i, e_i)` is packed into the R1CS witness vector
  without an intermediate CCS encoding layer.
- If and when the codebase migrates to Cyclo-native folding, a CCS encoder
  (`crates/pvthfhe-cyclo/src/ccs_encode.rs`, already scaffolded) will need to be
  implemented to convert the R1CS witness into CCS instances over R_{q_commit}.

#### R2.4 — Forgery Resistance

The Nova substitution's forgery resistance depends on:

1. **DLOG hardness on BN254/Grumpkin** (assumption ID: A-DLOG-1 through
   A-DLOG-4 in `assumptions-ledger.md`). A successful forgery would require
   breaking the discrete log on either curve, or finding a collision in
   Poseidon-BN254 (A-HASH-2).
2. **StepCircuit completeness**: The R1CS constraint system must exactly capture
   the RLWE decryption-share relation. Any under-constrained gate allows a
   prover to satisfy the R1CS with a witness that does not correspond to a valid
   decryption share.
3. **Norm-bound enforcement in-circuit**: The ∞-norm checks must be enforced
   inside the StepCircuit (not only in the off-chain aggregator), otherwise a
   malicious prover can fold a witness with an unbounded noise term.

Forgery resistance testing (`pvthfhe-aggregator/tests/cyclo_forgery_resistance.rs`
or equivalent) must test the full Nova pipeline against the following adversary
models:

- **Model 1 (raw-witness injection)**: Attempt to fold a witness with
  `‖e_i‖_∞ = B_e + 1 = 17`. Must be rejected by the StepCircuit.
- **Model 2 (wrong-relation)**: Attempt to fold a witness where `d_i ≠ c·s_i + e_i`.
  Must be rejected.
- **Model 3 (fold-depth overflow)**: Attempt to fold more than T=10 instances
  into one accumulator. Must be rejected.
- **Model 4 (commitment mismatch)**: Attempt to fold an instance with a
  SHA-256 binding tag that does not match the session transcript. Must be
  rejected (checked by aggregator, not in-circuit — but the circuit must
  receive the tag as a public input).

---

## 3. Soundness Budget

### 3.1 Discrete-Log Soundness

Nova Nova's soundness over BN254/Grumpkin is estimated at **≈ 2⁻¹²⁸** with
T ≥ 10 rounds, based on:

- BN254 scalar field size: p ≈ 2²⁵⁴ → 254 bits
- Nova knowledge soundness error: `ε_nova ≤ (σ_commit + σ_challenge)^T`, where
  `σ_commit` is the binding error of the Pedersen commitment (≈ 2⁻¹²⁸ via DLOG
  on Grumpkin) and `σ_challenge` is the soundness of the Fiat-Shamir challenge
  in ROM.
- With T=10 rounds and each round contributing ≤ 2⁻¹²⁸ error: total soundness
  error ≈ 10 × 2⁻¹²⁸, which is ≪ 2⁻¹²⁰ (comfortably below 2⁻⁸⁰).

**Comparison with Cyclo soundness budget** (from `spec-real-p2p3.md` §4.4):

| Property | Cyclo (lattice-native) | Nova Nova (substitute) |
|----------|----------------------|---------------------------|
| Underlying assumption | M-SIS over R_{q_commit} (A-LATTICE-1) | DLOG on BN254/Grumpkin (A-DLOG-1–A-DLOG-4) |
| Post-quantum | Yes (≥128-bit PQ target) | No (classical only) |
| Concrete soundness | ⊕₂(κ_nu, κ_rom, κ_msis) ≈ 2⁻⁹⁴ + … | ε_nova × T ≈ 10 × 2⁻¹²⁸ |
| Norm growth budget | β_10 = 1344 (Theorem 3) | Same β_10 = 1344 (enforced in StepCircuit) |
| Invertibility heuristic | Lemma 9 (κ_nu ≈ 2⁻⁹⁴) | Not applicable (uniform challenges in F_p) |
| Challenge type | Biased ternary (p=1/3) | Uniform random in F_p |

### 3.2 StepCircuit Constraint Budget

| Sub-circuit | Estimated R1CS gates over F_p |
|-------------|-------------------------------|
| RLWE linear constraint `d_i = c·s_i + e_i` | N × (log₂q in F_p) ≈ 8192 × 174 ≈ 1.4M |
| ∞-norm check `‖e_i‖_∞ ≤ 16` | 8192 × 6 ≈ 49K |
| Ternary check `‖s_i‖_∞ ≤ 1` | 8192 × 2 ≈ 16K |
| Accumulator state update (norm_bound, fold_depth) | O(1) ≈ 1K |
| SHA-256 binding tag inclusion (public input, not constraint) | 0 (pub input only) |
| **Total per-fold step** | **≈ 1.5M R1CS gates** |

Nova Nova at 1.5M gates per fold step, T=10 sequential folds: total prover
work ≈ 10 × (1.5M R1CS constraint evaluations + NIFS overhead). This is within
the Nova benchmark range (≤ 2^21 R1CS constraints total = 2M constraints).

The compressed Nova proof (after T=10 folds) is O(log₁₀) ≈ 15–20 KB in size,
smaller than the Cyclo accumulator (~50–60 KB, `spec-real-p2p3.md` §4.6).

---

## 4. v2 Migration Surface (Nova → Lattice-Folding)

When a production-grade lattice folding backend becomes available (Cyclo Lemma 9
formalized and audited, or LatticeFold+ reference implementation stabilized),
the migration path is:

### 4.1 Traits That Change

| Trait / Type | Current (Nova) | v2 (Cyclo-native) | Migration Shape |
|-------------|-------------------|-------------------|-----------------|
| `CycloAdapter::fold_one` | Delegates to Nova Nova fold | Implements real Cyclo fold over R_{q_commit} | Swap internal implementation; trait signature unchanged |
| `CycloAccumulator` | Stores R1CS-encoded accumulator state | Stores CCS accumulator over R_{q_commit} (`acc_commitment` in R_{q_commit}^a) | Type remains; serialization changes `acc_commitment_bytes` from R1CS to CCS format |
| `CcsPShareInstance` | Wraps R1CS witness bytes | Wraps CCS witness over R_{q_commit} | Type unchanged; encoding changes from R1CS to CCS |
| `ProofCompressor` trait | Nova adapter (`nova/mod.rs`) | Cyclo-native adapter | Trait surface preserved; backend-specific impl swapped |

### 4.2 Files Touched

From `nova-migration.md` — the bounded migration surface:

| File | Change |
|------|--------|
| `crates/pvthfhe-compressor/src/lib.rs` | Swap backend selector from Nova to Cyclo-native |
| `crates/pvthfhe-compressor/src/step_circuit.rs` | **Unchanged** — step-circuit shape is backend-agnostic per Invariant 2 |
| `crates/pvthfhe-compressor/src/nova/mod.rs` | Replaced by `cyclo/mod.rs` implementing the CCS adapter |
| `crates/pvthfhe-cyclo/src/adapter.rs` | Current `LegacyHashChainAdapter` replaced with `CycloFoldingAdapter` implementing real Cyclo fold |
| `crates/pvthfhe-cyclo/src/ccs_encode.rs` | CCS encoder for RLWE relation over R_{q_commit} (scaffolded, previously a stub) |
| `crates/pvthfhe-cyclo/src/fold.rs` | Real Cyclo folding step (caller-agnostic), replacing stub |
| `crates/pvthfhe-cyclo/src/fiat_shamir.rs` | FS transcript for Cyclo challenge sampling (biased ternary) |
| `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` | Report new backend identity |
| `crates/pvthfhe-bench/src/bin/bench_comparison.rs` | Record new backend identity in benchmark artifacts |

**Total files touched**: 9. No changes required in P1 NIZK layer, P3 on-chain
verifier, Solidity contracts, Noir circuits, or FHE backend.

### 4.3 What Does NOT Change

- **P1 NIZK interface** (`LatticeNizk` trait, `CycloNizkAdapter`): unchanged —
  per-share witness production is unaffected by folding engine choice.
- **P3 on-chain verifier** (`IPvthfheVerifier.sol`, Noir circuit signature): the
  7 frozen public inputs (§2 of `spec-real-p2p3.md`) and the ABI remain
  identical.
- **FHE backend** (`gnosisguild/fhe.rs`): unchanged.
- **Rust aggregator** (blame bookkeeping, transcript validation): unchanged.
- **Cyclo parameter struct** (`CycloParams`, `PVTHFHE_CYCLO_PARAMS`): the
  locked parameters (φ=256, a=13, T=10, β_10=1344) are the **v2 target**
  parameters — useful as a sizing budget even during the Nova phase.
- **∞-norm CI lint** (`forbid::bytes_iter_max_in_norm`): unchanged — enforced
  in both Nova and Cyclo-native phases.

### 4.4 Migration Triggers

The migration from Nova to lattice-native folding is unlocked when **any** of
the following conditions are met:

1. **Cyclo Lemma 9 formalized and audited**: An independent re-implementation
   of the Lemma 9 invertibility heuristic for φ=256 cyclotomic is publicly
   available and passes at least one external audit.
2. **LatticeFold+ reference implementation stabilized**: The
   `NethermindEth/latticefold` repository reaches a stable release (≥v1.0) with
   production-grade Rust implementation and test coverage for RLWE folding over
   R_{q_commit} (φ=256, q≈2^50).
3. **CCS encoder for RLWE relation designed and hardened**: A CCS constraint
   system encoding exactly the RLWE decryption-share relation (`d_i = c·s_i + e_i`,
   `‖e_i‖_∞ ≤ B_e`) is available as a standalone crate and has passed oracle
   review.

Until any of these conditions are met, the Nova substitution remains in place
with the discrete-log soundness budget documented in §3.

---

## 5. Why NOT Cyclo-Native (Today)

Cyclo (ePrint 2026/359) is the correct mathematical foundation for lattice-based
folding over RLWE. It is not used directly in the current PVTHFHE prototype for
the following reasons, ranked by severity:

| Reason | Severity | Detail |
|--------|----------|--------|
| **No production reference implementation** | Blocker | The Cyclo authors provide a Sage/Python research artifact, not a Rust library. Porting the folding logic to `pvthfhe-cyclo/src/fold.rs` is a multi-month engineering effort with no existing test vectors or integration examples. |
| **Lemma 9 formalization exceeds budget** | Blocker | Lemma 9 (invertibility heuristic for biased ternary challenges in power-of-two cyclotomics) is formalized in the paper but has no independent re-implementation or audit. Verifying the bound κ_nu ≈ 2⁻⁹⁴ for φ=256 is a research project in itself. |
| **CCS encoder design is a separate engineering task** | High | The RLWE fold relation must be expressed as a CCS (Customizable Constraint System) over R_{q_commit}. This requires designing a CCS encoding for polynomial arithmetic modulo X^256+1 with 50-bit coefficients — a task that touches `ccs_encode.rs`, `range_check.rs`, and `extension.rs` in the `pvthfhe-cyclo` crate. |
| **No NTT acceleration for Cyclo ring** | Medium | The commitment ring R_{q_commit} = Z_{q_commit}[X]/(X^256+1) uses very small degree (φ=256), making NTT-based acceleration less efficient than for large NTT-friendly moduli. The `fhe-math` ring backend provides Poly/Rq arithmetic but may need optimization for this specific ring size. |
| **FS transcript domain separation is Cyclo-specific** | Low | The FS domain separator `"pvthfhe/cyclo-ajtai-d2/v1/" ∥ session_id ∥ "/" ∥ participant_id_decimal` is designed for Cyclo's transcript format. Nova uses a different separator. |

---

## 6. Why NOT LatticeFold+ (Today)

LatticeFold+ (ePrint 2025/247, Boneh–Chen) is an alternative lattice-based
folding scheme that generalizes Nova to lattice commitments. It is not used for
the same core reason: **no production reference implementation exists**.

| Reason | Severity | Detail |
|--------|----------|--------|
| **No production reference impl** | Blocker | `NethermindEth/latticefold` (Apache 2.0) is the closest Rust artifact, but it is a research prototype that has not been audited, benchmarked at PVTHFHE-relevant parameters (φ=256, m≈53K), or integrated with any FHE backend. |
| **CRYPTO 2025 publication, no stable tooling** | Blocker | LatticeFold+ was published at CRYPTO 2025 (August 2025). As of May 2026, there is no v1.0 release, no documented API, and no production users. |
| **Different folding model from Cyclo** | Medium | LatticeFold+ folds **batched** lattice commitments (generalizing the LatticeFold commitment scheme), not sequential CCS instances. Adapting the RLWE decryption-share relation to LatticeFold+'s batching model is a separate research task that has not been done. |
| **No CCS encoder exists** | Medium | Same as Cyclo — the RLWE relation must be encoded into the scheme's constraint format, which differs from both R1CS and Cyclo's CCS. |

---

## 7. Assumptions Added by This Decision

This document adds the following entries to the assumptions ledger
(`assumptions-ledger.md`):

| ID | Statement | Added By |
|----|-----------|----------|
| **A-DLOG-5** | **Nova Nova soundness over BN254/Grumpkin cycle.** With T ≥ 10 sequential fold rounds, the knowledge soundness error of the Nova folding scheme instantiated over BN254 (primary) and Grumpkin (secondary) is ≤ 10 × 2⁻¹²⁸. This assumes DLOG hardness on both curves (A-DLOG-1 through A-DLOG-4) and Poseidon collision resistance (A-HASH-2). | R2.0, §3.1 |
| **A-STRUCT-7** | **StepCircuit exactness.** The R1CS circuit encoding the per-party RLWE decryption-share relation exactly captures the statement `d_i = c·s_i + e_i ∧ ‖e_i‖_∞ ≤ 16 ∧ ‖s_i‖_∞ ≤ 1` with no under-constrained gates. Any deviation risks forgery. | R2.0, §2.3 |
| **A-COND-5** | **Nova substitution is a temporary surrogate.** The Nova-based P2 folding layer is NOT post-quantum. It is accepted as a temporary substitute for the lattice-native folding (Cyclo/LatticeFold+) that was originally planned. The migration path is documented in §4. | R2.0, §1 |

---

## 8. CI Lints Added by R2

| Lint | Scope | Test File |
|------|-------|-----------|
| `forbid::bytes_iter_max_in_norm` | All production crates | Flag any `bytes.iter().max()` used as norm check substitute |
| `forbid::raw_pvthfhe_domain_tag` (R0.4, reused) | Enforced for Nova-specific domain separators | `pvthfhe-domain-tags/tests/exhaustive.rs` |

---

## 9. References

| Citation | Full Reference |
|----------|---------------|
| Cyclo ePrint 2026/359 | Garreta, Lipmaa, Luhaäär, Osadnik — "Cyclo: Lightweight Lattice-based Folding via Partial Range Checks", IACR ePrint 2026/359 (Eurocrypt 2026) |
| LatticeFold+ ePrint 2025/247 | Boneh, Chen — "LatticeFold+", IACR ePrint 2025/247 (CRYPTO 2025) |
| Nova (CRYPTO 2022) | Kothapalli, Setty, Tzialla — "Nova: Recursive Zero-Knowledge Arguments from Folding Schemes" |
| Nova | https://github.com/privacy-scaling-explorations/nova — Rust library for folding schemes including Nova over BN254/Grumpkin |
| spec-real-p2p3.md | `.sisyphus/design/spec-real-p2p3.md` — Real P2 + P3 Joint Freeze (L4) |
| assumptions-ledger.md | `.sisyphus/design/assumptions-ledger.md` — Assumptions Ledger (L5) |
| nova-migration.md | `.sisyphus/design/nova-migration.md` — Bounded migration surface for compressor backend swap |
| proof-boundary.md | `.sisyphus/design/proof-boundary.md` — PVTHFHE Proof Boundary Freeze (T25) |

---

*Document version*: 1.0
*Last updated*: 2026-05-08
*Oracle review*: Required before R2.0 checkbox can be marked complete
  (see `.sisyphus/notepads/pvthfhe-remediation/decisions.md` §R2.0)
