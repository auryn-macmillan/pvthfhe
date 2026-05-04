# NIZK Candidate Selection (L3)

> **Phase**: 0 / L3 — per-share NIZK candidate selection  
> **Status**: DRAFT — feeds Phase 2 Cyclo folding design  
> **Date**: 2026-05-04  
> **Depends on**: cyclo-digest.md, micronova-digest.md, proof-boundary.md, parameters.toml, theorem-inventory.md  

---

## 1. Goal & Constraints

### 1.1 Core Goal

Select the per-share NIZK scheme for the P1 relation that (a) can be directly
accumulated by Cyclo folding in Phase 2, and (b) preserves a clean
conditional-soundness disclosure path while P1 remains formally tabled.

### 1.2 P1 Relation (verbatim from plan)

Per-share public statement:

```
x_i = (session_id, i, t, c, d_i, C_i, q, N, k, B_e)
```

Per-share witness:

```
w_i = (s_i, e_i)
  where:
    C_i = SHA256(session_id || i_le || s_i_be)            [P4 commitment]
    d_i = c · s_i + e_i  mod q   in R_q = Z_q[X]/(X^N+1) [RLWE decryption share]
    ‖e_i‖_∞ ≤ B_e                                         [shortness bound]
```

**PVTHFHE parameters** (from `.sisyphus/design/parameters.toml`):
- N = 8192 (ring degree)
- log₂q ≈ 174 bits, 3 RNS limbs (three 58-bit NTT-friendly primes)
- B_e: drawn from discrete Gaussian σ=3.19; practical ∞-norm budget B_e ≈ 16 (6σ)
- Target parties n ≤ 1024

### 1.3 Hard Constraints

| Constraint | Value / Rationale |
|---|---|
| **Conditional-soundness disclosure** | P1 tabled; must surface in API doc, SECURITY.md banner, prover output, verifier rejection path. T2 remains skeleton. |
| **ROM baseline** | Required. QROM is a stretch goal; do not sacrifice ROM soundness for QROM elegance. |
| **PQ security** | ≥ 120-bit post-quantum (matching `parameters.toml [security] pq_bits = 128`). |
| **Cyclo norm budget** | Per-share NIZK witness / response vector must satisfy ‖·‖_∞ ≤ B_Cyclo = 2^10 (Cyclo Table 2, cyclo-digest.md §5.1) when encoded as a CCS witness. |
| **R1CS/CCS encodability** | Proof output must decompose into a linear relation over R_{q_commit} (Cyclo's commitment ring, q_commit ≈ 2^50, φ_commit = 256 working hypothesis, cyclo-digest.md §6.5). |
| **Seven frozen public inputs** | The on-chain SNARK ultimately binds `(ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, D_commitment)` (proof-boundary.md §Accumulator-to-SNARK Encoding). Per-share NIZK must be compatible with these without additional chain-visible inputs. |
| **Minimum integration delta** | The existing `RealNizkAdapter` trait (`prove`, `verify`, `batch_verify`) is the surface to replace. Prefer designs that keep the same trait boundary. |

---

## 2. Candidates

### (A) Status Quo — SLAP-style Sigma + Fiat-Shamir (Baseline)

**Summary**: Current `crates/pvthfhe-fhe/src/real_nizk.rs`. Single-round
sigma protocol over the scalar s_i and error vector e_i. Prover samples
masks (y_s, y_e), sends commitment t, receives FS challenge c, responds with
(z_s = y_s + c·s_i, z_e = y_e + c·e_i). Currently also **opens the witness
directly** (`secret_share_open`, `error_open` in `ProofPayload`), making the
current prototype non-ZK.

**Soundness model**: ROM, rewinding extractor (T2 skeleton). Knowledge
soundness depends on algebraic binding of the sigma transcript plus SHA-256
binding (T5). **T3 is proved for the abstract randomized core only** — the
deterministic mask derivation `SHA256(stmt||witness)` in the prototype is
explicitly weaker (theorem-inventory.md T3 caveat).

**Prover cost**:
- 1 SHA-256 hash (mask commitment)
- 1 SHA-256 hash (FS challenge)
- 2N scalar multiplications in Z_q (z_s, z_e)
- Proof size ≈ 32 KB (matching `parameters.toml nizk_size_bytes = 32768`)

**Verifier cost**: O(N) — recompute t from (z_s, z_e, witness_open) and check.

**R1CS friendliness**: Poor — SHA-256 commitment (non-algebraic) and witness opening break the linear structure needed for Cyclo CCS encoding. No direct R_q_commit encoding.

**ROM/QROM**: ROM only. No known QROM proof.

**Conditional-soundness**: Partially surfaced (prototype opens witness); no formal soundness banner. Knowledge soundness is T2 skeleton — not proved.

**Integration delta**: Zero — this is the current state.

**Risk**: High — the witness-opening pattern is definitionally not ZK. Cannot
be accumulated natively by Cyclo without major redesign of the proof payload.

---

### (B) LaBRADOR-style Succinct Lattice IOP

**Summary**: LaBRADOR (Beullens-Seiler, ePrint 2022/1341) and its successor
Greyhound (ePrint 2024/352 [CITATION NEEDED — candidate: Beullens-Seiler 2024
Greyhound]) provide succinct lattice IOPs using recursive splitting and
aggregate norm proofs. Proof size shrinks from O(N) to O(polylog N) over the
witness, at the cost of multiple rounds of interaction (made non-interactive
via FS).

**Soundness model**: ROM, knowledge soundness under M-SIS. Greyhound reduces
to a simpler relation with O(log²N) communication vs LaBRADOR's O(log³N).

**Prover cost (LaBRADOR)**:
- O(N log²N) R_q multiplications (recursive halving)
- Estimated prover time: ~seconds for N=8192 (no PVTHFHE-specific benchmark)
- Proof size: ≈ 10–50 KB for N=8192 depending on recursion depth [CITATION NEEDED — exact figure for N=8192, k=1 module rank]

**Verifier cost**: O(polylog N) — very fast.

**R1CS friendliness**: Medium — LaBRADOR proofs are over the commitment ring
R_q (MSIS lattice). The linear aggregation structure is compatible with Cyclo's
CCS model if the commitment ring is set equal to R_{q_commit}. However, the
recursive structure requires encoding multiple levels of inner products, which
may inflate CCS constraint count significantly.

**ROM/QROM**: ROM for LaBRADOR. QROM analysis not established as of this
writing [CITATION NEEDED].

**Conditional-soundness**: LaBRADOR provides knowledge soundness (extractor
outputs short kernel vectors); the RLWE / SHA-256 joint relation requires a
custom reduction not present in the base paper. P1 disclosure banner still
required.

**Integration delta**: High — requires rewriting `RealNizkAdapter` from
scratch, integrating an external crate (no production Rust library for
LaBRADOR/Greyhound known as of 2026-05-04), and bridging the SHA-256
commitment domain to the algebraic commitment.

**Risk**: Medium — powerful technique but no off-the-shelf Rust implementation; integration effort is large.

---

### (C) Lyubashevsky-style Rejection-Sampling Sigma (for Joint RLWE/Hash Relation)

**Summary**: The standard approach for lattice sigma protocols: prover samples
large Gaussian mask y (over R_q), computes commitment W = Ay + e_mask,
receives challenge c from the verifier (FS hash), computes response z = y +
c·s_i, then **aborts and resamples** if z is not uniformly distributed
(rejection sampling). Makes the response distribution independent of the
witness. Applicable variants: Lyubashevsky 2012 (`ePrint 2011/537`), Esgin et
al. CRYPTO 2019 (MatRiCT, `ePrint 2019/1287`), Esgin et al. CRYPTO 2020
(Raptor / LaBRADOR predecessor, `ePrint 2020/518`).

The **joint SHA-256/RLWE relation** requires a hybrid proof:
1. A standard rejection-sampling sigma for the RLWE part (`d_i = c·s_i + e_i`).
2. A SHA-256 opening argument for the P4 commitment (`C_i = SHA256(session_id || i || s_i)`).

Part (2) is non-algebraic; requires either:
- A Garbled-circuit / MPC-in-the-head approach for the SHA-256 sub-statement, or
- Replacing the SHA-256 commitment with an algebraic Ajtai commitment (breaks backward compatibility with P4).

**Prover cost**:
- O(N) R_q multiplications per trial + expected O(e) trials per rejection
- Concrete abort probability ≈ e^{-Nσ²/(2B²)} with σ=11·B (standard Lyubashevsky choice); for B_e≈16 and N=8192 the abort rate is tolerable but not benchmarked here.
- Proof size: O(N) coefficients ≈ 174·8192 bits ≈ 178 KB before compression, or ~4–8 KB with MSIS aggregation tricks.

**Verifier cost**: O(N) — one ring multiplication.

**R1CS friendliness**: Good for the RLWE part (linear relation over R_q, directly encodable as CCS). The SHA-256 sub-proof is the bottleneck: encoding SHA-256 in R1CS requires ≈20,000+ constraints for one 256-bit hash, which scaled to N=8192 is impractical as-is.

**ROM/QROM**: ROM for the sigma part (Lyubashevsky 2012). QROM requires
measure-and-reprogram; Kiltz-Lyubashevsky-Schaffner 2018 covers the
module-lattice case [CITATION NEEDED — exact reference].

**Conditional-soundness**: Knowledge soundness conditional on M-SIS for the
RLWE part; SHA-256 binding inherited from T5. The joint relation requires a
composed extractor not yet written for PVTHFHE (T2 remains skeleton).

**Integration delta**: Medium — the RLWE part maps cleanly to a new
`RealNizkAdapter` backend; the SHA-256 joint part is the significant research
and implementation gap.

**Risk**: High for full joint proof. Medium if SHA-256 is replaced by an Ajtai
commitment (but that changes the P4 interface).

---

### (D) Cyclo-Companion NIZK: Native Ajtai Opening Proof over R_{q_commit}

**Summary**: Rather than treating the per-share NIZK as a separate primitive,
embed it natively in Cyclo's commitment ring R_{q_commit} (φ=256, q_commit≈2^50)
by proving the following purely linear relation over R_{q_commit}:

```
Given:  A ∈ R_{q_commit}^{a×m}  (Ajtai commitment key)
Claim:  u = A·w,  ‖w‖_∞ ≤ B_Cyclo = 2^10
```

where the per-share witness `(s_i, e_i)` is packed into the coefficient
vector `w` after a base-2 decomposition and the RLWE equation `d_i = c·s_i +
e_i` is encoded as a linear constraint over R_{q_commit} by the θ_k map
(cyclo-digest.md §6.2, Lemma 5). The SHA-256 commitment is handled either:
  - (D1) by replacing it with an Ajtai commitment over R_{q_commit} (clean algebraic path, requires P4 interface change), or
  - (D2) by adding a separate hash-binding assertion checked outside the folded NIZK (conditional-soundness banner for the hash component only).

This is the "native folding" path: the per-share Ajtai opening proof **is** the
first Cyclo fold input. No separate NIZK scheme is needed; the folding prover
directly accumulates the per-share relation.

**Prover cost**:
- One Ajtai commitment per share: a·m R_{q_commit} multiplications; for a=13, m=2^20, φ=256: dominant but O(1) per share.
- Per-share witness encoding into CCS: O(N·log q / log q_commit) coefficients = O(N·174/50) ≈ O(3.5N); for N=8192 ≈ 28,500 R_{q_commit} coefficients per share.
- For n=1024 shares folded sequentially (T=10): 10 Cyclo fold steps at ~36.6 s/step (single-threaded, cyclo-digest.md §5.3), total ≈ 366 s unparallelized. With n=1024 parties computing in parallel: dominated by single-party fold time ≈ 36 s.
- **Per-share proof size**: not a standalone proof; the Cyclo accumulator at depth T=10 is ≈ 50–60 KB (scaled from 31.8 KB × (256/128), cyclo-digest.md §6.5).

**Verifier cost**: O(a) = O(13) R_{q_commit} multiplications per fold step (cyclo-digest.md §5.4). Succinct.

**R1CS/CCS encoding**: Native — by construction. The Cyclo accumulator is the
R1CS/CCS instance. The θ_k map bridges the 174-bit RLWE field to R_{q_commit}:
need ℓ_2(2^174) = 174 < φ = 256 ✓ (cyclo-digest.md §6.2, condition satisfied
with φ_commit = 256).

**Norm budget**: Per-share witness encoding must satisfy ‖w_i‖_∞ ≤ B_Cyclo =
2^10 after base-2 decomposition of the RLWE coefficients. Since RLWE secret s_i
is ternary and error e_i has ‖e_i‖_∞ ≤ B_e ≈ 16, and after packing into
174-bit coordinates and decomposing in base 2 we recover individual bits — all
within bound. ✓

**ROM/QROM**: Inherits Cyclo's ROM security (Module-SIS + RO, cyclo-digest.md
§4.4). QROM gap inherited from Cyclo (not addressed in paper).

**Conditional-soundness**:
- RLWE relation: knowledge soundness under M-SIS, inherited from Cyclo Theorem 3 (cyclo-digest.md §4.3) — still formally depends on T2 sketch.
- SHA-256 component: if D2 variant, hash binding is conditional (T5 proved, but not folded). Must assert P1 banner.

**Integration delta**: Largest in terms of total system scope (must implement
Cyclo), but **minimum delta for the NIZK boundary** — the `LatticeNizk` trait
can be reimplemented as a thin wrapper around the Cyclo fold prover. The
`ProofPayload` structure is replaced by an Ajtai commitment + CCS instance.

**Risk**: Medium-High — Cyclo has no production Rust implementation (cyclo-digest.md §7.1). Must implement from the paper. However, NethermindEth/latticefold is the closest starting point.

---

### (E) Sumcheck-based RLWE Proof (Candidate: Plonky2-flavoured, BabyBear field)

**Summary**: Use a Plonky2/STARK-style recursive SNARK over BabyBear (p=2^31−2^27+1)
or Goldilocks (p=2^64−2^32+1) to prove the RLWE relation. This requires
expressing `d_i = c·s_i + e_i mod q` as a BabyBear arithmetic circuit,
leveraging NTT structure.

**Assessment**: The RLWE modulus q ≈ 2^174 does not fit natively in a 31-bit or
64-bit field; splitting requires ≥3 field elements per coefficient, inflating the
circuit to ≥ 3N = 24,576 field elements per share just for one polynomial, plus
the NTT butterfly structure adds a log factor. Total constraint count: O(N log N)
= O(8192·13) ≈ 100,000 constraints per share, manageable for a BabyBear STARK.

**However**: The result is a Plonky2/FRI-based proof, which is:
- Not lattice-based (not PQ-sound over lattice assumptions; inherits FRI/hash assumptions).
- Not natively encodable as R_{q_commit} CCS for Cyclo folding without an additional recursion layer.
- Incompatible with the BN254-based MicroNova compression step unless wrapped in Grumpkin (cycle mismatch with BabyBear).

**Verdict**: Out-of-scope for the PVTHFHE NIZK layer. May be revisited as a
preprocessing step for the P3 SNARK layer, but does not satisfy the R1CS/CCS
encodability or PQ-security constraints for the per-share NIZK. **Not
recommended.**

---

## 3. Comparison Matrix

| Candidate | Soundness model | Proof size | Prover time | Verifier time | R1CS/CCS encoding cost | ROM/QROM | Conditional-soundness fit | Integration delta | Risk |
|---|---|---|---|---|---|---|---|---|---|
| **(A) SLAP Sigma+FS (status quo)** | ROM, skeleton T2 | ~32 KB | <1 s (trivial) | <1 ms | Poor — SHA-256 non-algebraic; witness open | ROM only | Partial (no formal banner; witness opened) | 0 | HIGH — not ZK; not Cyclo-encodable |
| **(B) LaBRADOR / Greyhound** | ROM, M-SIS | 10–50 KB | ~seconds (est.) | O(polylog N) | Medium — recursive inner-product structure | ROM; QROM unknown | Needs custom joint extractor for SHA-256 | High — no Rust impl | Medium — powerful but unimplemented |
| **(C) Rejection-Sampling Sigma** | ROM, M-SIS | ~4–178 KB | <1 s RLWE part; SHA-256 sub-proof TBD | O(N) | Good (RLWE); Poor (SHA-256 sub-proof) | ROM; QROM with measure-and-reprogram | Needs hash-binding sub-proof | Medium — RLWE clean; SHA-256 gap | High (joint proof); Medium (RLWE only with D2 hash) |
| **(D) Cyclo-companion Ajtai NIZK** | ROM, M-SIS (Cyclo T3) | N/A (folded) / ~50–60 KB acc. | ~36 s/fold (single-threaded) per cyclo-digest §5.3 | O(a)=O(13) R_q_commit mults | Native — is the CCS instance | ROM; QROM gap (inherited) | Clean with D2 hash variant + P1 banner | Large system scope; small trait delta | Med-High — no Cyclo Rust impl |
| **(E) Plonky2/BabyBear** | FRI/hash | ~100–200 KB | ~1–5 s | Fast | None — incompatible with Cyclo | ROM (FRI) | Incompatible with PQ mandate | Very high | Out-of-scope |

---

## 4. Recommendation

### Primary: Candidate (D) — Cyclo-companion Ajtai NIZK (D2 variant)

**Rationale**:

**(i) Cyclo encoding cost**: By construction, the Cyclo-companion NIZK
**eliminates** the per-share NIZK as a separate circuit encoding step. The
per-share Ajtai commitment is the first Cyclo fold input; no additional R1CS
translation layer is needed. This avoids the "NIZK → R1CS → Cyclo" pipeline
that candidates A/B/C would require, which is the largest unknown risk in the
current design (cyclo-digest.md §6.4 "Witness count after R1CS reduction" —
severity HIGH/UNKNOWN).

**(ii) Preserving the P1 tabled status / conditional-soundness disclosure**: The
D2 variant explicitly bifurcates:
- The RLWE relation (`d_i = c·s_i + e_i, ‖e_i‖_∞ ≤ B_e`) is encoded
  algebraically in CCS and accumulated with Cyclo knowledge soundness
  (conditional on M-SIS, T2 skeleton status preserved with Cyclo attribution).
- The SHA-256 commitment (`C_i = SHA256(...)`) is checked **outside** the
  fold as a hash-binding assertion (T5 proved). The P1 conditional-soundness
  banner is asserted precisely over this non-algebraic component.
  This is a cleaner disclosure than candidate A (which doesn't distinguish the
  two) or C (which requires a hard-to-construct joint extractor).

**(iii) Minimum integration delta vs `RealNizkAdapter`**: The public API trait
(`prove`, `verify`, `batch_verify`) is retained. The `prove` implementation
becomes a Cyclo-fold prover call; `verify` becomes an Ajtai commitment check
plus a hash assertion; `batch_verify` becomes a sequential Cyclo fold. The
`ProofPayload` structure is replaced by a `CcsWitness + AjtaiCommitment` struct;
no external trait boundary changes.

**(iv) PQ security**: Inherits Cyclo's Module-SIS soundness (≥128-bit PQ per
cyclo-digest.md §4.4 + `parameters.toml pq_bits=128`). No elliptic-curve
or pairing assumption at this layer.

### Fallback: Candidate (C) — Rejection-Sampling Sigma (RLWE part only, D2 hash)

If L4 discovers that Cyclo parameter validation fails (e.g., witness count
exceeds m=2^20 for the PVTHFHE circuit, or Cyclo norm-growth analysis fails
for the T=10 sequential fold pattern), fall back to a standard rejection-sampling
sigma proof for the RLWE relation only, with the SHA-256 commitment handled by
hash-binding outside the proof (D2 pattern). This preserves ROM soundness
under M-SIS, can use the existing `NizkStatement/NizkWitness` API, and does
not require Cyclo to exist. The main cost is that the per-share proof becomes
a standalone ~4–8 KB sigma transcript per share, which then still needs a
separate encoding step for Cyclo accumulation.

---

## 5. Conditional-Soundness Disclosure Plan

### 5.1 Components with Formal Status

| Component | Claim | Status |
|---|---|---|
| RLWE relation `d_i = c·s_i + e_i` (Cyclo M-SIS) | Knowledge soundness under M-SIS in ROM | Conditional on Cyclo Theorem 3 + T2 sketch |
| Norm bound `‖e_i‖_∞ ≤ B_e` | Range check via Cyclo Theorem 1 (cyclo-digest.md §4.1) | Conditional on Cyclo soundness |
| SHA-256 commitment `C_i = SHA256(...)` | Collision-resistance binding (T5) | **PROVED** (theorem-inventory.md T5) |
| Joint knowledge soundness (both components) | T2 ROM extractor | **SKELETON** — not proved |
| ZK / HVZK | T3 abstract randomized core | Proved for abstract sigma only; D2 Ajtai variant requires new T3 argument |

### 5.2 Required Banner Locations

1. **`SECURITY.md` open problems section**: Add P1 disclosure paragraph:
   > "P1 (CRITICAL): Per-share RLWE NIZK knowledge soundness is conditional on
   > (a) Module-SIS hardness over R_{q_commit}, (b) Cyclo Theorem 3 soundness
   > (ePrint 2026/359), and (c) collision resistance of SHA-256 for the P4
   > commitment domain. Formal joint-extractor proof (T2) is deferred. Any
   > relying party must treat per-share proofs as computationally binding under
   > these assumptions only."

2. **API doc on `LatticeNizk::verify`**: Rustdoc `# Security` section must
   state: "Verification success is conditional on T2 (knowledge soundness —
   skeleton). See SECURITY.md §P1."

3. **`NizkProof::backend_id`**: For the new Cyclo backend, set
   `backend_id = "cyclo-ajtai-d2-conditional"` so any consumer can detect
   the conditional claim programmatically.

4. **`NizkError::VerificationFailed`**: Add variant
   `ConditionalSoundnessDisclosure(&'static str)` for the hash-binding
   assertion path (D2 SHA-256 check). Return this variant, not `VerificationFailed`,
   when the RLWE proof verifies but the SHA-256 binding cannot be checked
   algebraically (e.g., in a folded-only context).

5. **`docs/security-proofs/p1/theorem-inventory.md` T2**: Status remains
   `skeleton` until a full joint extractor is written. The Cyclo-companion
   NIZK does not automatically close T2 — it changes the reduction target
   from "M-SIS for ad hoc sigma" to "Cyclo Theorem 3 extractor composed with
   T5". The new status should read: `skeleton (reduction target: Cyclo T3 ∘ T5)`.

### 5.3 What Is Asserted vs Deferred

| Assertion | Asserted now | Deferred |
|---|---|---|
| SHA-256 commitment binding | Yes (T5 proved) | — |
| Norm bound ‖e_i‖_∞ ≤ B_e inside fold | Yes (Cyclo T1, conditional) | QROM upgrade |
| RLWE relation knowledge extraction | Conditional on M-SIS + Cyclo T3 | Full T2 proof |
| ZK for per-share witness | Conditional on Cyclo HVZK + new T3 rewrite | Formal T3 rewrite for Ajtai variant |
| Simulation-extractability (T4) | Not required (T4 decision: N/A) | If P2 interface changes |

---

## 6. Parameter Bridge to Cyclo

### 6.1 Encoding the Per-Share Witness into a CCS Instance

The per-share witness `w_i = (s_i, e_i) ∈ R_q^2` lives over the RLWE ring
`R_q` (N=8192, q≈2^174). The Cyclo commitment ring is `R_{q_commit}` (φ=256,
q_commit≈2^50). The bridge uses the θ_k map (cyclo-digest.md §6.2):

```
θ_2 : F_q → R_{q_commit}^{⌈174/256⌉} = R_{q_commit}^1   (since 174 < 256 ✓)
```

Each RLWE coefficient (up to 174 bits) maps to a single R_{q_commit} element
via binary expansion. The RLWE polynomial s_i (N=8192 coefficients) maps to a
vector of 8192 R_{q_commit} elements; same for e_i. Combined witness w_i is a
vector in R_{q_commit}^{16384}.

The RLWE linear constraint `d_i = c·s_i + e_i mod q` encodes as a linear
constraint over R_{q_commit}: with the NTT structure of R_q matched to the
cyclotomic structure of R_{q_commit} (both power-of-two), this is a degree-N
polynomial multiplication. In CCS, this becomes a single R1CS multiplication
gate over R_{q_commit}^{8192}, requiring m ≈ 8192 · (1+log₂q / log₂q_commit)
≈ 8192 · (1 + 174/50) ≈ 8192 · 4.5 ≈ 36,864 R_{q_commit} elements per share.

### 6.2 Constraint Count Estimate

For one per-share NIZK over the RLWE relation:

| Component | R_{q_commit} elements | Notes |
|---|---|---|
| Secret s_i | 8192 | ternary; ‖·‖_∞ = 1 ≤ B_Cyclo ✓ |
| Error e_i | 8192 | ‖e_i‖_∞ ≤ 16 ≤ B_Cyclo ✓ |
| RLWE linear constraint (c·s_i + e_i = d_i) | ~36,864 | coefficient-wise in NTT domain |
| Norm range checks (Cyclo T1) | ~8192 | one range check per e_i coefficient |
| **Total per-share witness** | **~53,248** | m ≈ 2^{15.7} |

For n=1024 shares folded **sequentially** (T=10 folds, L=1 per fold,
cyclo-digest.md §6.5 recommended pattern):

- Total accumulated constraints: m_acc ≈ 53,248 per fold step.
- This is **well below** the m=2^20 working hypothesis (cyclo-digest.md §5.1
  benchmark uses m=2^20 for the full accumulator, not per-input).
- ✅ Fits within m=2^20 without parameter renegotiation.

### 6.3 Norm Growth at Sequential T=10

From Cyclo Theorem 3 (cyclo-digest.md §4.3):
- After T folds with L=1, accumulator norm grows by: β_T = β_0 + T·b·γ
- With b=2 (base), γ = operator norm of ternary challenge set ≈ √φ = √256 = 16
- After T=10: β_10 = 2^10 + 10·2·16 = 1024 + 320 = 1344

This is still ‖·‖_∞ ≤ 2^{10.4}, comfortably within the norm budget. ✓
No intermediate norm refresh required for T=10.

### 6.4 Commitment Ring Parameters (Working Hypothesis)

| Parameter | Value | Source |
|---|---|---|
| Cyclotomic degree φ_commit | 256 (X^{256}+1) | cyclo-digest.md §6.5 |
| Modulus q_commit | ≈ 2^50 (50-bit prime ≡ 1 mod 4·256) | cyclo-digest.md §6.5 |
| Ajtai rank a | 13 | cyclo-digest.md Table 2 (scaled from φ=128 → 256) |
| Initial witness norm B | 2^10 | cyclo-digest.md Table 2 |
| Challenge set | Biased ternary, p=1/3, κ_nu ≈ 2^{-94} | cyclo-digest.md §5.5 |
| Witness dimension m | ≈ 53,248 ≪ 2^20 | §6.2 above |
| Proof size (T=10 folds) | ≈ 50–60 KB accumulator | cyclo-digest.md §6.5 estimate |

---

## 7. Open Questions for L4

The following decisions must be locked at the L4 (joint spec) phase:

1. **Exact R1CS/CCS template**: Define the CCS instance encoding of `d_i = c·s_i + e_i` over R_{q_commit} — specifically the constraint matrix dimensions, NTT-domain vs. coefficient-domain representation, and which Ajtai commitment key is shared vs. per-party.

2. **SHA-256 bridging (D1 vs D2)**: Decide whether P4 commitment `C_i = SHA256(...)` is (a) replaced by Ajtai commitment over R_{q_commit} (D1 — breaks P4 interface), or (b) retained as hash-binding outside the fold with conditional-soundness banner (D2). The PVTHFHE security model requires this decision before T2 can be restated.

3. **Fiat-Shamir challenge domain**: Confirm the challenge space (biased ternary over R_{q_commit}^φ) and the exact domain-separation tag for the FS hash in `challenge_bytes()`. Must be compatible with the existing `session_id || pvss_commitment` tag in `RealNizkAdapter::challenge_bytes`.

4. **Sequential vs. batched aggregation of n=1024 per-share NIZKs**: Lock the fold pattern (T=10 sequential folds, L=1 each as recommended in cyclo-digest.md §6.5) vs. any batched variant. The norm explosion risk for L≥2 batched folds must be explicitly ruled out.

5. **Witness packing strategy**: Determine whether `s_i` (ternary, 1 bit/coeff) and `e_i` (4-bit Gaussian) are packed into the same R_{q_commit} witness vector or kept separate. Separate packing enables tighter norm bounds (ternary witness has ‖·‖_∞=1 vs. 16 for error).

6. **Cyclo implementation path**: Decide whether to (a) implement Cyclo from the ePrint 2026/359 paper starting from NethermindEth/latticefold, or (b) await an official reference implementation. Gate Phase 2 start on this decision.

7. **`NizkProof` format migration**: Define the binary format for the Cyclo-companion proof payload (replacing `ProofPayload` in `real_nizk.rs`) and the versioning/migration path for existing test vectors in `tests/lattice_nizk.rs` and `tests/lattice_nizk_adversarial.rs`.

---

## 8. References

- **Cyclo**: Garreta, Lipmaa, Luhaäär, Osadnik — "Cyclo: Lightweight Lattice-based Folding via Partial Range Checks", IACR ePrint 2026/359 (Eurocrypt 2026). See cyclo-digest.md for full digest.
- **MicroNova**: Zhao, Setty, Cui, Zaverucha — "MicroNova", IACR ePrint 2024/2099 (S&P 2025). See micronova-digest.md.
- **LatticeFold+**: Boneh, Chen — "LatticeFold+", IACR ePrint 2025/247 (CRYPTO 2025).
- **LaBRADOR**: Beullens, Seiler — "LaBRADOR: Compact Proofs for R1CS from Module-SIS", IACR ePrint 2022/1341 (CRYPTO 2023).
- **Greyhound**: [CITATION NEEDED — candidate: Beullens, Seiler 2024 — "Greyhound" succinct lattice IOP, ePrint 2024/352 if correct].
- **Lyubashevsky sigma**: Lyubashevsky — "Lattice Signatures Without Trapdoors", IACR ePrint 2011/537 (EUROCRYPT 2012).
- **MatRiCT / Esgin et al. CRYPTO 2019**: Esgin, Nguyen, Seiler, Steinfeld — "MatRiCT: Efficient, Scalable and Post-Quantum Blockchain Confidential Transactions Protocol", IACR ePrint 2019/1287 (CCS 2019).
- **Raptor / Esgin et al. CRYPTO 2020**: Esgin, Steinfeld, Zhao — "Matricial Lattice Sigma Proofs", IACR ePrint 2020/518 [CITATION NEEDED — confirm exact title/ref].
- **Kiltz-Lyubashevsky-Schaffner QROM**: Kiltz, Lyubashevsky, Schaffner — "A Concrete Treatment of Fiat-Shamir Signatures in the Quantum Random Oracle Model", IACR ePrint 2017/916 (EUROCRYPT 2018).
- **Module-SIS hardness**: Langlois, Stehlé — "Worst-case to Average-case Reductions for Module Lattices", Designs, Codes and Cryptography (2015).
- **P1 theorem inventory**: `docs/security-proofs/p1/theorem-inventory.md` (this repo).
- **Proof boundary**: `.sisyphus/design/proof-boundary.md` (this repo).
- **PVTHFHE parameters**: `.sisyphus/design/parameters.toml` (this repo).
- **NethermindEth/latticefold**: https://github.com/NethermindEth/latticefold (Apache 2.0, Rust, LatticeFold/LatticeFold+ reference implementation).
