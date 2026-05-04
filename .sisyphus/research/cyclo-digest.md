# Cyclo: Implementation-Oriented Digest

**Paper**: IACR ePrint 2026/359 — "Cyclo: Lightweight Lattice-based Folding via Partial Range Checks"  
**Authors**: Albert Garreta (Nethermind Research), Helger Lipmaa (University of Tartu), Urmas Luhaäär (University of Tartu), Michał Osadnik (Aalto University)  
**Version**: Eurocrypt 2026 major revision (2026-04-13)  
**License**: CC BY  
**Reference URL**: https://eprint.iacr.org/2026/359

---

## 1. Paper Metadata

| Field | Value |
|-------|-------|
| Full title | Cyclo: Lightweight Lattice-based Folding via Partial Range Checks |
| Authors | Albert Garreta, Helger Lipmaa, Urmas Luhaäär, Michał Osadnik |
| Affiliations | Nethermind Research; University of Tartu; Aalto University |
| Publication | Eurocrypt 2026 (major revision) |
| Revision date | 2026-04-13 |
| Original submission | 2026-02-22 |
| License | CC BY |
| Contact | albert@nethermind.io, helger.lipmaa@ut.ee, u.luhaar@ut.ee, michal.osadnik@aalto.fi |

**Relationship to prior work**: Cyclo improves upon LatticeFold+ (Boneh-Chen, CRYPTO 2025) and incorporates pay-per-bit techniques from Neo (Nguyen-Setty, 2026). The authors are the same team behind the Nethermind Eth/latticefold Rust implementation.

---

## 2. The Folding Relation (Formal)

### 2.1 What Cyclo Folds

Cyclo folds **R1CS/CCS over $\mathbb{F}_q$** reduced to a **linear relation over $\mathcal{R}_q$** via the polynomial evaluation map.

The relation structure:
- **Input**: A constraint system (R1CS or CCS) over a prime field $\mathbb{F}_q$
- **Reduction**: The constraint system is converted to a linear relation over the cyclotomic ring $\mathcal{R}_q = \mathbb{Z}_q[X]/(\Phi_d(X))$
- **Witness**: A vector $\mathbf{w}$ satisfying the linear relation
- **Commitment**: Ajtai/module-SIS commitment to the witness

### 2.2 Ring and Witness Shape

| Parameter | Description |
|-----------|-------------|
| Ring | $\mathcal{R}_q = \mathbb{Z}_q[X]/(\Phi_d(X))$ where $\Phi_d$ is the $d$-th cyclotomic polynomial |
| Ring degree | $n = \varphi(d)$ (Euler's totient of $d$) |
| Modulus | $q$ — paper supports arbitrary cyclotomic rings including power-of-two cyclotomics |
| Witness shape | Vectors in $\mathcal{R}_q^m$ for some dimension $m$ |
| Norm bound | Witnesses must satisfy $\ell_\infty$-norm bound $B$ |

The paper supports the **complete family of cyclotomic rings**, meaning $d$ can be any integer giving suitable security/performance tradeoffs.

### 2.3 Public Statement / Instance Shape

An instance consists of:
- Commitment matrix $A \in \mathcal{R}_q^{m \times m}$ (public key / setup)
- Committed values $u, v \in \mathcal{R}_q$ (public IO)
- Commitment $c = A \cdot w$ to the witness $w$

### 2.4 Accumulator Structure

The **accumulator** in Cyclo is a pair:
1. **Commitment** to the folded witness: $c_{\text{acc}} = A \cdot w_{\text{acc}}$
2. **Auxiliary fields**: Contains the public IO and any error terms

Unlike LatticeFold+, Cyclo's accumulator does **not** require norm checks after folding — this is the key efficiency improvement.

---

## 3. The Protocol — Round-by-Round

### 3.1 Two Main Building Blocks

#### (a) Extension Commitment (Norm Reduction)

**Purpose**: Reduce the norm of a witness by decomposing and recommitting.

**Inputs**: A witness $w$ with potentially large norm  
**Outputs**: A new commitment to decomposed low-norm chunks

**Mechanism**:
1. Decompose $w$ into $k$ chunks $w_0, w_1, \ldots, w_{k-1}$ such that each chunk has small norm (base-$b$ decomposition)
2. Recommit to each chunk separately using Ajtai commitment
3. The extension commitment proves consistency between the original commitment and the decomposed commitments

This is the **norm-refreshing** step that allows Cyclo to avoid norm checks on the accumulator.

#### (b) $\ell_\infty$ Range Test via Sum-Check

**Purpose**: Prove that a committed vector has $\ell_\infty$-norm bounded by $b$.

**Inputs**: Commitment to a vector, norm bound $b$  
**Outputs**: Sum-check proof establishing the norm bound

**Mechanism**:
- The prover wants to show $\|f\|_\infty < b$ for a committed polynomial/vector $f$
- This is encoded as a polynomial identity check: $f \circ \prod_{i=1}^{B-1}(f - i) \circ (f + i) = 0$
- The sum-check protocol is used to prove this evaluation statement
- This is the **only** place where sum-check is invoked over the cyclotomic ring

### 3.2 Amortized Norm-Refreshing

**Key innovation**: Cyclo eliminates norm checks **on the accumulator** by adopting an amortized norm-refreshing design.

**How it works**:
1. Norm checks are performed **only on the input non-accumulated witness** (the new witness being folded)
2. The accumulator's norm grows **additively** per round, but within a generously bounded number of folds
3. After a bounded number of folds, a norm refresh is applied to the accumulator

**When are norm checks done?**
- **On non-accumulated input witness**: Yes, every fold
- **On accumulator**: No — norm refresh is amortized over many folds

This is fundamentally different from LatticeFold+, which required range proofs on all input witnesses (including accumulated ones) every round.

### 3.3 Pay-per-Bit Technique (from Neo)

When folding constraints over $\mathbb{F}_q$, Cyclo **does not decompose witnesses into low-norm chunks within the folding protocol itself**.

The pay-per-bit technique (from Neo/Nguyen-Setty 2026):
- The cost to commit scales with the bit-width of the scalars
- Committing to a vector of bits is $b$-times cheaper than committing to a vector of $b$-bit values
- Achieved via a folding-friendly instantiation of Ajtai commitments under Module-SIS

**What bits are paid for?**
- The bit-width of the field elements being committed
- Small field elements (e.g., 64-bit primes like Goldilocks) have low pay-per-bit cost
- This is a property inherited from Neo's construction

### 3.4 Protocol Flow (High-Level)

```
Prover                           Verifier
  |                                 |
  |  1. Commit to witness w         |
  |  2. Extension commitment       |
  |     (decompose + recommit)      |
  |  3. ℓ∞ range test (sum-check)  |
  |     on non-accumulated w        |
  |-------------------------------->|
  |  4. Receive challenges (FS)     |
  |                                 |
  |  5. Folding proof               |
  |-------------------------------->|
  |                                 |
  |  (Accumulator updated,          |
  |   no norm check needed)         |
```

The protocol is non-interactive via Fiat-Shamir (Folding scheme, not interactive).

---

## 4. Soundness Theorems (from full PDF)

### 4.1 Theorem 1 — Range Test (Πᵇ_range, Section 4)

For prime q, cyclotomic ring R with conductor f, A ∈ R_q^(a×m), φ = φ(f), the range protocol verifies a committed witness w ∈ R_q^m has ‖w‖_∞ ≤ b.

**Knowledge soundness error**: κ := ℓ(2b+2)/q^e   where ℓ = ⌈log(mφ)⌉

The reduction lifts the linear relation Ξ^lin_{A,a,n,b} ∪ Ξ^sis_b̂ ← Ξ^{lin-slack}_{A,n+1,b̃,ϱ} for b̂ = 2b̃γϱ.

**Communication**: 1 R_{q^e} element + (2b+2)ℓ + 1 F_{q^e} elements.

**Mechanism**: Sum-check over the polynomial identity f(X) · ∏_{j∈[-b,b]} (f(X)−j) = 0, evaluated multilinearly. The extractor uses standard rewinding; expected polynomial-time.

### 4.2 Theorem 2 — Extension Commitment (Π^ext_{b,C}, Section 5)

For prime q, R cyclotomic with conductor f, parameters b, B, k, n, B̃, ϱ, A ∈ R_q^(a×m), R ∈ R_q^(a'×mℓ), C strong sampling set with C ⊆ F_{q^e}, b ≥ 2.

**Knowledge soundness error**: ℓ_C/|C|   where ℓ_C := ⌈log₂ a⌉

The reduction Ξ^lin_{A,(M_i),a,n,m,B} ∪ Ξ^sis_{R,a',mℓ,2b} ← Ξ^lin_{R,a',n,mℓ,b}.

**Communication**: a' R_q elements (the extended commitment t = Rv).

**Mechanism**: Vertical decomposition v^T = (w_0^T, ..., w_{ℓ-1}^T) with each ‖w_i‖_∞ ≤ b and w = Σ w_i b^i, then re-commit to the concatenation. Verifier samples ĉ ← C^{ℓ_C} and combines via tensor(ĉ).

### 4.3 Theorem 3 — Cyclo Folding Scheme (Π^fs_{b,D,C}, Section 6)

For prime q, R cyclotomic with conductor f, b, B ∈ ℕ, A ∈ R_q^(a×m), R ∈ R_q^(a'×m·log_{2b} 2B), φ = φ(f), C ⊆ R_q strong sampling set, D ⊆ R_q κ_nu-approximate strong sampling set, γ = operator norm of D.

**(1) Correctness**: Ξ^lin_acc,β × (Ξ^lin_{a,n,m,B})^L → Ξ^lin_acc,β+Lbγ. Norm grows additively per fold by Lbγ.

**(2) Knowledge soundness error**:

```
κ ≤ L/|D| + (ℓ₀ + ℓ₁)/q^e + Lℓ₁(2b+2)/q^e + Lℓ_C/|C| + Lκ_nu
    └─ folding ─┘  └sum-check┘  └─── range ───┘  └ extension ┘  └non-units┘
```

where:
- ℓ₀ := ⌈log φ(2 + k + L(2 + n + k))⌉
- ℓ₁ := ⌈log(mφ · log_{2b} 2B)⌉
- ℓ_C := ⌈log a⌉

**Reduction with slack**: Ξ^sis_{R,2β̄δ} ∪ (Ξ^{lin-slack}_acc,β̂+Lbγ × (Ξ^lin_{a,n,m,B})^L) ← Ξ^lin_acc,β̂

with **norm/slack growth after extraction**:
- β̄ = β̂(2γ)^L + L · 2β̂(2γ)^{L-1}
- δ = (2γ)^L

**Communication**:
- La' + L elements in R_q
- (k+2)·(L+1) elements in R_{q^e}
- 2⌈log(mφ · log_{2b} 2B)⌉ F_{q^e} elements
- L(2b+2)⌈log(mφ · log_{2b} 2B)⌉ F_{q^e} elements

**Extractor**: Coordinate-wise forking via Lemma 4 (rewind one coordinate at a time, ROM-reprogrammed). Expected polynomial-time.

### 4.4 Cryptographic Assumptions

| Assumption | Role |
|---|---|
| **Module-SIS over R_q** | Binding of Ajtai commitments; extractor's fallback witness |
| **Random Oracle Model** | Coordinate-wise forking lemma requires domain-separated RO tags |
| **Approximate strong sampling sets** | Challenge distributions D, C; κ_nu = Pr[difference non-invertible] |
| **Schwartz–Zippel over F_{q^e}** | Sum-check soundness |

Plausibly post-quantum (M-SIS hardness).

---

## 5. Parameter Table (from Appendix C.1, Table 2)

### 5.1 Authors' Concrete Parameters

| Parameter | LatticeFold+ [BC25b] | Cyclo (this paper) |
|---|---|---|
| Rank a (Ajtai commitment) | 9 | **13** |
| Modulus q | ≈ 2^128 | **≈ 2^50** |
| Cyclotomic degree φ | 64 | **128** |
| Folding depth T | ∞ | 64 (extends to 2^20) |
| Initial norm B | 2^10 | **2^10** |
| Challenge distribution | {-1, 0, 1, 2}^φ | **{-1, 0, 1}^φ (biased ternary, p=1/3)** |
| Witness size m (R_q elements) | 2^21 | **2^20** |
| Total Z_q coefficients (φ·m) | 2^27 | **2^27** |
| Folded relations | 2 (accumulator) + 1 | **1 (accumulator) + 1** |
| Other parameters | L=3 | **e=2, L=1, k=3, n=1** |
| **Proof size** | 100 KB | **31.8 KB** |

### 5.2 Proof Size Sensitivity (Remark 9)

| Setting | Proof Size |
|---|---|
| Baseline (T=64, λ=128, κ=2^-80) | 31.8 KB |
| Folding depth T = 2^10 | 39.7 KB |
| Folding depth T = 2^20 | 41.7 KB |
| Security λ = 256 | 40.4 KB |
| Soundness κ = 2^-200 (e=4) | 52.4 KB |
| λ=256 ∧ κ=2^-200 simultaneously | 61 KB |

(Folding depth scales **logarithmically** in proof size — favorable for n=1024 parties.)

### 5.3 Prover Time (Section 6.1, paragraph "Comparison with [BC25b]")

For mφ = 2^27, excluding sum-check: **~36.6 s** (Cyclo) vs **129.4 s** (LatticeFold+) — ~3.5× speedup, single-threaded, AVX-512-IFMA-accelerated via Intel HEXL on q ≈ 2^50.

### 5.4 Asymptotic Complexity (Remark 3)

- **Prover**: O(L · a' · m · log_{2b} 2B) R_q-multiplications (dominant cost)
- **Verifier** (excluding hashing): O(L · a') R_q-multiplications
- **Online instance**: L · (a' + k + n) R_q-elements
- **Accumulated instance**: (a' + k + 1) R_q-elements
- **Folding proof**: La' + L in R_q, (k+2)·(L+1) in R_{q^e}, plus F_{q^e} sum-check transcripts (above)

### 5.5 Invertibility / Sampling Set Heuristic (Lemma 9)

For R = ℤ[X]/(X^φ + 1) with f = 2φ, q = 2k+1 (mod 4k) prime, biased ternary (p=1/3) over S = {c : ‖c‖_∞ ≤ 1}:

**κ_nu ≈ k / q^{φ/k}**

For φ=128, q≈2^50: κ_nu ≈ 2^-94 (negligible vs κ=2^-80).

**LIMITATION**: Lemma 9 is **specialized to power-of-two cyclotomic rings** (X^φ+1). Authors leave the generalization to arbitrary cyclotomic rings as future work.

---

## 6. Compatibility with PVTHFHE Parameters (REVISED)

### 6.1 PVTHFHE Target

| Parameter | Value |
|---|---|
| RLWE ring degree N (constraint side) | 8192 |
| RLWE modulus log₂q (constraint side) | ~174 bits, 3 RNS limbs |
| Plaintext modulus t | 2^17 |
| Target parties n | up to 1024 |

### 6.2 Two Independent Moduli (KEY INSIGHT)

A subtlety missed in the prior digest revision: Cyclo distinguishes:

1. **Constraint-side field F_q_constraint** — the field over which R1CS/CCS is expressed. For PVTHFHE this is the FHE arithmetic field (~174-bit composite from the RNS chain) OR a smaller prime if we lift to native R1CS over a SNARK-friendly field.
2. **Commitment-side ring R_q_commit** — the cyclotomic ring of the Ajtai commitment underlying the folding. Cyclo's benchmarks use q_commit ≈ 2^50.

The two are bridged by the θ_k : R_q_commit → F_q_constraint map (Section 7.1, Lemma 5), which requires:

**ℓ_k(q_constraint) = ⌈log_k(q_constraint)⌉ < φ**

For k=2 (binary) and q_constraint ≈ 2^174: need φ ≥ 175. Authors' φ=128 is **insufficient** for direct binary encoding of PVTHFHE field elements.

### 6.3 Revised Parameter Compatibility Matrix

| Item | PVTHFHE need | Cyclo bench | Status / Action |
|---|---|---|---|
| Power-of-2 cyclotomic | X^8192+1 (constraint) | X^128+1 (commitment) | OK — Lemma 9 covers power-of-2 |
| Commitment ring degree φ | choose ≥ 256 (to encode 174-bit) | 128 | **Resize**: φ=256 or 512 doubles witness/proof |
| Commitment modulus q_commit | choose ≈ 2^50 (any small prime) | 2^50 | OK — independent of PVTHFHE 174-bit q |
| Folding depth T | log₂(1024)=10 sequential folds, OR n=1024 batched | 64 (scales to 2^20) | OK — depth fits |
| Witness count φ·m | depends on circuit (per-share NIZK output × 1024) | 2^27 | **TBD**: needs P1 NIZK output budget |
| Number of accumulated relations | 1024 per epoch | L=1 in benchmark | OK — paper says T=2^20 still gives 41.7 KB |
| Norm growth at depth T=10 | β grows by Lbγ per round, must stay below 2^{50}/(2γ)^L | Tested at L=1 | **Risk**: with L=1024 batched, β̂(2γ)^1024 explodes; must use sequential T-fold pattern |

### 6.4 Updated Risks

| Risk | Severity (revised) | Notes |
|---|---|---|
| Constraint-modulus encoding (φ ≥ 175) | **MED** (was HIGH) | Resolved by choosing φ=256 commitment ring; ~2× cost vs paper |
| Norm explosion (2γ)^L when batching 1024 in one fold | **HIGH** | Must use **sequential** T=10 folds (L=1 each) not L=1024 batched |
| Witness count after R1CS reduction of 1024 NIZKs | **HIGH** (UNKNOWN) | Depends on P1 NIZK output shape; needs L3+L4 design |
| No native handling of ≥3 RNS limbs in folding | **LOW** (was MED) | Folding ring is independent; RNS lives only in R1CS witness |
| Reference impl exists but is research-only | **MED** | https://github.com/osdnk/cyclo has notebooks (estimates.ipynb, invertibility.ipynb); no production Rust |

### 6.5 Recommended Cyclo Parametrization for PVTHFHE

Working hypothesis (to be validated in L4):
- **Commitment ring**: φ = 256, X^256+1, q_commit ≈ 2^50 (50-bit prime ≡ 1 mod 4·k)
- **Constraint encoding**: k = 2, ℓ_2(2^174) = 174 < 256 ✓ (binary encoding fits)
- **Folding pattern**: sequential T = ⌈log₂(n)⌉ ≈ 10 folds, L = 1 per fold (avoid (2γ)^L blow-up)
- **Initial norm B**: 2^10 (matches paper); confirm P1 NIZK outputs respect this bound
- **Sampling set**: biased ternary (p=1/3) over S = {c : ‖c‖_∞ ≤ 1}; expected κ_nu ≈ 2^-94
- **Estimated proof size**: scale 31.8 KB by (256/128) ≈ ~50–60 KB per fold output

---

## 7. Implementation Pointers

### 7.1 Reference Implementation

**Status**: A research reference (notebooks only) exists at https://github.com/osdnk/cyclo (invertibility.ipynb, estimates.ipynb). No production Rust implementation as of Eurocrypt 2026 paper revision (2026-04-13).

The NethermindEth/latticefold repository (https://github.com/NethermindEth/latticefold) contains:
- **latticefold**: Main crate for LatticeFold and LatticeFold+
- **latticefold-plus**: Improved version (WIP)
- **cyclotomic-rings**: Ring trait definitions and implementations

**No `cyclo` crate exists** in the repository as of the last update (December 2025). Cyclo is a newer protocol (Eurocrypt 2026) and implementation may be forthcoming.

### 7.2 Repository Details

| Field | Value |
|-------|-------|
| Language | Rust (98.4%) |
| License | Apache 2.0 |
| Status | Proof-of-concept, not production-ready |
| Last push | 2025-12-17 |
| Stars | 126 |
| Main branch | main |

### 7.3 Closest Open-Source Folding Implementations to Study

1. **NethermindEth/latticefold** — LatticeFold and LatticeFold+ reference (Apache 2.0, Rust)
2. **microsoft/Nova** — Original folding scheme (not lattice-based, but foundational)
3. **geometryresearch/nova** — Rust implementation of Nova-style folding

### 7.4 Ancillary Primitives and Rust Crates

| Primitive | Likely Crate |
|-----------|--------------|
| Sumcheck | Jolt-based adaptation in latticefold repo |
| Lattice commitment | Ajtai commitment in latticefold |
| Transcript | Poseidon-based (PoseidonTranscript) |
| Cyclotomic rings | `stark-rings`, `cyclotomic-rings` (from Nethermind) |
| R1CS/CCS | Built into latticefold crate |

**Key crates from NethermindEth/latticefold**:
- `latticefold` — main folding implementation
- `latticefold-plus` — improved folding
- `cyclotomic-rings` — ring abstractions
- `stark-rings` — low-level ring arithmetic with NTT

---

## 8. Risk Register for PVTHFHE Integration

| Risk | Severity | Description | Mitigation |
|------|----------|-------------|------------|
| **Constraint count in Noir/UltraHonk** | HIGH | Verifying Cyclo accumulator inside Noir circuit may exceed practical gate counts | Profile the constraint count; consider delegated verification (MicroNova-style) |
| **Norm growth at n=1024** | HIGH | Amortized norm-refreshing may not handle 1024 parties within bounded norm | Increase norm bound budget or add intermediate refresh rounds |
| **Ring degree mismatch** | HIGH | Cyclo optimized for N≈1024; PVTHFHE uses N=8192 | Parameter study needed; possibly use ring switching or hierarchical folding |
| **Modulus shape incompatibility** | MED | 174-bit 3-limb RNS vs small-field preference | Evaluate if large-modulus folding is needed or if per-share folding works |
| **NIZK input format** | MED | Per-share NIZK must output foldable format | Define concrete interface: what shape must per-share proof/witness have? |
| **MicroNova compatibility** | MED | Cyclo accumulator must encode into MicroNova-style instance | Define accumulator serialization format; verify homomorphism properties |
| **No reference implementation** | MED | Cyclo has no code repository; must derive from paper | Study LatticeFold+ thoroughly; implement Cyclo from spec |
| **Soundness proof gaps** | LOW | Formal extractability proof not reviewed | Engage with paper authors or formal verification |

---

## 9. Key Open Questions for Implementation

1. **What is the exact accumulator format?** (commitment + auxiliary fields structure)
2. **How many folds before norm refresh is required?** (amortization parameter)
3. **What ring parameters (degree, modulus) are used in the paper's benchmarks?**
4. **Does the polynomial evaluation map handle arbitrary cyclotomic rings?**
5. **What is the interface to the sum-check subprotocol?**

---

## References

- Boneh, Chen — LatticeFold+ (ePrint 2025/247)
- Nguyen, Setty — Neo (ePrint 2026/242)
- Garreta et al. — Cyclo (ePrint 2026/359)
- NethermindEth/latticefold — https://github.com/NethermindEth/latticefold

---

*Digest compiled: 2026-05-03*
*Sources: IACR ePrint, Nethermind blog, GitHub, secondary analysis*
*Updated: 2026-05-04 — sections 4, 5, 6 populated from full PDF text extraction (eprint 2026/359, 2654 lines via pdftotext)*
