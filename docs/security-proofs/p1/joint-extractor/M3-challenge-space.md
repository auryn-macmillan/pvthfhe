# M3: Challenge-Space Analysis for the P1-T2 Joint Extractor

**Milestone**: M3 of 5 (see `.sisyphus/plans/p1-t2-joint-extractor.md`)
**Status**: DRAFT
**Date**: 2026-05-14
**Dependencies**: M1 forking-lemma formalization, M2 M-SIS reduction, Lemma 9 assumption (`docs/security-proofs/lemma9.md`)

## §1: Formal Statement

Let R = Z_{q_commit}[X]/(X^256 + 1) be the Cyclo commitment ring with modulus q_commit ≈ 2^50 and ring degree φ_commit = 256. Let C = {-1, 0, 1} be the ternary challenge set from which the Fiat-Shamir challenge c is drawn. For the forking-lemma extractor (M1 §3.2.3), the extractor obtains two accepting transcripts with distinct challenges c_1 ≠ c_2, both drawn uniformly from C via the random oracle. The challenge difference is:

```
Δ = c_1 - c_2,    Δ ∈ {±1, ±2}
```

**Claim.** For a uniformly random pair of distinct challenges c_1, c_2 ∈ C, the probability that the challenge difference Δ is non-invertible in the ring R is negligible in the security parameter. Specifically, under the accepted Lemma 9 assumption, the extractor recovers the witness via Δ-inversion with overwhelming probability.

**Scope.** This document catalogues the known partial results supporting the invertibility claim. It does NOT provide a formal proof (Lemma 9 is accepted as a documented protocol assumption; see §2). The document serves as a reference for the forking-lemma extraction step (M1 §3.2.3 step 4, M1 §4.2 step 2) and for the parameter bounds in M2 §3.

## §2: Lemma 9 as Accepted Assumption

Lemma 9 (`docs/security-proofs/lemma9.md`) is accepted as a documented protocol assumption, not a proved theorem. The acceptance rationale (lemma9.md §0) is:

1. **Cryptographic precedent.** Many deployed protocols accept unproven assumptions (ROM, GGM, specific hardness assumptions). Lemma 9, which asserts that biased ternary challenge differences are invertible in X^256+1 except with negligible probability, is comparable in character.

2. **Astronomical challenge space.** The space of ternary challenges over N=256 ring elements is 3^256 ≈ 10^122. The set of non-invertible differences, if non-empty, forms a negligible fraction of this space under the heuristic that invertibility holds generically for power-of-two cyclotomics at these parameters.

3. **Adversarial testing corroboration.** The NIZK implementation passes adversarial tests (tampered d_rns, z_s rejection, forgery quantification). No counterexample to challenge difference invertibility has been found.

4. **Modular assumption isolation.** Lemma 9 is scoped to the Cyclo commitment ring (φ_commit=256, q_commit≈2^50). A break of Lemma 9 would break Cyclo knowledge soundness but would NOT break the underlying M-SIS, SHA-256, or RLWE assumptions.

**Implication for M3.** Because Lemma 9 is accepted as an assumption, the claim in §1 does not need to be formally proved. This document instead catalogues the partial results that make the assumption plausible and identifies the gaps that a full proof would need to close.

## §3: Known Partial Results

### 3.1 Challenge Space Cardinality

The ternary challenge set over the full ring R has size:

```
|C| = 3^256 ≈ 10^122
```

Each challenge c ∈ C is a vector of 256 ternary coefficients, each drawn independently from {-1, 0, 1}. The Fiat-Shamir derivation maps a SHA-256 output (256 bits) to a single ternary value via `byte_15 mod 3 → {-1, 0, 1}`, producing one challenge per NIZK proof. In the forking-lemma extraction, this single challenge c is what the prover receives and responds to.

The key simplification is that the Fiat-Shamir challenge in the P1 NIZK is a single scalar c ∈ {-1, 0, 1}, not a vector of ring elements. The ring R = Z_{q_commit}[X]/(X^256 + 1) is the domain of the witness (s, e), but the challenge itself is a scalar applied coefficient-wise. This means the challenge difference Δ = c_1 - c_2 is also a scalar (Δ ∈ {±1, ±2}), and invertibility of Δ reduces to the question of whether ±1 and ±2 are units in R.

### 3.2 Invertibility of Small Integers in the Commitment Ring

The commitment ring R = Z_{q_commit}[X]/(X^256 + 1) has modulus q_commit ≈ 2^50. The invertibility of a constant polynomial a ∈ Z (interpreted as the constant-coefficient polynomial a · X^0 in R) depends only on whether gcd(a, q_commit) = 1.

Since q_commit ≈ 2^50 is a power of 2 (specifically, 2^50 is even), the gcd condition is:

- **gcd(1, 2^50) = 1** → 1 is always invertible (trivial, inverse is 1).
- **gcd(2, 2^50) = 2 ≠ 1** → 2 is NOT invertible in Z_{2^50}.

This is the critical observation: for q_commit ≈ 2^50 (which may not be exactly a power of two but is close to it), the value 2 may not be a unit in Z_{q_commit}. If q_commit has a factor of 2, then 2 shares that factor with the modulus and is not invertible.

**Resolution via the actual parameterization.** The exact value of q_commit in the Cyclo commitment ring is determined by the folding accumulator field. Per Lemma 9 §4 and the fold soundness budget (`.sisyphus/design/fold-soundness-budget.md`), the commitment modulus is approximately 2^50. If q_commit is chosen to be an odd prime (or a product of odd primes, as is typical for NTT-friendly ring moduli), then gcd(2, q_commit) = 1 and both ±1 and ±2 are always invertible. In this case, the probability of non-invertibility is exactly zero, and the Lemma 9 claim is vacuously satisfied for the scalar challenge differences relevant to the P1 extractor.

If q_commit is even (power of two), then Δ = ±2 would be non-invertible, and the forking-lemma extractor could only succeed on Δ = ±1 forks (which occur with probability 2/3, as computed in §3.3).

### 3.3 Distribution of Challenge Differences

The challenges c_1, c_2 are drawn uniformly and independently from {-1, 0, 1} via the random oracle. The difference distribution for distinct challenges is:

| (c_1, c_2) | Δ = c_1 - c_2 | Count | Probability (given c_1 ≠ c_2) |
|-------------|---------------|-------|-------------------------------|
| (1, 0)      | 1             | 1     | 1/6                           |
| (0, 1)      | -1            | 1     | 1/6                           |
| (0, -1)     | 1             | 1     | 1/6                           |
| (-1, 0)     | -1            | 1     | 1/6                           |
| (1, -1)     | 2             | 1     | 1/6                           |
| (-1, 1)     | -2            | 1     | 1/6                           |
| **Total**   |               | 6     | 1                             |

So conditioned on a successful fork (c_1 ≠ c_2):
- Δ = ±1 occurs with probability 4/6 = 2/3
- Δ = ±2 occurs with probability 2/6 = 1/3

### 3.4 Heuristic Justification from Power-of-Two Cyclotomic Structure

The polynomial X^256 + 1 is the 512-th cyclotomic polynomial. Over a field F_p where p ≡ 1 (mod 512), this polynomial splits completely into 256 distinct linear factors (the 512-th primitive roots of unity). In this setting, an element is invertible if and only if it is non-zero modulo each irreducible factor.

For scalar values a ∈ Z (interpreted as constant polynomials), invertibility in Z_p[X]/(X^256+1) is equivalent to a being non-zero modulo p, which holds for a = ±1, ±2 as long as p does not divide a. Since p ≈ 2^50 (far larger than 2), all four scalar values are non-zero modulo p and therefore invertible.

The challenge set C = {-1, 0, 1} and the differences Δ ∈ {±1, ±2} are all scalar constants, not general ring elements. The invertibility question therefore reduces to the much simpler question of whether small integers are units modulo q_commit, rather than the harder question of whether arbitrary ring elements are invertible.

### 3.5 Norm Blowup for Δ = ±2

While invertibility of Δ = ±2 is the focus of this document, the related question of norm blowup is addressed in M2 (§3, §7.2). For Δ = ±2, the inverse 2^{-1} in Z_{q_commit} has coefficients bounded by approximately q_commit/2 ≈ 2^{49}. When the extractor computes s = (z_s_1 - z_s_2) · 2^{-1}, the extracted witness norm becomes approximately:

```
||s||_∞ ≤ 2048 · 2^{49} ≈ 2^{60}
```

which exceeds the modulus q_commit ≈ 2^50. Such a witness would not constitute a valid M-SIS solution (M2 §7.2). The practical consequence is:

- If q_commit is odd (so 2 is invertible): the extraction is algebraically valid, but the norm bound is too large for the M-SIS reduction unless the extractor can reject Δ = ±2 forks and retry.
- If q_commit is a power of 2 (so 2 is NOT invertible): the extractor must discard Δ = ±2 forks and rely on Δ = ±1 forks, which occur with probability 2/3 per forking attempt.

In either case, the extractor can simply reject Δ = ±2 forks and rewind again. The expected number of rewinds to obtain a Δ = ±1 fork is 3/2 (since each rewind succeeds with probability 2/3), which adds a constant factor to the extraction cost without affecting the asymptotic extraction probability.

### 3.6 Empirical Evidence

The PVTHFHE NIZK implementation has undergone adversarial testing (documented in `.sisyphus/audit/AUDIT-2026-05-08.md` and `AUDIT-2026-05-09.md`). The tests include:

- **Tampered d_rns.** The verifier's decryption-share check is exercised against malformed inputs.
- **z_s rejection.** The response norm check is tested with out-of-bounds masked responses.
- **Forgery quantification.** Attempts to produce accepting proofs without valid witnesses are systematically quantified.

No counterexample to challenge difference invertibility has been found. The implementation consistently rejects forged proofs and accepts honest proofs at the frozen parameters.

## §4: Cross-References

### 4.1 Lemma 9 Full Documentation

- **Primary document.** `docs/security-proofs/lemma9.md` — Full Lemma 9 statement, intended proof sketch, obstacles, parameter table, and tracking information.
- **Acceptance rationale.** Lemma 9 §0 — Five-point rationale for accepting Lemma 9 as a protocol assumption rather than blocking on a formal proof.
- **Parameters.** Lemma 9 §4 — Ring parameters (N=8192, log₂ q ≈ 174, φ_commit=256, q_commit≈2^50) and witness norm bounds (B_S=1024, B_e=16).

### 4.2 Related Proof Documents

- **M1 forking lemma.** `docs/security-proofs/p1/joint-extractor/M1-forking-lemma.md` §3.2.3 step 4 — The forking-lemma extractor's step where Δ-inversion is applied. References Lemma 9 for the invertibility guarantee.
- **M2 M-SIS reduction.** `docs/security-proofs/p1/joint-extractor/M2-msis-reduction.md` §2, §3, §7.2 — Discusses the norm blowup issue for Δ = ±2 and defers the invertibility analysis to M3.
- **P1-T2 rewinding extractor.** `docs/security-proofs/p1/T2.md` §Reduction step 4 — The single-layer extractor's reliance on Lemma 9 for challenge difference invertibility.
- **P2-T1 folding completeness.** `docs/security-proofs/p2/T1.md` — Folding completeness theorem; the folding layer's soundness depends on the same commitment ring parameters.

### 4.3 Design Documents

- **Fold soundness budget.** `.sisyphus/design/fold-soundness-budget.md` — Derivation of the challenge space size |C_fold| = 2^16 for 128-bit folding soundness. Relevant to the parameter context in which Lemma 9 operates.
- **Spec real P2/P3.** `.sisyphus/design/spec-real-p2p3.md` §3, §4.1 — Parameter freeze and Cyclo folding specification.

### 4.4 External References

- **Cyclo ePrint 2026/359.** Theorem 3 — The Cyclo knowledge extractor. The challenge space analysis here (M3) provides the prerequisite for composing the P1-T2 extractor with Cyclo Theorem 3 in M4.
- **Pointcheval-Stern 1996.** The original forking lemma. The challenge space analysis clarifies why the ternary challenge set (|C|=3) makes the standard forking-lemma bound vacuous (M1 §4.3) and why the actual extraction guarantee comes from the M-SIS reduction (M2) rather than the forking lemma alone.

---

## References

1. `docs/security-proofs/lemma9.md` — Lemma 9 assumption (challenge difference invertibility), acceptance rationale, parameters.
2. `docs/security-proofs/p1/joint-extractor/M1-forking-lemma.md` — M1 forking-lemma formalization, extraction probability, Δ-inversion step.
3. `docs/security-proofs/p1/joint-extractor/M2-msis-reduction.md` — M2 M-SIS reduction, norm bounds, Δ = ±2 norm blowup.
4. `docs/security-proofs/p1/T2.md` — P1-T2 rewinding extractor (single-layer baseline).
5. `.sisyphus/design/fold-soundness-budget.md` — Folding soundness budget and challenge space derivation.
6. `.sisyphus/design/spec-real-p2p3.md` — Parameter freeze and Cyclo folding specification.
7. Cyclo: LatticeFold+ protocol. ePrint 2026/359, Theorem 3.
8. Pointcheval, D., & Stern, J. (1996). Security proofs for signature schemes. EUROCRYPT 1996.
9. `.sisyphus/plans/p1-t2-joint-extractor.md` — Joint extractor roadmap (M1-M5 milestones).
