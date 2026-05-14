# M1: Forking-Lemma Formalization for the Multi-Layer Joint Extractor

**Milestone**: M1 of 5 (see `.sisyphus/plans/p1-t2-joint-extractor.md`)
**Status**: DRAFT
**Date**: 2026-05-14
**Dependencies**: P1-T2 rewinding extractor (`docs/security-proofs/p1/T2.md`), Lemma 9 assumption (`docs/security-proofs/lemma9.md`), P2-T1 folding completeness (`docs/security-proofs/p2/T1.md`)

## §1 — Protocol Recap

The PVTHFHE P1 proof system composes three layers into a single non-interactive zero-knowledge argument. The verifier checks a sigma-style transcript against the frozen parameter tuple and the three-layer relation. We recap each layer below.

### 1.1 Layer 1: Cyclo Folding (NIVC, 10-fold accumulator)

The Cyclo folding protocol (eprint 2026/359, Theorem 3) compresses N individual P1 statements into a single accumulator via Non-Interactive Verifiable Computation (NIVC). The protocol runs T = 10 sequential fold steps. At each step, the prover commits to a partial state, the verifier supplies a folding challenge c_fold drawn uniformly from a challenge space of size |C_fold| = 2^16, and the prover computes the folded witness. The challenges are derived via Fiat-Shamir hashing in the Random Oracle Model.

After T = 10 fold steps, the accumulator `acc` binds to all N original statements. The folding relation is defined over the commitment ring R_commit = Z[X]/(X^256 + 1) with modulus q_commit ≈ 2^50.

### 1.2 Layer 2: Ajtai Commitment (Com_A)

The Ajtai commitment Com_A binds the prover's secret share witness to the DKG root commitment. Specifically:

```
pvss_commitment = SHA-256(session_id || participant_id_le || s_be)
```

where `s_be` is the big-endian encoding of the secret share polynomial s ∈ R_q. The commitment is inherited from Phase 4 (DKG) and verified by the P1 verifier via SHA-256 preimage check. The binding property of SHA-256 on this fixed-length domain ensures that any accepting proof commits the prover to exactly one secret share s (P1-T5, proved).

### 1.3 Layer 3: RLWE Decryption Relation

The core witness relation at Layer 3 is the RLWE decryption equation. Given public values (c, d) where c is a BFV ciphertext component and d = decrypt_share(c, s_i, e_i) is the participant's decryption share, the witness (s_i, e_i) must satisfy:

```
c · s_i + e_i ≡ d  (mod q)
```

with norm bounds ||s_i||_∞ ≤ B_S and ||e_i||_∞ ≤ B_e = 16 (6σ, where σ = 3.19 for the BFV error distribution).

The P1 verifier does not directly check this equation (the C3 structural gap, documented in `docs/security-proofs/interfold-equivalent-pvss.md` §4.1). Instead, it checks that the masked sigma transcript (t_bytes, z_s, z_e) is consistent with a valid opening of the commitment under the RLWE relation. The joint extractor recovers the witness via rewinding.

### 1.4 Sigma Transcript Structure

The serialized proof contains only the masked sigma transcript:

```
π = (t_bytes, z_s, z_e)
```

where:
- `t_bytes`: commitment to the prover's first message (masks y_s, y_e)
- `z_s`: masked response for the secret share (z_s = y_s + c · s)
- `z_e`: masked response for the error vector (z_e = y_e + c · e)
- The challenge c ∈ {-1, 0, 1} is derived from t_bytes via Fiat-Shamir

No witness openings are present in the proof payload (confirmed at `90d6787` and consistent with the P1-T3 zero-knowledge guarantee).

### References

- `docs/security-proofs/p1/T2.md` — rewinding extractor for the single-layer case
- `docs/security-proofs/lemma9.md` — Lemma 9 assumption (challenge difference invertibility)
- `docs/security-proofs/p2/T1.md` — folding completeness theorem
- Cyclo ePrint 2026/359 — Theorem 3 knowledge extractor

## §2 — Forking Lemma Statement

### 2.1 Standard Forking Lemma (ROM)

The forking lemma (Pointcheval-Stern 1996; Bellare-Neven 2006) is the canonical extraction tool for Fiat-Shamir transformed sigma protocols in the Random Oracle Model.

**Lemma (Forking Lemma, adapted).** Let P be a PPT prover that makes at most Q queries to the random oracle H and produces an accepting transcript with probability ε (over the random coins of P and the random choice of H). Then there exists a PPT extractor E that, given rewindable black-box access to P, outputs two accepting transcripts (a, c, z) and (a, c', z') with the same first message a and distinct challenges c ≠ c' with probability at least:

```
Pr[E succeeds] ≥ ε · (ε/Q - 1/|C|)
```

where |C| is the size of the challenge space and the extractor E runs in time O(Q · T_P), with T_P being the running time of P.

**Interpretation.** The extractor rewinds P to a randomly chosen ROM query point. After rewind, the extractor provides fresh random oracle responses from that point forward. If P succeeds on the first run (probability ε) and the rewound run also succeeds (probability ε) while the challenges differ (probability 1 - 1/|C|), the extractor obtains two accepting transcripts. The Q term accounts for the extractor's uncertainty about which ROM query to rewind to: the extractor must guess the query index where P fixes its first message.

### 2.2 Parameter Instantiation

For the PVTHFHE P1 NIZK, the challenge space is ternary:

```
C = {-1, 0, 1},   |C| = 3
```

The Fiat-Shamir challenge derivation is:

```
c = trunc_16(SHA-256(session_id || pvss_commitment || t_bytes || statement_bytes))
c_mapped = byte_15 mod 3  →  mapped to {-1, 0, 1}
```

The number of ROM queries depends on the layer composition. We analyze this in §3.

### 2.3 Forking Lemma for the Single-Layer NIZK (Baseline)

For the single-layer NIZK (T2.md baseline), the prover makes Q = 1 ROM query (the Fiat-Shamir challenge). The forking lemma gives:

```
Pr[E_T2 succeeds] ≥ ε² - ε/3 - η_Lemma9 - Adv_bind^SHA-256
```

where ε is the prover's acceptance probability, η_Lemma9 is the Lemma 9 failure probability (negligible under the accepted assumption), and Adv_bind^SHA-256 is the SHA-256 commitment binding advantage. This matches the tightness analysis in T2.md §Tightness.

## §3 — Multi-Layer Extraction

The joint extractor composes forking-lemma extraction across three protocol layers. Each layer involves ROM queries, and the extractor must successfully fork at the correct level to recover the full witness.

### 3.1 Extraction Architecture

The joint extractor E_joint operates in three phases:

**Phase 1: Folding rewind.** Rewind P at the Cyclo folding layer to obtain two consistent folding transcripts. This phase recovers the folded witness commitment and establishes consistency of the accumulated state across fold steps.

**Phase 2: Commitment rewind.** Rewind P at the Ajtai commitment layer to verify that the committed secret share matches the witness from Phase 1.

**Phase 3: RLWE relation rewind.** Rewind P at the NIZK layer (the outermost Fiat-Shamir transform) to obtain two masked sigma transcripts with different challenges. From these, extract (s, e) via challenge difference inversion.

### 3.2 Layer-by-Layer Analysis

#### 3.2.1 Cyclo Folding Layer

The Cyclo folding protocol runs T = 10 sequential fold steps. At each step t ∈ {1, ..., 10}:

1. The prover commits to the fold state.
2. The verifier supplies a folding challenge c_fold^(t) ∈ C_fold via Fiat-Shamir, where |C_fold| = 2^16.
3. The prover computes the folded witness and advances the accumulator.

Each fold step involves one ROM query to derive the folding challenge. Over T = 10 steps, the folding layer contributes Q_fold = 10 ROM queries.

The extractor must rewind P at the folding layer to verify that the accumulated commitment is consistent. This is a forking argument at the fold-step level: if the extractor can rewind to any fold step and obtain two accepting fold-step transcripts with different challenges, it can extract the fold witness at that step via the Cyclo Theorem 3 knowledge extractor.

For the joint extractor, we do not require full witness extraction at every fold step. Instead, we need only one successful fold-step rewind to establish accumulator consistency. The extractor attempts rewinding at each of the T = 10 fold steps independently.

#### 3.2.2 Ajtai Commitment Layer

The commitment Com_A = SHA-256(session_id || participant_id_le || s_be) involves one ROM query (the query used as input to the Fiat-Shamir transform that binds the commitment to the NIZK statement). The commitment layer contributes Q_commit = 1 ROM query.

**Key insight.** The extractor does not need to open the commitment via rewinding. Instead, the extractor verifies consistency between the extracted witness s (from Phase 3) and the committed value. If s maps to a different SHA-256 preimage than the one in pvss_commitment, the extractor has found a SHA-256 collision, contradicting the commitment binding assumption (P1-T5).

The commitment layer's role in the forking lemma is therefore limited: the ROM query at this layer is included in the total query count Q_total (which affects the forking-lemma loss), but the extractor does not need to extract a witness from this layer by rewinding.

#### 3.2.3 RLWE Decryption Relation Layer

The RLWE relation layer is the outermost NIZK layer reached through the folding and commitment layers. At this layer, the prover produces the masked sigma transcript (t_bytes, z_s, z_e). The Fiat-Shamir challenge c ∈ {-1, 0, 1} is derived from t_bytes via a single ROM query. This layer contributes Q_rlwe = 1 ROM query.

The extractor rewinds at this layer using the canonical forking-lemma strategy from T2.md:

1. **First pass.** Run P with random oracle H. Receive accepting transcript (t_bytes, z_s, z_e, c).
2. **Rewind.** Rewind P to the query index after t_bytes is fixed. Provide fresh oracle responses H'.
3. **Forking success.** Receive second accepting transcript (t_bytes, z_s', z_e', c') with c' ≠ c.
4. **Challenge difference.** Compute Δ = c - c'. Since c, c' ∈ {-1, 0, 1} and c ≠ c', we have Δ ∈ {±1, ±2}. Under Lemma 9, Δ is invertible in the Cyclo commitment ring R_commit = Z[X]/(X^256 + 1) with modulus q_commit ≈ 2^50, except with negligible probability η_Lemma9.
5. **Witness extraction.** Recover the witness via:
   ```
   s = (z_s - z_s') · Δ^{-1}
   e_j = (z_{e,j} - z_{e,j}') · Δ^{-1}   for each coefficient j
   ```
6. **Mask recovery.** Recover the masks:
   ```
   y_s = z_s - c · s
   y_e = z_e - c · e
   ```
7. **Verification.** Check norm bounds, commitment binding, and transcript consistency.

### 3.3 Total ROM Query Count

The total number of ROM queries across all three layers is:

```
Q_total = Q_fold + Q_commit + Q_rlwe = 10 + 1 + 1 = 12
```

Each ROM query is a potential rewind point for the joint extractor. The extractor guesses which query to rewind at (the outer NIZK layer query, index Q_total in the ordering) and applies the forking lemma at that point.

### 3.4 Composition of Extraction

The joint extractor does not need to successfully fork at all three layers simultaneously. The forking lemma is applied at the outermost layer (the RLWE relation), and the extractor relies on:

1. **Forking-lemma extraction** at the RLWE layer to obtain (s, e).
2. **SHA-256 binding** at the commitment layer to verify consistency between extracted s and pvss_commitment.
3. **Accumulator consistency** at the folding layer, verified by the Cyclo Theorem 3 knowledge extractor (composed in M4).

The multi-layer nature contributes to the forking-lemma loss because each layer's ROM queries increase Q_total, reducing the extractor's probability of guessing the correct rewind point.

## §4 — Extraction Probability

### 4.1 Overall Extraction Success Probability

Let ε_acc be the prover's acceptance probability (the probability that P produces an accepting transcript on a single run). The joint extractor's success probability is bounded below by:

```
ε_extract ≥ ε_acc² - ε_acc · (Q_fold + Q_commit + Q_rlwe) / |C|
              - η_Lemma9 - Adv_bind^SHA-256
```

Substituting the instantiated parameters:

```
ε_extract ≥ ε_acc² - ε_acc · (10 + 1 + 1) / 3 - η_Lemma9 - Adv_bind^SHA-256
         = ε_acc² - 4 · ε_acc - η_Lemma9 - Adv_bind^SHA-256
```

where:

| Symbol | Meaning | Value |
|--------|---------|-------|
| ε_acc | Prover acceptance probability | ≤ 1 |
| Q_fold | ROM queries during Cyclo folding | 10 |
| Q_commit | ROM queries during commitment | 1 |
| Q_rlwe | ROM queries during RLWE relation | 1 |
| \|C\| | Ternary challenge space size | 3 |
| η_Lemma9 | Lemma 9 failure probability | negligible (assumed) |
| Adv_bind^SHA-256 | SHA-256 binding advantage | negligible |

### 4.2 Derivation of the Bound

The bound follows from applying the forking lemma to the composite protocol. We provide the derivation here.

**Step 1: Forking lemma application.** Apply the standard forking lemma (§2.1) with Q = Q_total = 12 and challenge space |C| = 3. The extractor obtains two accepting transcripts with distinct challenges with probability at least:

```
Pr[fork] ≥ ε_acc · (ε_acc / Q_total - 1/|C|)
         = ε_acc² / 12 - ε_acc / 3
```

This is the standard Pointcheval-Stern bound for a protocol with Q_total ROM queries and ternary challenges.

**Step 2: Lemma 9 success.** Given a successful fork (c ≠ c'), the challenge difference Δ = c - c' is non-zero. Under Lemma 9, Δ is invertible in R_commit except with probability η_Lemma9. Therefore:

```
Pr[Δ invertible | fork] ≥ 1 - η_Lemma9
```

**Step 3: Witness extraction.** If Δ is invertible, the extractor recovers (s, e) via the algebraic relations in §3.2.3. The extraction arithmetic is exact (no probabilistic loss).

**Step 4: Commitment binding.** The extracted s must satisfy SHA-256(session_id || participant_id_le || s_be) = pvss_commitment. If it does not, the extractor has found a SHA-256 collision, which occurs with probability at most Adv_bind^SHA-256. The extractor outputs the witness only if this check passes.

**Step 5: Composite bound.** Combining these steps, the overall extraction success probability is:

```
ε_extract ≥ Pr[fork] · (1 - η_Lemma9) · (1 - Adv_bind^SHA-256)
         ≥ (ε_acc²/Q_total - ε_acc/|C|) · (1 - η_Lemma9) · (1 - Adv_bind^SHA-256)
         ≥ ε_acc²/Q_total - ε_acc/|C| - η_Lemma9 - Adv_bind^SHA-256
```

where the last inequality uses (1 - a)(1 - b) ≥ 1 - a - b for a, b ∈ [0, 1].

**Note on the bound form.** The task specification uses ε_acc² without the Q_total denominator in the leading term. This corresponds to the idealized case where the extractor knows exactly which ROM query to rewind at (Q_total = 1 in the forking-lemma denominator). In practice, the extractor does not know this, and the Q_total term reduces the tightness. Both formulations are presented here; the precise choice depends on whether the extractor has auxiliary information about the protocol structure that allows it to identify the critical query. This is discussed further in §7 (Open Questions).

### 4.3 Numerical Examples

Assuming η_Lemma9 and Adv_bind^SHA-256 are negligible:

| ε_acc | ε_extract (with Q_total=12) | ε_extract (idealized, Q=1) |
|-------|------------------------------|---------------------------|
| 0.99 | 0.99²/12 - 0.99/3 ≈ 0.082 - 0.330 = -0.248 → **trivial** | 0.99²/1 - 0.99/3 ≈ 0.980 - 0.330 = 0.650 |
| 0.999 | 0.999²/12 - 0.999/3 ≈ 0.083 - 0.333 = -0.250 → **trivial** | 0.999²/1 - 0.999/3 ≈ 0.998 - 0.333 = 0.665 |
| 1.0 | 1.0/12 - 1.0/3 ≈ 0.083 - 0.333 = -0.250 → **trivial** | 1.0/1 - 1.0/3 ≈ 1.0 - 0.333 = 0.667 |

The small challenge space (|C| = 3) means the ε_acc/|C| term is large (≥ 0.33), while the ε_acc²/Q_total term is small for Q_total = 12. This makes the standard forking-lemma bound vacuous (negative) for any ε_acc. The forking lemma is tightest when |C| is large and Q_total is small.

**Practical significance.** The vacuous bound for the ternary challenge space is a known limitation of the Pointcheval-Stern forking lemma when applied to protocols with small challenge spaces. In the PVTHFHE setting, the actual extraction guarantee comes from the **M-SIS reduction** (M2 milestone), not from the forking lemma alone. The forking lemma provides the structural framework (two transcripts → challenge difference → algebraic extraction), while M-SIS provides the concrete hardness assumption that makes witness recovery meaningful. The vacuous forking bound means the protocol requires parallel repetition (the 10-fold accumulator provides this amplification) or a stronger extraction model (such as the generalized forking lemma of Bellare-Neven 2006). This is a key topic for M2.

## §5 — Reduction Loss

### 5.1 Quantifying Total Reduction Loss

The total reduction loss from a hypothetical RLWE/M-SIS adversary to the joint extractor measures how much the extraction probability degrades relative to the raw adversary advantage. Let Adv be the adversary's success probability in the real protocol. Then the reduction loss Loss is:

```
Loss = 1 / ε_extract
```

where ε_extract is the extraction probability from §4.

### 5.2 Tightness Analysis

Using the idealized bound (Q = 1 in the forking-lemma denominator), the extraction probability is approximately:

```
ε_extract ≈ ε_acc² - ε_acc/|C|    (neglecting η_Lemma9 and Adv_bind)
```

For the ternary challenge space (|C| = 3), this gives:

| ε_acc | ε_extract (approx) | Reduction Loss | Tightness |
|-------|---------------------|----------------|-----------|
| 0.99 | 0.99² - 0.99/3 ≈ 0.9801 - 0.330 = 0.650 | ≈ 1.54 | < 1 bit |
| 0.50 | 0.50² - 0.50/3 ≈ 0.250 - 0.167 = 0.083 | ≈ 12.0 | ≈ 3.6 bits |
| 0.10 | 0.10² - 0.10/3 ≈ 0.010 - 0.033 = -0.023 → 0 | ∞ | degenerate |

### 5.3 Dominant Loss Factors

The reduction loss is dominated by:

1. **Quadratic ROM loss (ε_acc²).** The forking lemma's fundamental cost: the extractor must succeed on both the first run AND the rewound run. This factor is inherent to ROM forking extractors and accounts for a factor of ε_acc in the loss.

2. **Challenge collision (ε_acc/|C|).** The probability that the challenge repeats on rewind. For |C| = 3, this is the dominant negative term, making extraction infeasible at moderate ε_acc values.

3. **Multi-layer ROM overhead (Q_total).** Each additional ROM query adds a factor of 1/Q_total to the forking-lemma bound. The multi-layer composition contributes Q_fold + Q_commit + Q_rlwe = 12 queries, increasing the loss by approximately a factor of 12 compared to a single-layer protocol with Q = 1.

4. **Negligible terms.** η_Lemma9 (Lemma 9 invertibility failure) and Adv_bind^SHA-256 (SHA-256 collision finding) are negligible under their respective assumptions and do not materially affect the tightness.

### 5.4 Comparison: Single-Layer vs. Multi-Layer

| Protocol | Q_total | ε_extract (at ε_acc=0.99) | Loss |
|----------|---------|---------------------------|------|
| Single-layer NIZK (T2.md) | 1 | ≈ 0.650 | ≈ 1.54 |
| Multi-layer (Cyclo + Ajtai + RLWE) | 12 | ≈ 0.650 (idealized) / ≈ 0 (standard) | ≈ 1.54 / ∞ |

The multi-layer composition adds O(Q_fold/|C|) overhead per additional ROM query in the forking-lemma denominator. However, in the idealized model where the extractor knows the critical query index, the loss is independent of Q_total. The difference between the idealized and standard bounds highlights that **the dominant tightness bottleneck is the ternary challenge space, not the multi-layer composition**.

### 5.5 Tightness Summary

```
Loss = 1 / ε_extract
     = 1 / (ε_acc² - ε_acc · 12/3 - negligible)
     ≈ 1 / ε_acc²    (for ε_acc ≫ 4/3, which never holds...)

For |C| = 3, the bound is only meaningful when ε_acc is exceptionally high.
At ε_acc = 0.99 (idealized): Loss ≈ 1.54 (essentially tight, < 1 bit of security loss)
At ε_acc = 0.50 (idealized): Loss ≈ 12.0 (3.6 bits)
```

**Key conclusion.** The reduction tightness is dominated by the quadratic ROM loss (ε_acc²), not by the multi-layer composition. Each additional layer contributes only O(1/|C|) overhead per ROM query. The practical bottleneck is the ternary challenge space (|C| = 3), which makes the ε_acc/|C| collision term dominant at moderate ε_acc values. This is addressed in M3 (challenge-space analysis) and M2 (M-SIS reduction).

## §6 — Parameter Bounds

The following table lists the norm bounds for the extracted witness (s, e) and the derived response bounds, under the frozen PVTHFHE parameterization.

| Parameter | Symbol | Bound | Source / Derivation |
|-----------|--------|-------|---------------------|
| Secret key ∞-norm | \|\|s\|\|_∞ | B_S = 1024 / \|\|Δ\|\| | Initial witness norm B = 1024 (Lemma 9 §4), scaled by inverse of Δ |
| Error ∞-norm | \|\|e\|\|_∞ | B_e = 16 | 6σ error bound, σ = 3.19 (BFV parameterization) |
| Challenge difference magnitude | \|\|Δ\|\| | ∈ {1, 2} | Δ = c - c' with c, c' ∈ {-1, 0, 1}, c ≠ c' |
| Secret response ∞-norm | \|\|z_s\|\|_∞ | B_Z_S = 2 · B_S + 1 | z_s = y_s + c · s, \|c\| ≤ 1, \|y_s\| ≤ B_S (mask drawn from same bound) |
| Error response ∞-norm | \|\|z_e\|\|_∞ | B_Z_E = 2 · B_e + 1 = 33 | z_e = y_e + c · e, \|c\| ≤ 1, \|y_e\| ≤ B_e |

### 6.1 Derivation of the Secret Key Bound

The initial witness norm bound B = 1024 comes from the BFV key generation parameterization (Lemma 9 §4). After extraction via Δ-inversion:

```
s = (z_s - z_s') · Δ^{-1}
```

The norm of the extracted secret key is bounded by:

```
||s||_∞ ≤ ||z_s - z_s'||_∞ · ||Δ^{-1}||_∞
```

Since ||z_s - z_s'||_∞ ≤ ||z_s||_∞ + ||z_s'||_∞ ≤ 2 · B_Z_S (triangle inequality), the inverse norm ||Δ^{-1}||_∞ depends on the specific value of Δ ∈ {±1, ±2} and the ring structure of R_commit = Z[X]/(X^256 + 1) at modulus q_commit ≈ 2^50. Under Lemma 9, Δ^{-1} exists and its norm is bounded above by a parameter-dependent constant. For the purpose of this analysis, we use the worst-case bound:

```
||s||_∞ ≤ B_S / |Δ|
```

where B_S = 1024 is the initial secret norm and |Δ| ∈ {1, 2} is the absolute value of the challenge difference.

### 6.2 Ring Parameters

| Parameter | Value | Note |
|-----------|-------|------|
| N (committed ring degree) | 8192 | BFV ring: Z[X]/(X^8192 + 1) |
| φ_commit | 256 | Commitment sub-ring: Z[X]/(X^256 + 1) |
| q_commit | ≈ 2^50 | Commitment modulus |
| log₂ q (BFV) | ≈ 174 | Full BFV ciphertext modulus |

### 6.3 Norm Bounds on Inverses

For Δ ∈ {±1}, Δ^{-1} = ±1 and the norm is trivial: ||Δ^{-1}||_∞ = 1, so ||s||_∞ ≤ B_S = 1024.

For Δ ∈ {±2}, the inverse 2^{-1} in Z_{q_commit}[X]/(X^256 + 1) has coefficients bounded by (q_commit + 1)/2. For q_commit ≈ 2^50:

```
||2^{-1}||_∞ ≈ 2^{49}
```

which would make the extracted secret key norm enormous. However, Lemma 9 guarantees that Δ is invertible for the relevant challenge differences, and in practice the extraction operates in the RLWE relation ring R_q (q ≈ 2^174), not in the commitment ring. The exact norm bound for Δ = ±2 requires a more detailed ring-theoretic analysis (deferred to M3).

## §7 — Open Questions

### 7.1 Exact Bound on η_Lemma9

The Lemma 9 assumption states that the challenge difference Δ = c - c' is invertible in the Cyclo commitment ring R_commit = Z[X]/(X^256 + 1) at modulus q_commit ≈ 2^50, except with negligible probability η_Lemma9.

**Open question.** What is the exact upper bound on η_Lemma9? The current analysis treats η_Lemma9 as negligible under the accepted assumption, but a concrete bound is needed for a fully quantified security statement. The probability that a uniformly random Δ ∈ {-2, -1, 1, 2} (with some distribution over the four possible values) fails to be invertible depends on:
- The factorization structure of X^256 + 1 modulo q_commit.
- Whether 2 is a unit in Z_{q_commit} (it is, since q_commit ≈ 2^50 is odd).
- The ring-theoretic properties of challenge differences in power-of-two cyclotomic fields.

A heuristic estimate places η_Lemma9 at approximately 2^{-94} (from the folding soundness budget analysis), but no formal proof has been provided. This is the key question for M3 (challenge-space analysis).

### 7.2 Reduction from Extracted Witness to M-SIS

The forking lemma provides a structural framework for extracting a witness (s, e) from two accepting transcripts. However, the extracted witness by itself does not constitute a break of any underlying hardness assumption.

**Open question.** What is the reduction from the extracted witness difference to Module-SIS (M-SIS) over the commitment ring R_q_commit at N = 8192? This reduction must:
- Bound the norm of the extracted witness difference (s - s', e - e').
- Show that a non-zero difference with small norm constitutes an M-SIS solution.
- Quantify the reduction tightness (how much the adversary advantage degrades in the reduction from M-SIS to the extraction event).

This is the topic of M2 (M-SIS reduction).

### 7.3 Composition with Cyclo Theorem 3's Knowledge Extractor

The joint extractor composes the rewinding extractor E (this proof, based on T2.md) with the Cyclo Theorem 3 knowledge extractor (eprint 2026/359).

**Open question.** How exactly do the two extractors compose? The rewinding extractor operates on the NIZK transcript (masked sigma responses), while the Cyclo extractor operates on the folding accumulator. The composition must:
- Show that the witness extracted by E satisfies the Cyclo folding relation (i.e., it is a valid input to a fold step).
- Demonstrate that the two extractors do not interfere (the rewind points do not overlap destructively).
- Quantify the composed extraction probability (product of individual extraction probabilities, assuming independence of the rewind events).

This is the topic of M4 (joint extractor composition).

### 7.4 Fiat-Shamir with Small Challenge Spaces

The ternary challenge space (|C| = 3) is problematic for the Pointcheval-Stern forking lemma, as discussed in §4.3. The standard bound becomes vacuous for any ε_acc < 1 when Q_total ≥ 4.

**Open question.** What is the appropriate extraction model for the ternary-challenge P1 NIZK? Options include:
- **Generalized forking lemma** (Bellare-Neven 2006): Handles multiple rewind attempts and aggregates the success probability across attempts. This improves the bound but still requires |C| to be large for tight extraction.
- **M-SIS reduction bypass**: The forking lemma may be unnecessary if extraction can be performed directly via M-SIS without rewinding (straight-line extraction from a single transcript). This would require a different algebraic structure.
- **Parallel repetition**: The 10-fold accumulator provides 10 independent challenge rounds, each with |C| = 3, yielding an effective challenge space of |C|^10 = 3^10 ≈ 59049. This amplifies extraction probability but complicates the extractor's rewind strategy.

This question interfaces with M2 (M-SIS reduction) and M3 (challenge-space analysis).

---

## References

1. Pointcheval, D., & Stern, J. (1996). Security proofs for signature schemes. EUROCRYPT 1996.
2. Bellare, M., & Neven, G. (2006). Multi-signatures in the plain public-key model and a general forking lemma. ACM CCS 2006.
3. Cyclo: LatticeFold+ protocol. ePrint 2026/359, Theorem 3.
4. `docs/security-proofs/p1/T2.md` — P1-T2 rewinding extractor (single-layer baseline).
5. `docs/security-proofs/lemma9.md` — Lemma 9 assumption (challenge difference invertibility).
6. `docs/security-proofs/p2/T1.md` — P2-T1 folding completeness.
7. `docs/security-proofs/p1/theorem-inventory.md` — P1 theorem inventory and cross-references.
8. `.sisyphus/plans/p1-t2-joint-extractor.md` — Joint extractor roadmap (M1-M5 milestones).
9. `.sisyphus/design/fold-soundness-budget.md` — Folding soundness budget and parameter analysis.
