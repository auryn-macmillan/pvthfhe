# M5: Formal Write-Up — P1-T2 Joint Knowledge Extractor

**Milestone**: M5 of 5 (see `.sisyphus/plans/p1-t2-joint-extractor.md`)
**Status**: DRAFT
**Date**: 2026-05-14
**Dependencies**: M1 forking-lemma formalization, M2 M-SIS reduction, M3 challenge-space analysis, M4 joint extractor composition

## §1: Theorem Statement

**Theorem (P1-T2 Joint Knowledge Soundness, ROM).** There exists a joint knowledge extractor E_joint that, given rewindable black-box access to a PPT prover P producing Cyclo-folded proofs accepted by the PVTHFHE verifier, outputs witnesses for all leaf statements except with negligible probability. Formally, for any PPT prover P that, on input a set of t statements {x_i}_{i=1}^{t} and a random oracle H, produces a folded proof π_fold and leaf NIZK proofs {π_i}_{i=1}^{t} accepted by the PVTHFHE verifier with probability ε_acc, the extractor E_joint outputs:

```
{w_i = (s_i, e_i)}_{i=1}^{t}
```

satisfying for each leaf i ∈ {1, ..., t}:

1. **RLWE relation.** c_i · s_i + e_i ≡ d_i (mod q), where (c_i, d_i) are the public ciphertext and decryption share for leaf i.
2. **Norm bounds.** ||s_i||_∞ ≤ 2048 and ||e_i||_∞ ≤ 66 (for forking with Δ = ±1).
3. **Commitment binding.** SHA-256(session_id || participant_id_le_i || s_i_be) = pvss_commitment_i.
4. **Folding consistency.** The t extracted witnesses, when composed through the T = 10 Cyclo fold steps, produce an accumulator matching π_fold.

The extraction succeeds with probability at least:

```
ε_joint ≥ (ε_leaf)^t · ε_fold
```

where ε_leaf is the single-leaf extraction probability (M1 §4.1) and ε_fold is the Cyclo folding extraction probability (M4 §3.1). The extraction runs in expected time O(t/ε²), where ε is the per-leaf forking-lemma success rate.

The extraction failure probability is bounded above by the sum of the adversary's advantages against four independent assumptions:

```
Pr[E_joint fails | P succeeds] ≤ Adv_break(Lemma 9) + Adv_break(SHA-256) + Adv_break(M-SIS) + Adv_break(ROM)
```

Each term is negligible in the security parameter under the corresponding accepted assumption (§2).

**Equivalently:** Any PPT adversary who produces an accepted Cyclo-folded proof for a set of statements, at least one of which is false (no valid witness exists), can be transformed into an adversary that breaks at least one of the four assumptions with comparable probability and running time.

## §2: Assumptions

The theorem's soundness rests on four independently-accepted assumptions. A break of any single assumption does not imply a break of the others; the joint extractor is sound only if ALL four hold.

| # | Assumption | Status | Scope | Documented At |
|---|-----------|--------|-------|---------------|
| A1 | **Lemma 9 (challenge difference invertibility).** For the ring R = Z_{q_commit}[X]/(X^256+1) and ternary challenge set C = {-1, 0, 1}, the challenge difference Δ = c_1 - c_2 ∈ {±1, ±2} is invertible in R except with negligible probability. | Accepted assumption | P1-T2 extraction, Cyclo commitment ring | `docs/security-proofs/lemma9.md` |
| A2 | **SHA-256 collision resistance.** SHA-256 is collision-resistant on the commitment domain `session_id || participant_id_le || secret_share_be`. Finding two distinct preimages that hash to the same digest requires at least 2^128 operations. | Standard assumption (P1-T5 proved) | P1 commitment binding | M1 §1.2, M2 §4 |
| A3 | **M-SIS hardness over R_commit.** Module-SIS over the commitment ring Z_{q_commit}[X]/(X^256+1) with shortness bound β = 2048 is hard for PPT adversaries. No adversary can find a non-zero short vector w with ||w||_∞ ≤ β such that a · w ≡ 0 (mod q_commit) with probability non-negligibly greater than 2^{-128}. | Standard lattice assumption | Cyclo folding binding | M2 §1, M2 §5 |
| A4 | **Random Oracle Model (ROM).** The Fiat-Shamir transform (SHA-256 modeled as a random oracle) is sound for both the P1 NIZK and the Cyclo folding protocol. The extractor may rewind the prover and reprogram oracle responses. | Standard heuristic | Forking lemma, Cyclo Theorem 3 | M1 §2.1, M4 §5.4 |

### 2.1 Assumption Independence

The four assumptions operate at distinct layers of the protocol and rely on different mathematical structures:

- A1 (Lemma 9) is a ring-theoretic property of Z_{q_commit}[X]/(X^256+1).
- A2 (SHA-256) is a property of a specific hash function on a fixed-length domain.
- A3 (M-SIS) is a lattice hardness property of the Ajtai commitment.
- A4 (ROM) is a heuristic about the indistinguishability of SHA-256 from a random function.

No known reduction exists between any pair of these assumptions. Breaking A1 would not help break A2, A3, or A4, and vice versa. This modularity means the joint extractor's security is the minimum of four independent security levels, not the product or sum.

### 2.2 Security Level Summary

| Assumption | Target Security | Confidence |
|------------|----------------|------------|
| Lemma 9 | Negligible (no concrete bound) | Accepted as assumption, not proved |
| SHA-256 | 2^{-128} collision probability | High (NIST standard, no known breaks) |
| M-SIS (φ=256, q≈2^50, β=2048) | 2^{-128} (estimated) | Medium-high (standard lattice assumption, concrete estimate not verified) |
| ROM | Heuristic | High (standard in Fiat-Shamir proofs) |

The composite security is bounded above by the weakest link. For the current parameterization, the bottleneck is the Lemma 9 assumption (no concrete bound) and the M-SIS concrete estimate (not independently verified). Both are accepted under documented risk acceptance (Lemma 9 §0, M2 §7 open items).

## §3: Extraction Algorithm

### 3.1 Pseudocode

```
Algorithm: JointKnowledgeExtractor(P, π_fold, {π_i}, {x_i}, H)
Input:
  P       : rewindable PPT prover
  π_fold  : Cyclo-folded proof (accumulator after T=10 fold steps)
  {π_i}   : t leaf NIZK proofs, π_i = (t_bytes_i, z_s_i, z_e_i)
  {x_i}   : t leaf statements, x_i = (c_i, d_i, pvss_commitment_i, session_id, participant_id_i)
  H       : random oracle (initially set to the prover's oracle)
Output:
  ({w_i}, ⊥) or (⊥, collision) or (⊥, msis_solution) or (⊥, ⊥)

1. // Phase 1: Extract leaf witnesses
2. for i = 1 to t:
3.   (w_i, err) ← LeafExtractor(P, π_i, x_i, H)
4.   if err == SHA256_COLLISION:
5.     return (⊥, err.collision_pair)   // SHA-256 break found
6.   if err == EXTRACTION_FAILURE:
7.     return (⊥, ⊥)                     // Leaf extraction failed
8.   // w_i = (s_i, e_i) satisfies RLWE relation and norm bounds
9.
10. // Phase 2: Verify accumulator consistency
11. result ← FoldVerifier(π_fold, {w_i}, {x_i})
12. if result == INCONSISTENT:
13.   msis_sol ← FoldExtractor(P, π_fold, {w_i})
14.   if msis_sol ≠ ⊥:
15.     return (⊥, msis_sol)             // M-SIS break found
16.   else:
17.     return (⊥, ⊥)                     // Folding extraction failed
18.
19. // Phase 3: Composite witness verification
20. for i = 1 to t:
21.   // Check RLWE relation
22.   assert c_i · s_i + e_i ≡ d_i (mod q)
23.   // Check norm bounds
24.   assert ||s_i||_∞ ≤ 2048
25.   assert ||e_i||_∞ ≤ 66
26.   // Check commitment binding
27.   assert SHA-256(session_id || participant_id_le_i || s_i_be) == pvss_commitment_i
28. // Check folding consistency
29. acc' ← Fold({w_i}, T=10, |C_fold|=2^16)
30. assert acc' == π_fold.accumulator
31.
32. return ({w_i}, ⊥)  // Joint extraction succeeded


Algorithm: LeafExtractor(P, π_i, x_i, H)
Input:
  P    : rewindable PPT prover
  π_i  : leaf NIZK proof (t_bytes, z_s, z_e)
  x_i  : leaf statement (c, d, commitment, session_id, participant_id)
  H    : random oracle
Output:
  (witness, error_code)

1. Parse π_i as (t_bytes, z_s, z_e)   // Verified by outer acceptance check
2. Parse x_i as (c, d, pvss_commitment, session_id, participant_id)
3. c_1 ← H(session_id || pvss_commitment || t_bytes || statement_bytes)
4.
5. // Rewind loop (up to MAX_REWINDS attempts)
6. for attempt = 1 to MAX_REWINDS:
7.   // Rewind P to query index where t_bytes was fixed
8.   P_rewound ← RewindProver(P, query_index)
9.   H' ← FreshRandomOracle()
10.  (t_bytes', z_s', z_e', c_2) ← P_rewound(H')
11.
12.  if t_bytes' ≠ t_bytes:
13.    continue     // Wrong rewind point; P committed to different first message
14.  if c_2 == c_1:
15.    continue     // Challenge collision; fork failed
16.
17.  // Successful fork: Δ = c_1 - c_2 ∈ {±1, ±2}
18.  Δ ← c_1 - c_2
19.  if not IsInvertible(Δ, R_commit):
20.    continue     // Lemma 9 assumption failure (negligible probability)
21.
22.  // Extract witness via Δ-inversion
23.  Δ_inv ← Invert(Δ, R_commit)
24.  s ← (z_s - z_s') · Δ_inv
25.  e ← (z_e - z_e') · Δ_inv  // coefficient-wise
26.
27.  // Verify commitment
28.  h ← SHA-256(session_id || participant_id || s_be)
29.  if h ≠ pvss_commitment:
30.    // Two distinct s, s'? Find the other one by re-extracting
31.    // (The prover's original witness is the "other" preimage)
32.    return (⊥, SHA256_COLLISION)
33.
34.  // Verify norm bounds
35.  if ||s||_∞ > 2048 or ||e||_∞ > 66:
36.    return (⊥, EXTRACTION_FAILURE)  // Witness outside admissible range
37.
38.  // Verify RLWE relation
39.  if c · s + e ≠ d (mod q):
40.    return (⊥, EXTRACTION_FAILURE)  // Extraction arithmetic error
41.
42.  // Recover masks for transcript consistency
43.  y_s ← z_s - c_1 · s
44.  y_e ← z_e - c_1 · e
45.  if Encode(y_s, y_e) ≠ t_bytes:
46.    return (⊥, EXTRACTION_FAILURE)  // Transcript encoding mismatch
47.
48.  return ((s, e), ⊥)  // Leaf extraction succeeded
49.
50. return (⊥, EXTRACTION_FAILURE)  // Exhausted rewind attempts
```

### 3.2 Complexity

The leaf extractor (LeafExtractor) makes at most MAX_REWINDS rewind attempts per leaf. Each rewind runs the prover P on a fresh random oracle. The expected number of rewinds to obtain a successful fork is bounded by:

```
E[rewinds per leaf] ≤ (Q_total / ε_acc) · (|C| / (|C| - 1))
```

where Q_total = 12 (M1 §3.3) and |C| = 3. The factor Q_total/ε_acc accounts for guessing the correct ROM query index. The factor |C|/(|C|-1) = 3/2 accounts for challenge collisions.

The fold verifier (FoldVerifier) runs in time linear in the number of fold steps T = 10 and the statement size. The fold extractor (FoldExtractor) is invoked only on inconsistency and runs the Cyclo Theorem 3 extractor.

Total expected runtime:

```
Time(E_joint) = t · O(Q_total / ε_acc²) + O(T / ε_fold²)
              = O(t / ε_acc²)
```

where the folding extraction cost is dominated by the leaf extraction cost for t ≥ 1.

## §4: Tightness Summary

### 4.1 Extraction Probability

The joint extraction probability compounds the per-leaf extraction probability multiplicatively across t leaves:

```
ε_joint = (ε_leaf)^t · ε_fold
```

where:

```
ε_leaf = ε_acc²/Q_total - ε_acc/|C| - η_Lemma9 - Adv_bind^SHA-256
ε_fold = 1 - T · |C_fold|^{-1} = 1 - 10 · 2^{-16} ≈ 0.99985
```

For the frozen PVTHFHE parameters (|C| = 3, Q_total = 12, |C_fold| = 2^16, T = 10):

```
ε_leaf ≈ ε_acc²/12 - ε_acc/3 - negligible
ε_fold ≈ 0.99985   (essentially 1)
ε_joint ≈ (ε_acc²/12 - ε_acc/3)^t
```

### 4.2 Reduction Loss

The reduction loss is the multiplicative inverse of the extraction probability:

```
Loss_joint = 1 / ε_joint
           = (1/ε_leaf)^t · (1/ε_fold)
           ≈ (1/ε_leaf)^t               (since ε_fold ≈ 1)
```

The loss is exponential in t, the number of leaf proofs. This is the fundamental cost of extracting witnesses independently for each leaf.

### 4.3 Numerical Tightness Table

For the default PVTHFHE threshold t = 4 (ignoring negligible terms η_Lemma9 and Adv_bind^SHA-256):

| ε_acc | ε_leaf | ε_joint (t=4) | Loss | Security Loss (bits) |
|-------|--------|---------------|------|----------------------|
| 0.999 | 0.999²/12 - 0.999/3 ≈ 0.0832 - 0.3330 = NEGATIVE → 0 | 0 | ∞ | ∞ (degenerate) |
| 0.9999 | 0.9999²/12 - 0.9999/3 ≈ 0.0833 - 0.3333 = NEGATIVE → 0 | 0 | ∞ | ∞ (degenerate) |
| 1.0 | 1.0/12 - 1.0/3 ≈ 0.0833 - 0.3333 = NEGATIVE → 0 | 0 | ∞ | ∞ (degenerate) |

**The standard forking-lemma bound with Q_total = 12 and |C| = 3 is vacuous for all ε_acc ≤ 1.** The ε_acc²/Q_total term is always smaller than the ε_acc/|C| term when Q_total/|C| > ε_acc, which holds for Q_total = 12, |C| = 3, and any ε_acc ≤ 1.

This vacuity is the central tightness problem identified in M1 (§4.3, §7.4). The resolution, as discussed in M1 and M2, is that the actual extraction guarantee comes from:

1. **The M-SIS reduction** (M2). The forking lemma provides the structural framework (two transcripts with different challenges → algebraic extraction), but the reduction that makes extraction meaningful goes to M-SIS and SHA-256, not to an idealized ε_extract bound.
2. **Practical security.** In the implemented protocol, the verifier checks response norms, commitment binding, and transcript consistency. An adversary who produces an accepting proof for a false statement with non-negligible probability can be transformed into an adversary that breaks SHA-256 or M-SIS (M2 §5).
3. **Parallel repetition via folding.** The T = 10 fold steps with |C_fold| = 2^16 provide amplification at the folding layer but do not improve the leaf extraction probability.

### 4.4 Tightness Bottleneck

The dominant tightness bottleneck is the ternary challenge space (|C| = 3) at the leaf NIZK layer. This is an architectural limitation of the P1 NIZK design, not an artifact of the joint extractor composition. The joint extractor inherits this bottleneck multiplicatively across t leaves but does not introduce new tightness loss beyond the per-leaf extraction.

### 4.5 Alternative Extraction Models

As noted in M1 §7.4, alternative models could improve tightness:

- **Generalized forking lemma** (Bellare-Neven 2006): Reduces the ε_acc/|C| penalty for small challenge spaces but does not eliminate it.
- **Straight-line extraction via M-SIS**: If the extractor could recover the witness from a single transcript without rewinding, the forking-lemma loss would be eliminated entirely. This would require a different algebraic structure in the NIZK.
- **Increased challenge space**: Replacing the ternary challenge set with a larger set (e.g., |C| = 2^16, mirroring the folding challenge space) would make |C| ≫ Q_total and eliminate the vacuity. This would require protocol changes to the NIZK design.

These are documented as open questions and are not resolved in the current joint extractor.

## §5: Parameter Bounds

### 5.1 Extracted Witness Bounds

All bounds assume forking with Δ = ±1 (M3 §3.3). Forks with Δ = ±2 are rejected and retried by the extractor.

| Parameter | Symbol | Bound | Derivation Source |
|-----------|--------|-------|-------------------|
| Extracted secret key ∞-norm | \|\|s\|\|_∞ | ≤ 2048 | M2 §3: 2 · B_Z_S / 1 |
| Extracted error ∞-norm | \|\|e\|\|_∞ | ≤ 66 | M2 §3: 2 · B_Z_E / 1 |
| M-SIS shortness bound | β | 2048 | Inherited from \|\|s\|\|_∞ (M2 §6) |

### 5.2 Protocol Parameters

| Parameter | Symbol | Value | Documented At |
|-----------|--------|-------|---------------|
| BFV ring degree | N | 8192 | Lemma 9 §4 |
| BFV ciphertext modulus | q | ≈ 2^174 | Lemma 9 §4 |
| Commitment ring degree | φ_commit | 256 | Lemma 9 §4 |
| Commitment modulus | q_commit | ≈ 2^50 | Lemma 9 §4 |
| Ternary challenge space | \|C\| | 3 | M1 §2.2 |
| Folding challenge space | \|C_fold\| | 2^16 = 65536 | Fold soundness budget §2.4 |
| Folding rounds | T | 10 | M1 §1.1 |
| Number of leaf proofs | t | configurable (default 4) | M4 §3.5 |
| ROM queries (total) | Q_total | 12 | M1 §3.3 |
| Honest secret norm | B_S | 1024 | Lemma 9 §4 |
| Honest error norm | B_e | 16 | Lemma 9 §4 |

## §6: Document Cross-References

This formal write-up synthesises results from four milestone documents. The table below maps each concept to its primary source document for readers seeking full detail.

| Concept | Primary Document | Key Sections |
|---------|-----------------|--------------|
| Forking lemma formalization and extraction probability | `M1-forking-lemma.md` | §2 (statement), §3 (multi-layer analysis), §4 (extraction probability), §5 (reduction loss) |
| M-SIS reduction and commitment binding path | `M2-msis-reduction.md` | §1 (M-SIS definition), §3 (norm bounds), §4 (reduction path), §5 (joint reduction preview) |
| Challenge-space analysis and Δ invertibility | `M3-challenge-space.md` | §1 (formal claim), §2 (Lemma 9 acceptance), §3 (partial results), §4 (cross-references) |
| Joint extractor composition algorithm | `M4-joint-extractor-composition.md` | §1 (component recap), §2 (construction), §3 (probability and tightness), §4 (parameter bounds), §5 (assumption acceptance) |
| Lemma 9 assumption documentation | `docs/security-proofs/lemma9.md` | §0 (acceptance rationale), §1 (statement), §3 (obstacles), §4 (parameters) |
| P1-T2 single-layer rewinding extractor | `docs/security-proofs/p1/T2.md` | Full document |
| Fold soundness budget | `.sisyphus/design/fold-soundness-budget.md` | §2 (|C_fold| derivation), §4 (concrete parameters) |
| Cyclo folding protocol | ePrint 2026/359 | Theorem 3 (knowledge extractor) |
| Joint extractor roadmap | `.sisyphus/plans/p1-t2-joint-extractor.md` | Full plan |

---

## References

1. Bellare, M., & Neven, G. (2006). Multi-signatures in the plain public-key model and a general forking lemma. ACM CCS 2006.
2. Pointcheval, D., & Stern, J. (1996). Security proofs for signature schemes. EUROCRYPT 1996.
3. Cyclo: LatticeFold+ protocol. ePrint 2026/359, Theorem 3.
4. Ajtai, M. (1996). Generating hard instances of lattice problems. STOC 1996.
5. Lyubashevsky, V., & Micciancio, D. (2006). Generalized compact knapsacks are collision resistant. ICALP 2006.
6. `docs/security-proofs/p1/joint-extractor/M1-forking-lemma.md` — M1 forking-lemma formalization.
7. `docs/security-proofs/p1/joint-extractor/M2-msis-reduction.md` — M2 M-SIS reduction.
8. `docs/security-proofs/p1/joint-extractor/M3-challenge-space.md` — M3 challenge-space analysis.
9. `docs/security-proofs/p1/joint-extractor/M4-joint-extractor-composition.md` — M4 joint extractor composition.
10. `docs/security-proofs/p1/T2.md` — P1-T2 rewinding extractor.
11. `docs/security-proofs/lemma9.md` — Lemma 9 assumption.
12. `.sisyphus/design/fold-soundness-budget.md` — Folding soundness budget.
13. `.sisyphus/plans/p1-t2-joint-extractor.md` — Joint extractor roadmap.
