# M4: Joint Extractor Composition for the P1-T2 Protocol

**Milestone**: M4 of 5 (see `.sisyphus/plans/p1-t2-joint-extractor.md`)
**Status**: DRAFT
**Date**: 2026-05-14
**Dependencies**: M1 forking-lemma formalization, M2 M-SIS reduction, M3 challenge-space analysis, P1-T2 rewinding extractor (`docs/security-proofs/p1/T2.md`), Cyclo Theorem 3 (ePrint 2026/359)

## §1: Component Recap

The joint knowledge extractor E_joint composes two independently-defined extractors that operate at distinct layers of the PVTHFHE P1 proof system. This section recaps both components before describing their composition.

### 1.1 P1-T2 Rewinding Extractor (E_leaf)

The P1-T2 rewinding extractor (documented in `docs/security-proofs/p1/T2.md` and formalized in M1) operates on a single leaf NIZK proof. Each leaf proof is a masked sigma transcript:

```
π_i = (t_bytes_i, z_s_i, z_e_i)
```

for participant i ∈ {1, ..., t}, where t is the number of leaf proofs (participants).

The extractor E_leaf, given rewindable black-box access to the prover P, operates as follows (M1 §3.2.3, T2 §Reduction):

1. **First pass.** Run P with random oracle H. Receive accepting transcript (t_bytes, z_s, z_e, c) where c ∈ {-1, 0, 1} is the Fiat-Shamir challenge.
2. **Rewind.** Rewind P to the point after t_bytes is fixed. Provide fresh oracle responses H'.
3. **Fork.** Receive second accepting transcript (t_bytes, z_s', z_e', c') with c' ≠ c.
4. **Invert Δ.** Compute Δ = c - c' ∈ {±1, ±2}. Under Lemma 9 (accepted assumption, M3 §2), Δ is invertible in the Cyclo commitment ring R_commit = Z_{q_commit}[X]/(X^256+1) except with negligible probability.
5. **Extract witness.** Recover the witness algebraically:
   ```
   s = (z_s - z_s') · Δ^{-1}
   e = (z_e - z_e') · Δ^{-1}
   ```
6. **Verify commitment.** Check that SHA-256(session_id || participant_id_le || s_be) = pvss_commitment. If mismatch, output a SHA-256 collision (P1-T5 binding break).
7. **Verify transcript.** Check that t_bytes encodes the recovered masks (y_s, y_e) under the canonical encoding.

The extraction succeeds with probability (M1 §4.1, simplified for a single leaf):

```
ε_leaf ≥ ε_acc² - ε_acc/|C| - η_Lemma9 - Adv_bind^SHA-256
```

where |C| = 3 is the ternary challenge space size, η_Lemma9 is the Lemma 9 failure probability (negligible under the accepted assumption), and Adv_bind^SHA-256 is the SHA-256 collision advantage (negligible for SHA-256).

**Key property.** E_leaf is a rewinding extractor: it rewinds the prover in the random oracle model and requires two accepting transcripts with distinct challenges. The extracted witness satisfies:

- RLWE decryption relation: c · s + e ≡ d (mod q)
- Norm bounds: ||s||_∞ ≤ 2048, ||e||_∞ ≤ 66 (for Δ = ±1; see M2 §3)
- Commitment match: SHA-256 preimage of pvss_commitment (or SHA-256 collision found)

### 1.2 Cyclo Theorem 3 Knowledge Extractor (E_fold)

Cyclo Theorem 3 (ePrint 2026/359) provides a knowledge extractor for the sequential T-round Cyclo folding protocol. The protocol compresses t leaf statements into a single folded accumulator acc via T = 10 sequential fold steps. At each fold step k ∈ {1, ..., T}:

1. The prover commits to the fold step state.
2. The verifier supplies a folding challenge c_fold^(k) ∈ C_fold via Fiat-Shamir, where |C_fold| = 2^16.
3. The prover computes the folded witness and advances the accumulator.

The Cyclo Theorem 3 extractor E_fold, given rewindable access to the folding prover, recovers a fold-step witness at any successfully rewound fold step. The extractor operates on the folding accumulator and the committed fold-step states, not on the leaf NIZK proofs.

**Key property.** E_fold verifies that the folded accumulator acc is consistent with the committed leaf witnesses. If the folding is sound (i.e., the accumulator correctly represents the composition of the leaf statements), then any accepting folded proof implies that the leaf witnesses are valid inputs to the fold relation. The folding soundness error is:

```
ε_fold ≤ T · |C_fold|^{-1}   (per-round)
ε_fold_total ≤ |C_fold|^{-T} = (2^{16})^{-10} = 2^{-160}   (after T rounds)
```

per the fold soundness budget (`.sisyphus/design/fold-soundness-budget.md` §2.3).

**Reduction target.** The folding knowledge extractor reduces to the M-SIS hardness assumption over the commitment ring R_commit. An adversary who produces an accepting folded accumulator for a false statement must either break the Ajtai commitment binding (M-SIS over R_commit) or contradict the leaf witness extraction (SHA-256 binding). See M2 §5 for the full reduction path.

## §2: Joint Extractor Construction

The joint extractor E_joint composes E_leaf and E_fold into a single extraction algorithm that recovers witnesses for all t leaf statements from a single Cyclo-folded proof and its constituent leaf proofs.

### Algorithm

**Input:**
- A Cyclo-folded proof π_fold (the final accumulator acc after T = 10 fold steps)
- Leaf proofs {π_i}_{i=1}^{t} (one NIZK proof per participant)
- Public parameters: session_id, statement values {(c_i, d_i, pvss_commitment_i)}_{i=1}^{t}
- Oracle access: rewindable black-box access to the prover P

**Output:**
- Witnesses {w_i = (s_i, e_i)}_{i=1}^{t} for all t leaf statements, OR
- A break of SHA-256 collision resistance (collision pair), OR
- A break of M-SIS over R_commit (short non-zero solution to a·x ≡ 0), OR
- ⊥ (extraction failure)

**Procedure:**

**Step 1: Extract leaf witnesses via E_leaf.**

For each leaf proof π_i (i = 1, ..., t), invoke the P1-T2 rewinding extractor E_leaf on the single-leaf NIZK instance:

```
(s_i, e_i) ← E_leaf(P, π_i, session_id, c_i, d_i, pvss_commitment_i)
```

The extractor E_leaf rewinds P to obtain two accepting transcripts for leaf i. If E_leaf succeeds, it outputs a witness (s_i, e_i) satisfying the RLWE decryption relation and the commitment check.

If E_leaf fails for any leaf i (the rewinding produces c_1 = c_2 after the maximum number of rewind attempts, or the extracted witness fails the commitment check without producing a SHA-256 collision), the joint extractor aborts and outputs ⊥. If E_leaf produces a SHA-256 collision (two distinct preimages hashing to pvss_commitment_i), the joint extractor outputs the collision pair as a break of SHA-256 binding and terminates.

If all t leaf extractions succeed, the joint extractor holds witnesses {w_i = (s_i, e_i)}_{i=1}^{t}.

**Step 2: Verify accumulator consistency via E_fold.**

Apply the Cyclo Theorem 3 knowledge extractor E_fold to the folded proof π_fold:

```
E_fold(P, π_fold, {committed_statements_i}_{i=1}^t)
```

The extractor E_fold:

- Checks that the folded accumulator acc binds to all t leaf statements.
- Verifies that each leaf witness w_i extracted in Step 1 is a valid witness for the corresponding fold-step relation (i.e., the witness norm is bounded and the RLWE relation holds under the fold-step constraints).
- If the accumulator is inconsistent with any extracted witness, E_fold attempts to extract a fold-step witness that demonstrates the inconsistency.

If E_fold succeeds in verifying accumulator consistency, the joint extractor accepts the composed witness as valid and outputs {w_i}_{i=1}^{t}.

If E_fold discovers an inconsistency between the accumulator and the leaf witnesses, there are two cases:

- **Case A (commitment mismatch).** The leaf witness w_i was correctly extracted (Step 1) but does NOT match the committed value in the accumulator. This means the accumulator was constructed from a different witness than the one the prover used in the leaf NIZK. This is a break of the Ajtai commitment binding at the folding layer, which reduces to M-SIS over R_commit (M2 §5).
- **Case B (fold-step failure).** The folding extractor fails to verify consistency at fold step k, meaning the accumulator was constructed by a malicious folding prover who violated the fold-step relation. This is also a break of M-SIS over R_commit, per the Cyclo Theorem 3 reduction.

In either case, the joint extractor outputs the extracted M-SIS solution as a break of the M-SIS assumption.

**Step 3: Witness composition verification.**

As a final sanity check, the joint extractor verifies that the composed witness satisfies all three protocol layers simultaneously:

1. **RLWE layer.** For each leaf i: c_i · s_i + e_i ≡ d_i (mod q) and ||s_i||_∞ ≤ 2048, ||e_i||_∞ ≤ 66.
2. **Commitment layer.** For each leaf i: SHA-256(session_id || participant_id_le_i || s_i_be) = pvss_commitment_i.
3. **Folding layer.** The t extracted witnesses, when fed through the fold-step relation (T = 10 rounds, challenge space |C_fold| = 2^16), produce an accumulator that matches π_fold.

If all checks pass, {w_i} is the joint extracted witness.

**Step 4: Contradiction argument.**

If extraction fails at any step, the joint extractor has found either:
- A valid folded proof π_fold for which no consistent leaf witnesses exist (M-SIS break via E_fold), or
- A valid leaf proof π_i for a false statement (SHA-256 collision via E_leaf), or
- A forking-lemma failure (challenge collision after maximum rewind attempts).

In the first two cases, the joint extractor directly contradicts the prover's original acceptance: the prover produced an accepting proof, but the extractor proved it to be invalid by exhibiting a hardness break. In the third case, the failure probability is bounded by the extraction probability analysis (§3).

### Independence of the Two Extractors

The extractors E_leaf and E_fold operate at distinct protocol layers and require rewinding the prover at different points:

- E_leaf rewinds at the NIZK layer (outermost Fiat-Shamir transform), where the prover commits to its first message t_bytes. The rewind point is after the commitment but before the challenge response.
- E_fold rewinds at the folding layer (inner Fiat-Shamir transform, within each fold step), where the prover commits to the fold-step state. The rewind point is after the fold-step commitment but before the folding challenge response.

Because the two layers have independent Fiat-Shamir challenges (derived from different hash inputs at different protocol stages), the rewinding events are independent. The joint extractor can rewind at the NIZK layer for E_leaf without disturbing the fold-step state used by E_fold, and vice versa.

## §3: Extraction Probability and Tightness

### 3.1 Joint Extraction Success Probability

Let ε_leaf be the extraction success probability of E_leaf on a single leaf proof. Let ε_fold be the extraction success probability of E_fold on the folded proof. The joint extractor succeeds if and only if ALL t leaf extractions succeed AND the folding extraction succeeds. Assuming independence of the t + 1 extraction events (justified by the independence of the Fiat-Shamir challenges across layers, §2), the joint extraction probability is:

```
ε_joint = (ε_leaf)^t · ε_fold
```

Substituting the per-leaf extraction probability (M1 §4.1, simplified for a single leaf):

```
ε_leaf ≈ ε_acc² - ε_acc/3 - η_Lemma9 - Adv_bind^SHA-256
```

and the folding extraction probability (Cyclo Theorem 3, with T = 10, |C_fold| = 2^16):

```
ε_fold ≥ 1 - T · |C_fold|^{-1} = 1 - 10 · 2^{-16} ≈ 0.99985
```

The joint extraction probability is therefore:

```
ε_joint = (ε_leaf)^t · (1 - 10 · 2^{-16})
```

### 3.2 Reduction Loss

The reduction loss is the inverse of the extraction probability. For t leaf proofs:

```
Loss_joint = 1 / ε_joint
           = 1 / ((ε_leaf)^t · ε_fold)
           = (1/ε_leaf)^t · (1/ε_fold)
```

The dominant factor is (1/ε_leaf)^t, which grows exponentially in t. For ε_leaf close to 1 and small t, the loss is manageable. For larger t or smaller ε_leaf, the loss becomes prohibitive.

### 3.3 Tightness: Per-Leaf Rewinding vs. Batch Extraction

The joint extractor as described rewinds independently for each of the t leaf proofs. Each rewind costs O(1/ε²) operations (standard forking-lemma overhead). The total extraction cost is:

```
Cost(E_joint) = t · Cost(E_leaf) + Cost(E_fold)
              = t · O(1/ε²) + O(1/ε²)
              = O(t / ε²)
```

where the O(1/ε²) term comes from the forking lemma's rewinding overhead: the extractor must guess the correct ROM query index and rewind, which requires O(Q/ε) attempts in expectation, each taking O(1/ε) work, giving O(Q/ε²) ≈ O(1/ε²) for constant Q.

The folding extraction cost O(1/ε²) is dominated by the leaf extraction cost O(t/ε²) when t is non-trivial. For typical PVTHFHE deployments with t ≥ 4 (threshold setting), the folding cost is negligible compared to the leaf extraction cost.

### 3.4 Expected Number of Forking Attempts

The forking lemma (M1 §2.1) requires the extractor to guess the correct ROM query to rewind at. For a single leaf proof with Q_total = 12 ROM queries (M1 §3.3: 10 folding + 1 commitment + 1 RLWE), the extractor guesses the correct query with probability 1/Q_total = 1/12. If the guess is wrong, the extractor must rewind again. The expected number of rewinding attempts per leaf proof is:

```
E[rewinds per leaf] = Q_total / ε_leaf
```

For ε_leaf ≈ ε_acc² - ε_acc/3 (ignoring negligible terms), this is approximately 12 / (ε_acc² - ε_acc/3) rewinds per leaf. The total expected rewinds across all t leaves is:

```
E[total rewinds] = t · 12 / (ε_acc² - ε_acc/3)
```

### 3.5 Numerical Example

For a concrete deployment with t = 4 participants (the PVTHFHE default threshold), ε_acc = 0.99 (adversary succeeds with probability 0.99), and ignoring negligible terms:

```
ε_leaf ≈ 0.99² - 0.99/3 ≈ 0.9801 - 0.330 = 0.650
ε_fold ≈ 0.99985
ε_joint ≈ 0.650^4 · 0.99985 ≈ 0.1786 · 0.99985 ≈ 0.1786
Loss_joint ≈ 1 / 0.1786 ≈ 5.6
```

This means the extraction probability is approximately 17.9% and the reduction loss is about 2.5 bits. The loss is dominated by the ε_leaf^t = 0.650^4 term; increasing t worsens the loss exponentially.

**Practical note.** The ternary challenge space (|C| = 3) makes ε_leaf modest even at high ε_acc, as discussed in M1 §4.3. The 10-fold accumulator provides amplification across fold steps but does NOT amplify the leaf extraction probability. The leaf extraction probability bottleneck is the primary limitation of the joint extractor and is inherited from the single-layer P1-T2 design.

## §4: Parameter Bounds

The following parameter bounds are inherited from the single-layer extraction (M2 §3) and apply to each leaf witness extracted by the joint extractor. All bounds assume successful forking with Δ = ±1 (which occurs with probability 2/3 per fork; see M3 §3.3). For Δ = ±2 forks, the extractor rejects and retries.

### 4.1 Witness Norm Bounds

| Parameter | Symbol | Bound | Derivation |
|-----------|--------|-------|------------|
| Extracted secret key ∞-norm | \|\|s\|\|_∞ | ≤ 2048 | 2 · B_Z_S / 1 = 2 · 1024 (M2 §3) |
| Extracted error ∞-norm | \|\|e\|\|_∞ | ≤ 66 | 2 · B_Z_E / 1 = 2 · 33 (M2 §3) |
| Combined witness norm | \|\|(s, e)\|\|_∞ | ≤ 2048 | max(2048, 66) |
| Honest secret norm (reference) | B_S | 1024 | BFV key generation bound (Lemma 9 §4) |
| Honest error norm (reference) | B_e | 16 | 6σ BFV error bound, σ = 3.19 |
| Masked response bound (secret) | B_Z_S | 1024 | Verifier response check (T2 §Parameter Constraints) |
| Masked response bound (error) | B_Z_E | 33 | 2·B_e + 1 |

### 4.2 Ring Parameters

| Parameter | Value | Note |
|-----------|-------|------|
| N (BFV ring degree) | 8192 | Z[X]/(X^8192 + 1) |
| φ_commit (commitment ring degree) | 256 | Commitment sub-ring: Z[X]/(X^256 + 1) |
| q (BFV modulus) | ≈ 2^174 | Full BFV ciphertext modulus |
| q_commit (commitment modulus) | ≈ 2^50 | Cyclo accumulator field |
| Challenge space size \|C\| | 3 | Ternary: {-1, 0, 1} |
| Folding challenge space \|C_fold\| | 2^16 = 65536 | Per fold-step challenge set |
| Folding rounds T | 10 | Locked in PVTHFHE_CYCLO_PARAMS |
| Number of leaf proofs t | configurable | Typically t = 4 (threshold setting) |

### 4.3 M-SIS Parameters at the Folding Layer

| Parameter | Value | Note |
|-----------|-------|------|
| M-SIS witness dimension n | 1 | Single Ajtai commitment per participant |
| M-SIS codomain dimension m | 1 | Single commitment output element |
| M-SIS shortness bound β | 2048 | Inherited from leaf witness norm (M2 §6) |
| M-SIS hardness (estimated) | ≥ 2^128 | Under standard lattice estimates at φ=256, q≈2^50 |

### 4.4 Security Parameter Dependencies

The joint extractor's bounds depend on the following parameter chains:

- **Leaf witness norm → M-SIS β.** The extracted secret key norm bound of 2048 determines the M-SIS shortness parameter at the folding layer. A smaller β makes M-SIS harder (increasing security) but requires tighter response bounds in the verifier.
- **q_commit parity → Δ invertibility.** If q_commit is odd, all Δ ∈ {±1, ±2} are invertible. If q_commit is a power of 2, only Δ = ±1 is invertible, reducing the effective forking success probability by a factor of 2/3 (M3 §3.2, §3.3).
- **t (number of leaves) → extraction probability.** The joint extraction probability decays exponentially in t. The protocol should be parameterized with the smallest t that satisfies the threshold security requirement.

## §5: Acceptance of Assumptions

The joint extractor's soundness depends on four assumptions, each accepted at a specific level of confidence:

### 5.1 Lemma 9: Challenge Difference Invertibility

**Status.** Accepted as a documented protocol assumption (`docs/security-proofs/lemma9.md` §0).

**What it provides.** For the ternary challenge set C = {-1, 0, 1} and the Cyclo commitment ring R = Z_{q_commit}[X]/(X^256+1), the challenge difference Δ = c_1 - c_2 ∈ {±1, ±2} is invertible in R except with negligible probability η_Lemma9.

**Why it is accepted.** The acceptance rationale (lemma9.md §0) cites cryptographic precedent, astronomical challenge space size (3^256 ≈ 10^122), adversarial testing corroboration, and modular assumption isolation. For odd q_commit, invertibility of ±1 and ±2 is provable (gcd(2, q_commit) = 1). For power-of-two q_commit, the extractor rejects Δ = ±2 forks (probability 1/3) and relies on Δ = ±1 forks (probability 2/3).

**Impact of a break.** A break of Lemma 9 would allow an adversary to produce accepting NIZK proofs for false statements by exploiting challenge-dependent singularities in the extraction matrix. This would break knowledge soundness at the P1 layer but would NOT break M-SIS, RLWE, or SHA-256. The protocol could be re-parameterized (choosing an odd q_commit, or expanding the challenge space beyond ternary) without changing the rest of the system.

### 5.2 SHA-256 Collision Resistance

**Status.** Standard assumption. SHA-256 collision resistance on the fixed-length commitment domain is assumed to hold with security level 2^128.

**What it provides.** The commitment Com_A = SHA-256(session_id || participant_id_le || s_be) binds the prover to a single secret share s. If the extractor recovers a witness (s, e) and the commitment check fails, the extractor has found a SHA-256 collision.

**Why it is accepted.** SHA-256 is a NIST-standardized hash function with no known practical collision attacks. The P1-T5 proof establishes the binding property on the specific commitment domain used in PVTHFHE.

**Impact of a break.** A SHA-256 collision would allow an adversary to produce an accepting leaf proof for a false statement by committing to one value and then revealing a different value in the masked response. This would break P1 knowledge soundness independently of the lattice assumptions.

### 5.3 M-SIS Hardness over the Commitment Ring

**Status.** Standard lattice hardness assumption. M-SIS over R_{q_commit} = Z_{q_commit}[X]/(X^256+1) with shortness bound β = 2048 is assumed hard for PPT adversaries.

**What it provides.** The binding property of the Ajtai commitment inside the Cyclo folding layer. An adversary who breaks this binding can produce two distinct short vectors that commit to the same value, yielding an M-SIS solution.

**Why it is accepted.** M-SIS is a well-studied lattice problem with reductions from worst-case lattice problems (SIS over ideal lattices). At φ = 256 and q_commit ≈ 2^50, the problem is believed to require at least 2^128 operations for β = 2048, though a formal concrete security estimate has not been produced (see M2 §7, item: "M-SIS β = 2048 concrete security level not quantified").

**Impact of a break.** An M-SIS break would allow the adversary to forge the folding accumulator, creating a valid folded proof that does not correspond to valid leaf witnesses. This would break P2 knowledge soundness even if P1 leaf extraction succeeds.

### 5.4 Random Oracle Model (ROM)

**Status.** Standard heuristic assumption. The Fiat-Shamir transform is modeled by a random oracle (SHA-256 modeled as a truly random function).

**What it provides.** The forking lemma (M1 §2.1) and the Cyclo Theorem 3 knowledge extractor both operate in the ROM. The ROM allows the extractor to rewind the prover and reprogram the oracle responses, which is essential for forking-lemma extraction.

**Why it is accepted.** The ROM is the standard model for Fiat-Shamir based proof systems. While the ROM is known to be unrealizable in the standard model (Canetti-Goldreich-Halevi 1998), no attack on a ROM-based protocol that exploits the non-randomness of SHA-256 has been found in practice.

**Impact of a break.** If SHA-256 is distinguishable from a random oracle in a way that the adversary can exploit, the forking lemma no longer applies and extraction cannot be guaranteed. This would affect both the P1 leaf extractor and the Cyclo folding extractor.

### 5.5 Assumption Dependencies

The four assumptions are modular and independent: a break of any one assumption does not imply a break of the others. The joint extractor is sound if ALL four assumptions hold. This is the additive composition property established in M2 §5:

```
Adv_adversary ≤ Adv_break(Lemma 9) + Adv_break(SHA-256) + Adv_break(M-SIS) + Adv_break(ROM)
```

Each term is independent and bounded by the corresponding assumption's security parameter. The adversary cannot combine partial breaks across different assumptions to reduce the overall security below the strongest individual assumption.

---

## References

1. `docs/security-proofs/p1/joint-extractor/M1-forking-lemma.md` — M1 forking-lemma formalization, extraction probability, multi-layer ROM analysis.
2. `docs/security-proofs/p1/joint-extractor/M2-msis-reduction.md` — M2 M-SIS reduction, parameter bounds, reduction path from P1 to M-SIS.
3. `docs/security-proofs/p1/joint-extractor/M3-challenge-space.md` — M3 challenge-space analysis, Δ invertibility, q_commit parity analysis.
4. `docs/security-proofs/p1/T2.md` — P1-T2 rewinding extractor (single-layer baseline).
5. `docs/security-proofs/lemma9.md` — Lemma 9 assumption (challenge difference invertibility), acceptance rationale.
6. `docs/security-proofs/p2/T1.md` — P2-T1 folding completeness.
7. Cyclo: LatticeFold+ protocol. ePrint 2026/359, Theorem 3.
8. `.sisyphus/design/fold-soundness-budget.md` — Folding soundness budget, challenge space derivation.
9. `.sisyphus/plans/p1-t2-joint-extractor.md` — Joint extractor roadmap (M1-M5 milestones).
10. Pointcheval, D., & Stern, J. (1996). Security proofs for signature schemes. EUROCRYPT 1996.
11. Bellare, M., & Neven, G. (2006). Multi-signatures in the plain public-key model and a general forking lemma. ACM CCS 2006.
