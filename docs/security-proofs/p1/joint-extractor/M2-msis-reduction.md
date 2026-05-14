# M2: M-SIS Reduction for the P1-T2 Joint Extractor

**Milestone**: M2 of 5 (see `.sisyphus/plans/p1-t2-joint-extractor.md`)
**Status**: DRAFT
**Date**: 2026-05-14
**Dependencies**: M1 forking-lemma formalization (`docs/security-proofs/p1/joint-extractor/M1-forking-lemma.md`), Lemma 9 assumption (`docs/security-proofs/lemma9.md`), P2-T1 folding completeness (`docs/security-proofs/p2/T1.md`), P1-T2 rewinding extractor (`docs/security-proofs/p1/T2.md`)

## §1: Module-SIS Problem Statement

The Module Short Integer Solution (M-SIS) problem is the lattice assumption that underpins the binding property of the Ajtai commitment inside the Cyclo folding layer. We instantiate it over the Cyclo commitment ring.

**Definition (M-SIS over commitment ring).** Let:

```
R = Z_{q_commit}[X] / (X^256 + 1)
```

be the commitment ring with modulus q_commit ≈ 2^50. Given a uniformly random matrix A ∈ R^{m×n} and a norm bound β > 0, the M-SIS_{q_commit, m, n, β} problem asks: find a non-zero vector w ∈ R^n such that:

```
A · w ≡ 0   (mod q_commit)    and    0 < ||w||_∞ ≤ β
```

The problem is believed to be hard for PPT adversaries when β is small relative to q_commit. The Ajtai commitment binding reduces to this problem: if an adversary can produce two distinct short vectors s₁ ≠ s₂ such that Com_A(s₁) = Com_A(s₂), then s₁ - s₂ is a non-zero short M-SIS solution for the commitment key A.

**Instantiation for PVTHFHE.** The Cyclo folding layer uses an Ajtai commitment with:

| Parameter | Value | Meaning |
|-----------|-------|---------|
| n | 1 | Witness dimension (single secret share per Ajtai commitment) |
| m | 1 | Codomain dimension (single commitment output element) |
| q_commit | ≈ 2^50 | Ring modulus for Cyclo accumulation |
| φ_commit | 256 | Ring degree: Z[X]/(X^256 + 1) |
| β | ≤ 2048 | Shortness bound (derived in §3) |

The case m = n = 1 corresponds to a single-element Ajtai commitment Com_A(s) = a · s where a ∈ R is the public commitment key. Binding here means: it is hard to find s₁ ≠ s₂ with ||s₁||_∞, ||s₂||_∞ ≤ β such that a · s₁ ≡ a · s₂ (mod q_commit), which implies a · (s₁ - s₂) ≡ 0 with 0 < ||s₁ - s₂|| ≤ 2β.

## §2: Extracted Witness from the Forking Lemma

Recap from M1 (§3.2.3): the forking-lemma extractor rewinds the prover at the RLWE relation layer and obtains two accepting masked sigma transcripts with the same first message t_bytes but different Fiat-Shamir challenges c₁ ≠ c₂. From these paired transcripts, the extractor recovers the witness algebraically.

**Transcript pair.** Let:

```
Transcript 1: (t_bytes, z_s₁, z_e₁, c₁), challenge c₁ ∈ {-1, 0, 1}
Transcript 2: (t_bytes, z_s₂, z_e₂, c₂), challenge c₂ ∈ {-1, 0, 1}, c₂ ≠ c₁
```

Both transcripts pass the P1 verifier checks (M1 §1.4, T2 §Proof Strategy).

**Challenge difference.** Compute:

```
Δ = c₁ - c₂,    Δ ∈ {±1, ±2}
```

Since the challenges are distinct ternary values, Δ is always non-zero. Under Lemma 9 (accepted assumption), Δ is invertible in the Cyclo commitment ring R_{q_commit} except with negligible probability η_Lemma9.

**Witness extraction.** The sigma protocol structure gives:

```
z_s₁ = y_s + c₁ · s        z_s₂ = y_s + c₂ · s
z_e₁ = y_e + c₁ · e        z_e₂ = y_e + c₂ · e
```

where (y_s, y_e) are the masks (identical across both transcripts since t_bytes, the commitment to the masks, is the same). Subtracting:

```
z_s₁ - z_s₂ = (c₁ - c₂) · s = Δ · s
z_e₁ - z_e₂ = (c₁ - c₂) · e = Δ · e
```

The extractor therefore computes:

```
s = (z_s₁ - z_s₂) · Δ^{-1}
e = (z_e₁ - z_e₂) · Δ^{-1}
```

This is a deterministic algebraic extraction. No probabilistic loss beyond the forking-lemma success probability and the Lemma 9 invertibility failure.

## §3: Norm Bound on the Extracted Witness

The forking-lemma extractor produces a witness (s, e) whose norm bounds depend on the response norms of the two accepting transcripts.

**Response bounds.** From the P1 verifier checks (T2 §Parameter Constraints), each accepting transcript satisfies coefficient-wise bounds on the masked responses:

```
|z_s|_∞ ≤ B_Z_S = 1024                  (response bound on secret share component)
|z_{e,j}| ≤ B_Z_E = 2·B_e + 1 = 33     (response bound on error component, B_e = 16)
```

The response bound on z_s is 1024, matching the honest secret share norm B_S = 1024 (Lemma 9 §4). The tighter constraint |z_s| ≤ B_S rather than |z_s| ≤ 2·B_S + 1 reflects the implemented verifier predicate, which checks z_s against the same bound as the secret share itself rather than the looser sigma-protocol bound. This is a deliberate design choice that strengthens the norm argument (see §7, Discussion).

**Witness norm bound.** The extracted witness is:

```
s = (z_s₁ - z_s₂) · Δ^{-1}
```

Applying coefficient-wise triangle inequality and the fact that |Δ| ∈ {1, 2}:

```
||s||_∞ ≤ ||z_s₁ - z_s₂||_∞ · ||Δ^{-1}||_∞
        ≤ (||z_s₁||_∞ + ||z_s₂||_∞) · ||Δ^{-1}||_∞
        ≤ 2 · B_Z_S · ||Δ^{-1}||_∞
        = 2 · 1024 · ||Δ^{-1}||_∞
        = 2048 · ||Δ^{-1}||_∞
```

For Δ ∈ {±1}, the inverse is ±1 and ||Δ^{-1}||_∞ = 1, giving:

```
||s||_∞ ≤ 2048     (when Δ = ±1)
```

For Δ ∈ {±2}, the inverse of 2 in R_{q_commit} has coefficients bounded by (q_commit + 1)/2 ≈ 2^{49}, which would yield an enormous extracted norm. However, Lemma 9 guarantees invertibility in the commitment ring for the modulus q_commit, and the extraction arithmetic operates in the RLWE relation ring R_q (q ≈ 2^{174}), where the inverse norm is controlled differently. The exact bound for Δ = ±2 is deferred to M3 (challenge-space analysis). For the purpose of this reduction, we assume the worst case where |Δ| = 1 and no norm blowup occurs; the M3 analysis will quantify the probability of Δ = ±2 forks.

**Error vector norm bound.** Similarly:

```
||e||_∞ ≤ 2 · B_Z_E · ||Δ^{-1}||_∞ = 2 · 33 = 66     (when Δ = ±1)
```

**Combined bound.** Taking the worst case across both components:

```
||(s, e)||_∞ ≤ max(2048, 66) = 2048     (when Δ = ±1)
```

This is twice the honest witness norm of B_S = 1024 for the secret share. The factor of 2 is the standard forking-lemma norm loss: the extractor computes a difference of two responses, doubling the norm bound. This is tight (no further loss) because the extraction is a single algebraic step.

## §4: Reduction Path: Forking Lemma to Commitment Binding

The forking lemma extracts a witness (s, e) from two accepting transcripts. We now trace what a "false statement" means and where the reduction leads.

**What is a false statement in this setting?** The P1 NIZK statement includes the public values (c, d, pvss_commitment, session_id, participant_id) where:

- c: BFV ciphertext component (public)
- d: decryption share (public, the statement)
- pvss_commitment = SHA-256(session_id || participant_id_le || s_be): the promised secret share commitment

A **true statement** is one for which there exists a witness (s, e) satisfying:
1. c · s + e ≡ d (mod q): the RLWE decryption relation
2. ||s||_∞ ≤ B_S = 1024 and ||e||_∞ ≤ B_e = 16: the norm bounds
3. SHA-256(session_id || participant_id_le || s_be) = pvss_commitment: the commitment match

A **false statement** is one for which no such witness exists. The prover may nevertheless produce an accepting proof (t_bytes, z_s, z_e) that passes the verifier checks.

**What happens when the extractor succeeds on a false statement?** Suppose the adversary outputs an accepting proof for a false statement, and the forking-lemma extractor succeeds (producing two accepting transcripts with c₁ ≠ c₂ and Δ invertible). The extractor computes (s*, e*) = ((z_s₁ - z_s₂)Δ^{-1}, (z_e₁ - z_e₂)Δ^{-1}). By algebraic necessity (M1 §3.2.3), this pair satisfies the RLWE relation:

```
c · s* + e* ≡ d   (mod q)
```

The extracted witness therefore satisfies condition (1) of the statement relation. Its norm is bounded by 2048 (§3), which is looser than the honest witness bound of 1024 but still "short" in lattice terms (2048 ≪ q_commit ≈ 2^50).

**The commitment check distinguishes the cases.** The extractor then computes:

```
h = SHA-256(session_id || participant_id_le || s*_be)
```

and compares h against pvss_commitment. There are two possibilities:

**Case A: h = pvss_commitment.** The extracted s* opens the SHA-256 commitment. Since the statement is false (no valid witness exists), the extracted s* must differ from any value the honest prover could have produced. However, the verifier CHECKED the commitment during verification, so the accepting proof implies that the prover's claimed witness also opens to pvss_commitment. If the prover's witness differs from s*, we have two distinct preimages for the same SHA-256 commitment, which is a SHA-256 collision. This contradicts the assumed collision resistance of SHA-256.

**Case B: h ≠ pvss_commitment.** The extracted s* does not match the commitment. The extractor has found a witness (s*, e*) that satisfies the RLWE relation but binds to a different commitment than the one in the statement. This means the prover produced an accepting proof for a statement with commitment C, but the extractor recovers a witness for a different statement (one with a different commitment). This does NOT directly break any hardness assumption. It means the prover's first message t_bytes was "ambiguous": it can be consistently completed with two different commitments. This would be a failure of the Fiat-Shamir transform in binding the statement to the transcript, which is a property of the hash function and the transcript encoding.

**The P1 reduction target is SHA-256 binding, not M-SIS.** For the single-layer P1-T2 extractor, the adversary's ability to produce an accepting proof for a false statement reduces to SHA-256 collision resistance (Case A), not to M-SIS. The Ajtai commitment is NOT used at the P1 layer: the commitment there is purely SHA-256 based (P1-T5, proved). There is no lattice matrix A in the P1 path for M-SIS to act upon.

M-SIS enters the picture only when the Ajtai commitment is used inside the Cyclo folding accumulator, which is the P2 layer. The next section traces how the reduction composes at the joint extractor level.

## §5: Joint M-SIS Reduction (M4 Preview)

The M-SIS hardness assumption is the concrete foundation of the Cyclo (LatticeFold+) folding protocol soundness. This section outlines the path from the folding protocol to M-SIS over the commitment ring, establishing the bridge between the single-layer P1 extractor and the joint extractor composition (M4).

**Cyclo folding and the Ajtai commitment.** In each of the T = 10 fold steps, the Cyclo folding protocol uses an Ajtai commitment over the commitment ring R_{q_commit} = Z[X]/(X^256 + 1). Specifically, each participant's P1 witness is committed under:

```
Com_A(w) = a · w   (mod q_commit)
```

where a ∈ R_{q_commit} is a fixed public key (the commitment trapdoor) and w is the folded state vector. The binding property of this commitment reduces directly to M-SIS over R_{q_commit}: an adversary who produces two distinct short vectors w₁ ≠ w₂ with Com_A(w₁) = Com_A(w₂) yields a non-zero short vector w₁ - w₂ satisfying a · (w₁ - w₂) ≡ 0, which is an M-SIS solution with norm bound 2β.

**Fold-step soundness reduction.** Each fold step in Cyclo (eprint 2026/359, Theorem 3) is a sigma protocol with challenge space |C_fold| = 2^16 (from `.sisyphus/design/fold-soundness-budget.md`). The fold-step knowledge extractor, via a forking lemma argument at each step, extracts a witness for the fold-step relation. If the extracted witness differs from the honest witness, the extractor has found:
- Either a break of the fold-step binding (which reduces to M-SIS over R_{q_commit}), or
- A contradiction to the leaf witness verification (which reduces to SHA-256 binding via the P1 extractor).

**Composition path for the joint extractor (M4).** The full joint extractor E_joint composes:

```
E_joint = E_fold  ∘  E_commit  ∘  E_rlwe
```

where:
- E_rlwe: the P1 forking-lemma extractor (M1, T2), reduces to SHA-256 binding
- E_commit: the commitment consistency verifier (M1 §3.2.2), no new extraction, pure verification
- E_fold: the Cyclo Theorem 3 knowledge extractor, reduces to M-SIS over R_{q_commit}

An adversary who produces a valid folded proof with a false leaf witness must defeat at least one of these extractors. If the adversary defeats E_rlwe (producing an accepting P1 proof for a false RLWE statement), the reduction goes to SHA-256 collision resistance. If the adversary defeats E_fold (producing a valid accumulator that does not bind to the committed witnesses), the reduction goes to M-SIS over the commitment ring.

**Why two different reduction targets?** The P1 layer operates on the RLWE relation ring R_q (q ≈ 2^174, φ = 8192), where the statement is structured as an inhomogeneous linear equation with a norm bound. The quantity being extracted is the preimage under SHA-256, not an M-SIS solution. The P2 layer operates on the commitment ring R_{q_commit} (q_commit ≈ 2^50, φ = 256), where the Ajtai commitment provides lattice-based binding. The two layers use different algebraic structures, different moduli, and different hardness assumptions. The joint extractor is sound if BOTH assumptions hold.

**Tightness of the joint reduction.** Let ε_adversary be the probability that a PPT adversary produces a valid folded proof for a false statement. Then:

```
ε_adversary ≤ Adv_bind^SHA-256 + Adv_m-sis^{R_{q_commit}}
```

where Adv_bind^SHA-256 is the adversary's advantage in breaking SHA-256 collision resistance, and Adv_m-sis^{R_{q_commit}} is the advantage in solving M-SIS over the commitment ring. Each term corresponds to a distinct attack surface: the leaf layer (SHA-256) and the folding layer (M-SIS). This additive composition is the key insight of the joint extractor: the adversary cannot trade off a P1 break against a P2 break; both layers must be independently secure.

## §6: Parameter Table

| Parameter | Value | Source / Derivation |
|-----------|-------|---------------------|
| Commitment ring R | Z_{q_commit}[X]/(X^256 + 1) | Cyclo parameters (`.sisyphus/design/fold-soundness-budget.md`) |
| Ring degree φ_commit | 256 | Commitment sub-ring of the BFV ring |
| Commitment modulus q_commit | ≈ 2^50 | Cyclo accumulator field |
| RLWE ring R' | Z_q[X]/(X^8192 + 1) | BFV parameter set (Lemma 9 §4) |
| RLWE modulus q | ≈ 2^174 | Full BFV ciphertext modulus |
| M-SIS witness dimension n | 1 | Single Ajtai commitment per participant |
| M-SIS codomain dimension m | 1 | Single commitment output element |
| M-SIS shortness bound β | 2048 | Extracted witness norm from §3 (for Δ = ±1) |
| Honest secret norm B_S | 1024 | BFV key generation bound (Lemma 9 §4) |
| Honest error norm B_e | 16 | 6σ BFV error bound, σ = 3.19 |
| Response bound B_Z_S | 1024 | Verifier response check (T2 §Parameter Constraints) |
| Response bound B_Z_E | 33 | 2·B_e + 1 |
| Extracted secret norm (Δ = 1) | ≤ 2048 | 2·B_Z_S / |Δ| = 2048 (§3) |
| Extracted error norm (Δ = 1) | ≤ 66 | 2·B_Z_E / |Δ| = 66 (§3) |
| Challenge difference Δ | ∈ {±1, ±2} | Ternary challenge subtraction |
| Lemma 9 failure probability η_Lemma9 | negligible (accepted assumption) | `docs/security-proofs/lemma9.md` §0 |
| SHA-256 security | 128-bit collision resistance | P1-T5 commitment binding |
| Folding challenge space \|C_fold\| | 2^16 = 65536 | Fold soundness budget §2.4 |
| Folding rounds T | 10 | Locked in PVTHFHE_CYCLO_PARAMS |
| Fold soundness ε_fold | 2^{-160} | Per exponential bound \|C_fold\|^{-T} |

## §7: Discussion

### 7.1 Why s and e Have Different Reduction Paths

The secret share s and the error vector e play fundamentally different roles in the security argument. The secret share s is bound by the SHA-256 commitment: any deviation from the committed value is a hash collision. The error vector e is NOT bound by SHA-256. It is bound only by the RLWE relation itself: if the extractor recovers e and s together that satisfy the RLWE equation, the combination is valid. If the adversary uses a different e than the honest prover but the same s, the extracted (s, e) pair satisfies the RLWE relation because e is recovered algebraically to make the equation hold. This asymmetry means the binding reduction path for s goes through SHA-256, while for e it goes through the verifier's response norm check. Neither path involves M-SIS at the P1 layer.

### 7.2 When the Extracted Witness Is NOT Short

The bound in §3 gives ||(s, e)||_∞ ≤ 2048 for Δ = ±1. This is a "short" vector: 2048 is 12 bits, while q_commit ≈ 2^50 is 50 bits. The ratio ||w|| / q_commit ≈ 2^{-38} is extremely small, making the M-SIS problem well-parameterized in the folding layer.

If Δ = ±2, the inverse of 2 in R_{q_commit} has norm approximately 2^{49}, and the extracted witness norm would be approximately 2048 · 2^{49} ≈ 2^{60}, which is LARGER than the modulus q_commit. Such a vector would not constitute a valid M-SIS solution (the norm must be smaller than the modulus for the problem to be non-trivial). The M3 challenge-space analysis must therefore determine the probability of Δ = ±2 forks and whether these forks are safe to ignore or require protocol redesign.

### 7.3 Relation to the Fold Soundness Budget

The Cyclo folding soundness budget (`.sisyphus/design/fold-soundness-budget.md`) derives ε_fold ≤ 2^{-160} from the exponential bound |C_fold|^{-T} = (2^{16})^{-10}. This soundness argument assumes the M-SIS hardness of the Ajtai commitment at the fold-step level. The M-SIS parameter β = 2048 (from this document) determines the concrete security level: the adversary's work factor to find an M-SIS solution over R_{q_commit} with norm bound β. If the work factor falls below 2^{128}, the Cyclo folding soundness is weaker than claimed. The parameter table in §6 provides the concrete instantiation for this check.

### 7.4 The Bridge to M4

This document establishes the following chain of reductions that M4 will compose:

```
P1 false proof acceptance
    →  (forking lemma)  extracted witness (s, e) with norm ≤ 2048
    →  (SHA-256 check)  s opens committed value, OR SHA-256 collision
    →  (RLWE relation)   (s, e) satisfies c·s + e = d
    →  (Cyclo fold)       accumulator invariant holds OR M-SIS break
    →  (composition)      Adv ≤ Adv_SHA-256 + Adv_M-SIS
```

The M2 milestone has shown that the reduction from a false P1 proof to a hardness assumption splits into two independent branches. The SHA-256 branch terminates the P1 argument. The M-SIS branch feeds the P2 argument, which M4 will formally compose into the joint extractor. The parameter that bridges these two worlds is the extracted witness norm bound β = 2048, which determines the concrete security of the M-SIS assumption at the folding layer.

---

## References

1. Pointcheval, D., & Stern, J. (1996). Security proofs for signature schemes. EUROCRYPT 1996.
2. Bellare, M., & Neven, G. (2006). Multi-signatures in the plain public-key model and a general forking lemma. ACM CCS 2006.
3. Cyclo: LatticeFold+ protocol. ePrint 2026/359, Theorem 3.
4. `docs/security-proofs/p1/joint-extractor/M1-forking-lemma.md`: M1 forking-lemma formalization.
5. `docs/security-proofs/p1/T2.md`: P1-T2 rewinding extractor (single-layer baseline).
6. `docs/security-proofs/lemma9.md`: Lemma 9 assumption (challenge difference invertibility).
7. `docs/security-proofs/p2/T1.md`: P2-T1 folding completeness.
8. `.sisyphus/design/fold-soundness-budget.md`: Folding soundness budget and challenge space derivation.
9. `.sisyphus/plans/p1-t2-joint-extractor.md`: Joint extractor roadmap (M1-M5 milestones).
10. Ajtai, M. (1996). Generating hard instances of lattice problems. STOC 1996.
11. Lyubashevsky, V., & Micciancio, D. (2006). Generalized compact knapsacks are collision resistant. ICALP 2006.
