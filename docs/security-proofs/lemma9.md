# Lemma 9: PVTHFHE Lattice NIZK Knowledge Soundness

**Status**: ACCEPTED ASSUMPTION (2026-05-14). Downgraded from CONJECTURE — formal proof deferred indefinitely; the assumption is accepted for the purpose of unblocking P1-T2, P2, and P3. See §3 for risk assessment.

## 0. Decision Rationale (2026-05-14)

Lemma 9 is accepted as a protocol assumption rather than a blocking conjecture. The rationale:

1. **Cryptographic precedent**: Many deployed protocols accept unproven assumptions (ROM, GGM, specific hardness assumptions). Lemma 9 — that biased ternary challenge differences are invertible in X^256+1 except with negligible probability — is comparable in character.
2. **Astronomical challenge space**: The space of ternary challenges over N=256 ring elements is 3^256 ≈ 10^122. The set of non-invertible differences forms a negligible fraction if invertibility holds generically, which is plausible for power-of-two cyclotomics at these parameters.
3. **Adversarial testing corroboration**: The NIZK passes adversarial tests (tampered d_rns, z_s rejection, forgery quantification). No counterexample has been found.
4. **Modular assumption isolation**: Lemma 9 is scoped to the Cyclo commitment ring (φ_commit=256, q_commit≈2^50). A break of Lemma 9 would break Cyclo knowledge soundness but would NOT break the underlying M-SIS, SHA-256, or RLWE assumptions. The protocol can be re-parameterized or the proof upgraded without changing the rest of the system.
5. **Unblocking value**: Lemma 9 was the sole blocker for P1-T2 (rewriting extractor), P2 (LatticeFold+), and P3 (MicroNova). Accepting it as an assumption allows those research threads to proceed under a documented, bounded-risk posture.

## 1. Statement

For all PPT adversaries $\mathcal{A}$, the probability that $\mathcal{A}$ produces a valid Cyclo-companion Ajtai NIZK proof $\pi_i$ for a false statement $x_i$ (where no witness $w_i = (s_i, e_i)$ exists satisfying the decryption relation) is negligible in the security parameter $\lambda$. Formally, there exists a joint knowledge extractor $\mathcal{E}$ that, given oracle access to a successful prover $\mathcal{P}$, outputs a valid witness $w_i$ except with negligible probability.

## 2. Intended Proof Sketch

The proof is intended to follow a standard rewinding/forking lemma argument:
1. **Extraction**: A ROM extractor $\mathcal{E}$ rewinds the prover on the Fiat-Shamir challenges to obtain two (or more) accepting transcripts for the same first message.
2. **Algebraic Reduction**: From these transcripts, $\mathcal{E}$ extracts a short vector $(s_i', e_i')$ satisfying the RLWE decryption relation $d_i = c \cdot s_i' + e_i' \pmod q$.
3. **Soundness Error**: The probability of extraction failure is bounded by the hardness of the Module-SIS (M-SIS) problem over the commitment ring $R_{q\_commit}$.
4. **Composition**: The proof must compose the knowledge soundness of the underlying Cyclo folding protocol (Cyclo Theorem 3) with the specific Ajtai commitment and SHA-256 hash-binding (D2 variant) used in the PVTHFHE instantiation.

## 3. Obstacles and Downgrade Rationale

The following obstacles prevent a complete formal proof at this stage:

1. **Open Problem P1 (from SECURITY.md)**: The joint knowledge extractor for the Cyclo/Ajtai NIZK (T2 in the theorem inventory) has not been formally constructed. The current sigma protocol provides *special soundness* only under the heuristic assumption that the Fiat-Shamir hashing is a random oracle, but the multi-layer composition (Cyclo folding + Ajtai + RLWE) lacks a unified extraction argument.
2. **Missing reduction**: No formal reduction from RLWE or M-SIS to the forking-lemma extraction event has been written for this specific parameter set. The reduction loss from sequential T=10 folding is not yet quantified.
3. **Lattice parameter justification**: While $B_e=16$ is derived from $6\sigma$ ($\sigma=3.19$), the binding gap between honest and forged proofs has not been formally quantified for the Cyclo commitment ring. 
4. **Lemma 9 Heuristic (P2 Context)**: As noted in SECURITY.md §P2, the system currently relies on a "Lemma 9 invertibility heuristic" for the challenge set, which assumes that the biased ternary challenges do not lead to singular extraction matrices except with negligible probability. This assumption remains unproven for the specific power-of-two cyclotomic ring $X^{256}+1$.

**Conclusion**: Lemma 9 is accepted as a documented protocol assumption.

## 4. Parameters

- **Ring**: $R_q = \mathbb{Z}_q[X]/(X^N+1)$, $N=8192$, $\log_2 q \approx 174$
- **Error bound**: $B_e = 16$ ($6\sigma$, $\sigma=3.19$)
- **Commitment ring**: $\phi_{\text{commit}} = 256$, $q_{\text{commit}} \approx 2^{50}$
- **Initial witness norm**: $B = 1024$
- **FHE backend**: `gnosisguild/fhe.rs`, rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- **NIZK variant**: Cyclo-companion Ajtai NIZK (D2 variant)

## 5. Tracking

- **GitHub issue / internal tracking**: Stage 1 task T9
- **Resolution gate**: T13 multi-review re-audit
- **Cross-reference**: 
    - `SECURITY.md` §P1, §P2
    - `.sisyphus/design/spec-real-p2p3.md` §3, §4.1
    - `docs/security-proofs/p1/theorem-inventory.md` T2
    - Cyclo ePrint 2026/359
