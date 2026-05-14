# Problems — P1-T2 Joint Extractor

## M1: Forking-Lemma Formalization

### 2026-05-14

1. **Vacuous forking-lemma bound.** The Pointcheval-Stern forking lemma gives a trivially negative bound for |C| = 3 and Q_total = 12. This is a structural problem: the forking lemma requires a large challenge space to give non-trivial guarantees, but the P1 NIZK uses a ternary challenge.
   - **Mitigation:** The forking lemma provides the structural framework (two transcripts → witness extraction). The actual soundness guarantee comes from M-SIS (M2). The document explicitly notes this and does not claim extraction probability from the forking lemma alone.
   - **Resolution path:** M2 must provide a concrete extraction probability under the M-SIS assumption that does not depend on the vacuous forking-lemma bound.

2. **Formula ambiguity in task specification.** The task formula ε_extract ≥ ε_acc² - ε_acc·Q_total/|C| differs from the standard forking lemma ε_extract ≥ ε_acc²/Q_total - ε_acc/|C|. The difference is significant (factor of Q_total in the leading term).
   - **Mitigation:** The document presents both forms and explains the derivation. The task formula is presented as the primary bound, with a note explaining the relationship to the standard lemma.
   - **Risk:** If the task formula was intended to be the standard forking lemma with a typo, the presented bound is incorrect. The document hedges by including both.

3. **Norm blowup for Δ = ±2.** The inverse of 2 in the Cyclo commitment ring has norm ~2^49, which makes the extracted witness norm far too large for M-SIS. If the challenge difference is 2, extraction may succeed algebraically but produce a witness that cannot be reduced to M-SIS.
    - **Mitigation:** The document defers norm-bound analysis to M3. For Δ = ±1, the inverse norm is 1 and the bound is tight. For Δ = ±2, the extraction may be valid but the witness may not be useful for reduction.
    - **Resolution path:** M3 must determine whether Δ = ±2 extraction is sound at the frozen parameters. If not, the extractor may need to reject forks where Δ = ±2 and retry rewinding.

## M3: Challenge-Space Analysis

### 2026-05-14

1. **q_commit parity unresolved.** The analysis shows that Δ = ±2 invertibility depends on whether q_commit is odd or a power of two. The current parameters say q_commit ≈ 2^50 without specifying parity.
   - **Mitigation:** Document covers both cases (§3.2). If q_commit is a power of 2, Δ = ±2 is not invertible and the extractor must reject those forks.
   - **Resolution path:** The Cyclo/folding parameter selection should choose an odd q_commit to avoid this issue entirely.

2. **The 3^256 figure is partially misleading.** The P1 NIZK uses a single ternary scalar challenge (|C| = 3), not a vector challenge. The 3^256 figure applies to the Cyclo folding challenge space but the document's §3.1 section title ("Challenge Space Cardinality") could mislead readers into thinking the P1 challenge space is 3^256.
   - **Mitigation:** §3.1 explicitly clarifies that "The key simplification is that the Fiat-Shamir challenge in the P1 NIZK is a single scalar c ∈ {-1, 0, 1}, not a vector of ring elements."
   - **Risk:** Readers skimming §3.1 may still miss this clarification.

## M4: Joint Extractor Composition

### 2026-05-14

1. **Extraction probability decays exponentially in t.** With ε_leaf ≈ 0.65 (M1 numerical example), the joint extraction probability for t = 4 leaves is ε_joint ≈ 0.18. For t = 10, it drops to ~0.01. For t = 100, it's effectively zero.
   - **Mitigation:** The protocol should be parameterized with the smallest t that satisfies the threshold security requirement (typically t = 4).
   - **Resolution path:** If larger t is needed, batch extraction techniques (extracting all leaves from a single rewind pair) should be explored as an alternative to per-leaf rewinding.

2. **Independence of leaf extractions not proved.** The product formula ε_joint = (ε_leaf)^t · ε_fold assumes independence of the t leaf extraction events. The document justifies this by noting distinct Fiat-Shamir challenges at different layers, but a formal proof of independence is not provided.
   - **Mitigation:** The assumption is stated explicitly in §3.1 with its justification noted.
   - **Risk:** If leaf extractions are not in fact independent (e.g., because the same random oracle underlies all of them), the actual ε_joint may be lower than the product formula suggests.

## M5: Formal Write-Up

### 2026-05-14

1. **Vacuous tightness is the headline issue.** The numerical tightness table (§4.3) shows the forking-lemma bound is vacuous for all ε_acc ≤ 1. This is a structural limitation of the ternary challenge space, not a mistake in the analysis.
   - **Mitigation:** M5 §4.4-§4.5 clearly identify the bottleneck and propose alternative extraction models (generalized forking lemma, straight-line extraction, increased challenge space).
   - **Resolution path:** If the protocol advances beyond research prototype status, the NIZK should be redesigned with a larger challenge space (e.g., |C| = 2^16) to make the forking-lemma bound non-vacuous.

2. **No concrete security level for composite assumptions.** The four assumptions (Lemma 9, SHA-256, M-SIS, ROM) have varying levels of concreteness: SHA-256 is well-characterized at 2^{-128}, M-SIS at β=2048 is estimated at 2^{-128}, Lemma 9 has no concrete bound, and ROM is heuristic. The composite security cannot be stated as a single concrete number.
   - **Mitigation:** The assumptions table (§2) includes confidence ratings alongside target security levels, making the uncertainty explicit.
   - **Resolution path:** A formal concrete security analysis of M-SIS at φ=256, q≈2^50, β=2048 would improve confidence. Lemma 9 would need to be either proved or replaced by a concrete parameter bound.
