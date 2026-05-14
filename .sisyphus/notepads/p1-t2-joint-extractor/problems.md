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
