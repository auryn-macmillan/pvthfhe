# Decisions — P1-T2 Joint Extractor

## M1: Forking-Lemma Formalization

### 2026-05-14

- **Decision:** Present both the idealized bound (ε_acc², as in task spec) and the standard bound (ε_acc²/Q_total, as in Pointcheval-Stern) in §4.
  - **Rationale:** The task specification explicitly calls for ε_acc² without Q_total in the denominator. Rather than silently correct it, the document presents both formulations and explains the relationship. This prevents a future reader from thinking the standard forking lemma was misapplied.
  - **Impact:** The document is ~10% longer but is self-contained and transparent about the ambiguity. M2 should resolve which formulation is correct for the joint extractor.

- **Decision:** The Ajtai commitment layer does not require separate rewinding extraction. The extractor verifies consistency post-extraction via SHA-256 binding.
  - **Rationale:** Rewinding at the commitment layer would multiply the forking-lemma loss (product of two independent forking events), while the SHA-256 binding check provides the same guarantee without additional probabilistic loss.
  - **Impact:** The joint extractor is structurally simpler: Phase 2 is a verification check, not an extraction step.

- **Decision:** Q_commit = 1 is counted in Q_total even though the commitment layer does not need extraction.
  - **Rationale:** The ROM query at the commitment layer is still part of the prover's transcript and affects the extractor's ability to guess the correct rewind point. Omitting it would understate the forking-lemma loss.
  - **Impact:** Higher total Q (12 vs. 11), slightly worse (more vacuous) standard bound.

- **Decision:** Document structure follows the 7-section template from the task specification exactly, including the exact formula from §4.
  - **Rationale:** The task is explicit about what each section must contain. Deviating would risk non-compliance.
  - **Impact:** The document is longer than a minimal proof sketch but covers all required ground.

## M2: M-SIS Reduction

### 2026-05-14

- **Decision:** The P1 reduction target is explicitly stated as SHA-256 binding, not M-SIS.
  - **Rationale:** The P1 commitment is purely SHA-256 (P1-T5). There is no Ajtai/lattice commitment at this layer. Claiming an M-SIS reduction for P1 would be incorrect. The document instead traces the full reduction path honestly, showing M-SIS enters through P2 (Cyclo folding). This is faithful to the task specification's §4 correction.
  - **Impact:** The document serves as a bridge between the forking lemma (M1) and the joint extractor (M4), rather than claiming a direct P1-to-M-SIS reduction.

- **Decision:** The M-SIS shortness bound β = 2048 is derived from 2·B_Z_S / 1 (the Δ = ±1 case).
  - **Rationale:** For Δ = ±1, the extraction is clean: the inverse is the identity and there is no norm blowup. For Δ = ±2, the inverse of 2 in R_{q_commit} has enormous norm (~2^{49}), making the extracted witness norm exceed q_commit. The Δ = ±2 case is deferred to M3 and is excluded from the M-SIS parameterization in this document.
  - **Impact:** The β = 2048 parameter is only valid for Δ = ±1 forks. M3 must determine whether Δ = ±2 forks can be safely ignored (probability analysis) or require protocol changes.

- **Decision:** The additive composition formula ε_adversary ≤ Adv_SHA-256 + Adv_M-SIS is stated in §5 as a preview, not a formal proof.
  - **Rationale:** The full formal proof requires M4 composition. Stating it here establishes the architectural pattern for M4 to formalize. The additive nature (not multiplicative) is important: it means the security doesn't collapse to the weaker of the two assumptions.
  - **Impact:** M4 will need to prove this bound formally, but the structure is clearly laid out.

- **Decision:** §7 (Discussion) is added beyond the required §1-§6 sections to capture architectural insights.
  - **Rationale:** The asymmetry between s and e reduction paths, the Δ = ±2 norm blowup issue, and the bridge to M4 are important concepts that don't fit neatly into the required sections. The discussion section prevents these insights from being lost.
  - **Impact:** The document is slightly longer but serves as a better reference for M4.

## M3: Challenge-Space Analysis

### 2026-05-14

- **Decision:** M3 covers both q_commit parity cases (odd and power-of-two).
  - **Rationale:** The task specification didn't clarify the exact parity of q_commit (just says q_commit ≈ 2^50). The document covers both cases so the analysis is complete regardless of which parameterization is chosen.
  - **Impact:** The document includes a discussion of what happens if q_commit is even (2 is not a unit) and recommends the extractor reject Δ = ±2 forks and retry. This is a defensive design choice.

- **Decision:** M3 does NOT claim to prove Lemma 9.
  - **Rationale:** The task explicitly says "not a full proof — Lemma 9 is accepted as assumption." M3 catalogues partial results and cross-references the acceptance rationale without overclaiming. This is consistent with the "ACCEPTED ASSUMPTION" status in lemma9.md.
  - **Impact:** The document correctly serves as supporting analysis rather than a proof, which is what the task requests.

- **Decision:** The "astronomical challenge space" argument (3^256) is contextualized but not exaggerated.
  - **Rationale:** The P1 NIZK challenge is a ternary scalar (|C|=3), not a vector. The 3^256 figure correctly describes the Cyclo folding challenge space but is not directly relevant to the leaf extraction step. The document clarifies this distinction.
  - **Impact:** Prevents a future reader from incorrectly citing M3 as claiming the P1 challenge space is 3^256.

## M4: Joint Extractor Composition

### 2026-05-14

- **Decision:** The joint extractor algorithm is presented in prose (4 steps), not pseudocode.
  - **Rationale:** The task specification describes the joint extractor as a 4-step construction in prose. Full pseudocode is reserved for M5 (the formal write-up). This keeps M4 focused on the composition logic rather than implementation details.
  - **Impact:** M4 is a bridge document between the single-layer analysis (M1-M3) and the formal summary (M5). The prose format is appropriate for this bridging role.

- **Decision:** The extraction probability formula uses the product form ε_joint = (ε_leaf)^t · ε_fold.
  - **Rationale:** This matches the task specification exactly. The independence assumption is justified by the independence of Fiat-Shamir challenges across layers.
  - **Impact:** The exponential decay in t is correctly identified as the dominant tightness factor, not hidden behind an alternative formula.

- **Decision:** The parameter bounds in §4 explicitly reference M2 as the source.
  - **Rationale:** M2 is the authoritative document for norm bounds (||s|| ≤ 2048, ||e|| ≤ 66). M4 recapitulates these bounds but does not re-derive them. This avoids duplication and maintains a single source of truth.
  - **Impact:** If M2's bounds are updated, M4's bounds will need updating too. The cross-reference makes this dependency explicit.

## M5: Formal Write-Up

### 2026-05-14

- **Decision:** M5 includes full pseudocode for the joint extractor.
  - **Rationale:** M5 is the "formal write-up" and self-contained summary. A reader should be able to understand the extraction algorithm from M5 alone, with M1-M4 providing the detailed proofs. The pseudocode makes the algorithm concrete and implementable.
  - **Impact:** M5 is the longest of the five documents (334 lines) but is also the most self-contained.

- **Decision:** The vacuous forking-lemma bound is included in the numerical tightness table with explicit "NEGATIVE" markers.
  - **Rationale:** Honesty about the protocol's limitations is essential for a research prototype. A table that silently omitted the vacuous cases would be misleading. Showing "NEGATIVE → 0" makes the limitation visible and motivates the alternative extraction models in §4.5.
  - **Impact:** M5 is transparent about the tightness bottleneck. This is the right posture for a document that will be read by auditors and future protocol designers.

- **Decision:** M5's assumption table (§2) uses the same four assumptions as M4 §5.
  - **Rationale:** Consistency between M4 and M5 is important. Both documents present the same four assumptions (Lemma 9, SHA-256, M-SIS, ROM) in the same format. The assumption table in M5 adds security levels and confidence ratings.
  - **Impact:** The reader can move from the high-level summary (M5) to the detailed assumption discussion (M4 §5) seamlessly.
