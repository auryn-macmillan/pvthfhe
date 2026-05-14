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
