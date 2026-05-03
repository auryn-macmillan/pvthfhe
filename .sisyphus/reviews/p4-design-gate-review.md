# External Reviewer Memo — P4 Design Gate (DG-P4)

**Reviewer**: Agent Self-Review (advisory; external reviewer engagement deferred per plan §3.5)
**Date**: 2026-05-03
**Problem/Gate**: P4 Design Gate — Wave A.D outputs A.D.1–A.D.4
**Sections Reviewed**:
- `.sisyphus/design/p4/interface-spec.md` — frozen interface types
- `.sisyphus/design/p4/stack-decision.md` — Hermine-adapted PVSS stack selection
- `docs/security-proofs/obligations.md` — T1–T5 theorem skeletons
- `.sisyphus/design/p4/bench-plan.md` — benchmark targets n=128/512/1024
- `.sisyphus/design/p4/migration-plan.md` — adapter strategy and CI-green guarantee
- `crates/pvthfhe-keygen/` — migration-stub crate (`cargo check` verified green)

## Findings

1. **Interface spec (A.D.1)**: The five core types (`KeygenSession`, `Share`, `PublicVerificationArtifact`, `BlameProof`, `BFVPublicKey`) are frozen in `pvthfhe-keygen-spec` with serde wire encodings and trait surfaces matching the Hermine-adapted design. No blocking issues.

2. **Stack decision (A.D.2)**: The scorecard-based selection of the Hermine-adapted lattice PVSS is well-argued. Fallback candidates are documented. The kill criteria are clear. The decision memo correctly identifies BFV-key adaptation as the primary open risk, mitigated by explicit migration steps.

3. **Theorem skeletons (A.D.3)**: T1–T5 are at `skeleton` status in `docs/security-proofs/obligations.md`. Statement stubs and TODO markers are in place. Soundness of the lattice NIZK (P1) is still an open problem — explicitly acknowledged. Acceptable for this design stage.

4. **Benchmark plan (A.D.4a)**: Three sizes (n=128, 512, 1024), five metrics (dealer keygen, participant verify, proof gen, proof size, BFV reconstruct) are documented with target thresholds. Criterion.rs harness is specified. Kill criteria are defined. No blocking issues.

5. **Migration plan (A.D.4b)**: Four-step migration (M0–M4) with `migration-stub` feature flag ensures CI stays green throughout. The adapter trait surface (`KeygenAdapter`) matches the frozen interface spec. The surrogate `protocol.rs` is untouched. Risk register is complete.

6. **Migration stub crate (A.D.4c)**: `crates/pvthfhe-keygen` compiles cleanly with `cargo check -p pvthfhe-keygen --features migration-stub`. The stub round-trip test passes. No issues.

## Verdict

VERDICT: APPROVE

All four A.D. outputs are in place and meet the acceptance criteria stated in the plan. The design wave is complete. Implementation work (T1–T5 real proofs, HermineAdapter, benchmarks) is correctly deferred to T4.

---
**Signature**: agent/sisyphus-junior (advisory self-review; no blocking external sign-off required at stub phase)
