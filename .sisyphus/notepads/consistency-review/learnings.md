# Consistency Review — Learnings

## 2026-05-12: Initial deep consistency review

### Reviewed
- 4 architecture design docs (.sisyphus/design/*.md)
- 2 public docs (README.md, SECURITY.md)
- 4 stale docs (WARNING.md, STATUS.md, ARCHITECTURE.md, SECURITY-ADVISORY-001.md)
- 1 paper doc (paper/claims-table.md)
- 1 security proof (docs/security-proofs/interfold-equivalent-pvss.md)
- 1 security proof skeleton (docs/security-proofs/p2/T2.md)
- All crate source files for backend lock compliance
- All NIZK soundness claims across codebase
- Full demo-e2e pipeline trace

### Summary figures
- **22 architecture doc discrepancies**
- **12 README/SECURITY doc discrepancies**
- **0 backend lock violations** (clean)
- **8 NIZK soundness overstatements** (4 critical, 4 moderate)
- **10 demo-e2e gaps**

### Key patterns observed
1. **Documentation rots faster than code**: Five docs (WARNING, STATUS, ARCHITECTURE, SECURITY-MAR-ADVISORY, SECURITY.md §implementation status) were written for pre-remediation Stage 0 and never updated after real constraints replaced surrogates.
2. **Architecture specs describe aspirational state**: spec-real-p2p3.md documents trait APIs (CycloAdapter, MicroNovaAdapter) and crates (pvthfhe-p3-encoder) that diverged during implementation. The plan docs should either be updated to match code or marked as aspirational.
3. **bfv_sigma.rs is the invisible module**: A 533-line lattice-native proof module is undocumented across all 4 design docs. New modules need doc updates as part of "done".
4. **Soundness claims drift from conditional to absolute**: At the crate level (BACKEND_ID, lib.rs docs), conditional soundness is properly disclosed. But as claims propagate to README, paper, and architecture docs, the conditionals are dropped and "PROVED" or numerical bounds appear without caveats.
5. **Demo speed masked verification gaps**: The `demo-seeded-rng` skip of `verify_shares` hid a broken verification path for weeks. Feature gates that disable verification should carry explicit RED comments.
6. **Backend lock is well-enforced**: The only area that was 100% clean across the entire codebase.

### Remediation plan
See `.sisyphus/plans/consistency-remediation.md` — 4 phases, 29 tasks across 6 batches.
