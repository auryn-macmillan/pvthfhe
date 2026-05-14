# P3-M4 Decisions

## 2026-05-14

- **Target**: Set at <100,000 gas, consistent with the plan. This is aggressive but leaves headroom under the T4 ceiling.
- **Document structure**: Organized as optimization guide with measurement protocol, not as implementation code. Per task instructions: "Do NOT write code."
- **Pairing strategy**: Documented as 0–2 pairings depending on compression path. Decision on which path is deferred to P3-M3 completion and cryptography review.
- **Optimization order**: strip lookups → inline scalarmul → pairing strategy. Lookup removal is lowest-risk since LatticeFold+ doesn't use lookups.
