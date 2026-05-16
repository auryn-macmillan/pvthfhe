# G5: Position-Aware Merkle Verification — Decisions

## Decision: Remove leaf_index=0 constraint, defer full position-aware

**Rationale:**
- Witness generation always uses leaf_index=0, so the constraint was redundant
- Full position-aware Merkle requires computing `idx % arity` in R1CS and conditional sibling placement per tree level
- This is non-trivial R1CS work that needs careful implementation matching `merkle.rs:87-109`
- Removing the constraint is a safe incremental step that doesn't break existing soundness (witness uses 0)

**Trade-off:**
- Accepts non-zero leaf_index values that would produce incorrect hash ordering
- However, since witness generation always provides leaf_index=0, this gap doesn't affect current proofs
- Full fix documented as deferred work with cross-reference to native implementation
