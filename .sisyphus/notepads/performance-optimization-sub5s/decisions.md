## Decisions — A.1 + A.2 Implementation

### Decision: Use `powers.iter().rev()` in eval_with_powers
The Horner method convention puts coefficient 0 at the highest power (r^{N-1}). The precomputed powers array starts at r^0. Reversing the powers iteration matches Horner's output exactly.

### Decision: Use `Fr::from(1u64)` instead of `Fr::one()`
The `ark_ff::Field` trait import was flagged as unused by the compiler in this arkworks 0.5 installation, and `Fr::one()` was not found. The simpler `Fr::from(1u64)` pattern matches the existing code style and avoids trait import issues.

### Decision: Set batch_size = 8
Follows the plan's recommendation. For t=114 shares: ceil(114/8) = 15 Nova steps instead of 114, ~7.6× reduction.

### Decision: Remove commitment_bindings from batched steps
The batched steps use `Fr::zero()` for the third component (commitment), as specified in the plan's code. Per-share commitments cannot be meaningfully batched in the current circuit design.

### Decision: Remove unused imports (BigInteger, PrimeField)
The commitment_bindings computation was the only user of these imports. Removed to keep the code clean.

### Decision: Document A.3 profiling methodology as a standalone guide (2026-05-16)
The profiling guide (`docs/bench/nova-profiling-guide.md`) covers four profiling entry points (per-node, E2E demo, per_aggregator, flamegraph), five key profiling targets (`prove_steps`, `permute`, `generate_step_constraints`, NIFS folding, field multiplication), bottleneck analysis, and flamegraph interpretation. The per-node binary does NOT profile Nova — the guide clarifies this distinction and directs users to the E2E demo or per_aggregator for Nova IVC profiles. Marked A.3 in the plan as DOCUMENTED (A.3b), while A.3a (micro-benchmark crate) and A.3c (bottleneck fixes) remain TODO.
