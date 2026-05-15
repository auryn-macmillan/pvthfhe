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
