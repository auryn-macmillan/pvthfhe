# Learnings — P2-M4 Lattice Commitment

## Date: 2026-05-14

### Pattern: Zero trait in ark-ff 0.5
- `ark_ff::Zero` is a separate trait that provides `zero()`.
- Must import `use ark_ff::Zero;` explicitly — `PrimeField` alone does not bring `zero()` into scope when calling on concrete types like `ark_bn254::Fr`.
- Inside `impl<F: PrimeField>` blocks, `F::zero()` works because `PrimeField: Field` and the trait bound provides access.

### Pattern: Deterministic Ajtai matrix from SHA-256
- Derive base seed from `SHA-256(epoch || rows || cols)`.
- For each cell (i,j), hash `seed || i || j` and convert to field element via `F::from_be_bytes_mod_order()`.
- This ensures verifier-independent reproducibility.

### Pattern: Test file organization
- External test files go in `tests/` directory with `[[test]]` entries in `Cargo.toml`.
- Uses project convention: `#![allow(missing_docs, clippy::unwrap_used)]` at top of test files.

### Verification: All 4 tests pass
- `ajtai_commit_is_deterministic`: Same epoch → same matrix ✅
- `ajtai_commit_differs_for_different_epoch`: Different epoch → different matrix ✅
- `ajtai_commit_is_binding_toy`: Different witnesses → different commitments ✅
- `ajtai_commitment_folding_is_homomorphic`: Com_A(w1+w2) = Com_A(w1) + Com_A(w2) ✅
