# Issues — in-circuit-verification (G4 + G5)

## No blockers encountered

- Build passed cleanly (only pre-existing warnings for missing-docs, deprecated HermineAdapter)
- RED test passes as expected (non-zero leaf_index rejected)
- LSP diagnostics clean for both modified files

## Minor note

- `Fr::zero()` not available on ark_bn254::Fr without importing the `Field` trait. Used `Fr::from(0u64)` pattern instead.
