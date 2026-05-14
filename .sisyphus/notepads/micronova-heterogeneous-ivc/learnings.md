# Learnings — MicroNova Heterogeneous IVC

## Date: 2026-05-14

### Architecture Decision: `Params = ()` constraint workaround

**Problem**: SonobeCompressor requires `FCircuit<Fr, Params = ()>`, but the task specified
`HeterogeneousStepCircuit` with `type Params = CF` (the circuit family). Since
`SonobeCompressor::new` calls `S::new(())`, the family cannot be passed through the
standard Params mechanism.

**Solution**: Used `thread_local!` + `RefCell<Option<LatticeFoldTreeCircuitFamily>>` to
store the circuit family per-thread. `HeterogeneousStepCircuit::set_family()` must be
called before compressor construction. This provides test isolation (parallel tests are
safe) while respecting the `Params = ()` constraint.

**Alternative considered**: `OnceLock` — rejected because it can only be set once,
breaking parallel tests with different family configurations.

### Type inference: HeterogeneousCircuitFamily<F: PrimeField>

The trait is generic over `F`, but methods like `num_circuits()`, `circuit_index()`,
and `circuit_hash()` don't use `F` in their signatures. This causes type inference
failures when calling these methods on a concrete `LatticeFoldTreeCircuitFamily`.

**Solution**: Use UFCS (fully qualified syntax) with a concrete field type (e.g.,
`<LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::num_circuits(&family)`).
Helper functions in tests and unit test modules wrap these calls.

### State length: 3 (not 2)

The task specifies `state_len = 2`, but all existing circuits (`ToyStepCircuit`,
`CycloFoldStepCircuit`, `FoldVerifierStepCircuit`) use `state_len = 3`, and
`SonobeCompressor` initializes state with a triple. Using `state_len = 3` throughout
maintains compatibility.

### Tests

- 5 integration tests in `tests/micronova_heterogeneous.rs` — all pass
- 3 unit tests in `latticefold_circuit_family.rs` — all pass  
- Existing tests: `fold_verifier_step` (6/6), `micronova_compression` (2/2),
  `latticefold_micronova_integration` (1/1), `sonobe_roundtrip` (4/4) — all pass
- Test runtime: ~126s for 5 micronova_heterogeneous tests (Nova preprocessing + IVC)

### Files created/modified

- `crates/pvthfhe-compressor/src/sonobe/heterogeneous.rs` — trait + HeterogeneousStepCircuit (NEW)
- `crates/pvthfhe-compressor/src/sonobe/latticefold_circuit_family.rs` — LatticeFoldTreeCircuitFamily (NEW)
- `crates/pvthfhe-compressor/src/micronova/compressor.rs` — MicroNovaCompressor wrapper (NEW)
- `crates/pvthfhe-compressor/src/sonobe/mod.rs` — module declarations + exports (MODIFIED)
- `crates/pvthfhe-compressor/src/micronova/mod.rs` — compressor module (MODIFIED)
- `crates/pvthfhe-compressor/src/lib.rs` — pub use sonobe::heterogeneous (MODIFIED)
- `crates/pvthfhe-compressor/tests/micronova_heterogeneous.rs` — 5 integration tests (NEW)
