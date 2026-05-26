# Migrate Sonobe `folding-schemes` → Microsoft Nova `nova-snark`

**Status**: PLAN
**Goal**: Replace Sonobe's `folding-schemes` with Microsoft's `nova-snark` to fix the `pp_hash` serialization bug causing `IVCVerificationFail` in C4/C5 verification.

## Scope Assessment

Microsoft Nova uses **bellpepper** constraint system, not **ark-r1cs-std**. Our 5+ step circuits use `FpVar`/`ConstraintSystemRef`. This is a constraint API migration, not just a dependency swap.

**Why not the simpler pre-seed fix**: The pre-seed approach (`set_dkg_agg_data` before `SonobeCompressor::new()`) was tested with matching data shapes (n×n for C4, 1×n for C5) and still fails with `IVCVerificationFail`. The root cause is a `pp_hash` consistency bug in Sonobe's `VerifierParams` serialize/deserialize round-trip (line 416 of Sonobe's `mod.rs`), not a constraint-count mismatch. Pre-seeding fixes the R1CS shape but not the pp_hash divergence.

### Files affected (~14 files, ~2000 lines)

| File | Change |
|------|--------|
| `Cargo.toml` (compressor) | Replace `folding-schemes` with `nova-snark` |
| `sonobe/mod.rs` (~900 lines) | Rewrite `NovaCompressor` wrapper using `RecursiveSNARK` API |
| `snark_bridge.rs` | Update IVC proof serialization to `RecursiveSNARK` format |
| `dkg_aggregation_circuit.rs` | Rewrite from `FCircuit` → `StepCircuit` (bellpepper) |
| `pk_aggregation_circuit.rs` | Same |
| `pk_contribution_circuit.rs` | Same |
| `dealer_parity_circuit.rs` | Same (if used) |
| `cyclo_fold_circuit.rs` | Same (if used with Nova) |
| `lagrange_fold_circuit.rs` | Same |
| `full_pipeline.rs` | Update compressor instantiation, prove/verify |
| `per_node.rs`, `per_aggregator.rs` | Update compressor usage |
| `Cargo.toml` (cli) | Update feature flags |

### Key API Mappings

| Sonobe | Microsoft Nova |
|--------|---------------|
| `FCircuit<F>` | `StepCircuit<F>` |
| `state_len()` | `arity()` |
| `generate_step_constraints(cs, i, z_i, ei)` | `synthesize(cs, z_i, ei)` → `Vec<F>` |
| `FpVar<F>`, `ConstraintSystemRef<F>` | `SatisfyingAssignment<G>`, `LinearCombination<F>` |
| `SonobeNova::preprocess` | `PublicParams::setup` |
| `nova.prove_step` | `recursive_snark.prove_step` |
| `Nova::verify(verifier, ivc_proof)` | `recursive_snark.verify(pp, num_steps, z0_primary, z0_secondary)` |
| `ivc_proof.serialize_compressed` | `serde::Serialize` via bincode |
| `SonobeIvcProof` | `RecursiveSNARK` |
| Poseidon `PoseidonSpongeVar::new()` | `bellpepper-gadgets` equivalent or inline |

## Phases

### Phase 1 — Dependency Swap + Compressor Rewrite
- [x] Add `nova-snark` to Cargo.toml, remove `folding-schemes`
- [x] Rewrite SonobeCompressor for arecibo (prove_steps/verify_steps compile)
- [x] Gate CycloFoldStepCircuit to nova-backend
- [x] Build: `cargo build -p pvthfhe-compressor` must pass (0 errors, 24 doc warnings)

### Phase 2 — Step Circuit Migrations (5 circuits)
- [x] `DkgAggregationStepCircuit`: `FCircuit` → `StepCircuit`
- [x] `PkAggregationStepCircuit`: same
- [x] `PkContributionStepCircuit`: same
- [x] `DealerParityStepCircuit`: same
- [x] `LagrangeFoldStepCircuit`: same
- [x] Build each circuit independently (5 circuits compile with nova-backend)

### Phase 3 — Pipeline Integration
- [ ] Update `full_pipeline.rs`: C4, C5, C6 compressor instantiation
- [ ] Update `per_node.rs`, `per_aggregator.rs`
- [ ] Verify `just demo-e2e` C4/C5 verification PASSES
- [ ] Verify `just per-node` and `just per-aggregator`

### Phase 4 — Cleanup
- [ ] Remove `warn-only` P3 workaround in C4/C5
- [ ] Remove `sonobe-snark` remnants from Cargo.toml
- [ ] Update SECURITY.md P3 status
- [ ] Full test suite: `cargo test --workspace`

## Risks
- **Circuit rewrite**: ark-r1cs → bellpepper is a complete constraint API change
- **Poseidon sponge**: Different implementations between Sonobe and bellpepper
- **Thread-local data**: Bellpepper doesn't have thread-local support — need alternative data passing
- **ExternalInputs**: Sonobe's `ExternalInputs3/4` wrappers may not map to bellpepper
- **CycleFold**: Microsoft Nova handles cycle folding internally — may simplify our code

## Success Criteria
- [ ] `cargo build` zero errors
- [ ] `cargo test -p pvthfhe-compressor` passes
- [ ] `just demo-e2e` C4/C5 verification **PASSES** (no `IVCVerificationFail`)
- [ ] `just per-node` and `just per-aggregator` pass
- [ ] No warn-only workarounds remaining
