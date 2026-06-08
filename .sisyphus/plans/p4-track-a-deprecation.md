# P4 — Track A Deprecation Plan

**Epic**: Remove Nova SNARK (BN254+Grumpkin curve-cycle) compression backend, leaving only Track B (LatticeFold+ via Cyclo).

## Current State

**Track A** (to remove):
- `crates/pvthfhe-compressor/src/nova/` — Nova step circuits, `NovaCompressor<S>`, `NovaRecursiveSNARK`
- Dependencies: `nova-snark`, `ark-bn254`, `ark-grumpkin`, `bellpepper-core`, `ark-r1cs-std`
- `legacy-nova` feature (Sonobe folding-schemes, already deprecated)
- Step circuits: `CycloFoldStepCircuit`, `FheComputeStepCircuit`, `BootstrapStepCircuit`, `SchemeSwitchStepCircuit`, `C7MerkleStepCircuit`, etc.
- `ProofCompressor` trait impl on `NovaCompressor<S>`
- Approx. 4,000+ lines of Nova-specific code in `src/nova/mod.rs` alone

**Track B** (keep / integrate):
- `crates/pvthfhe-cyclo/` — LatticeFold+ primitives (fold, verify_fold, check_satisfiability, ajtai commitments, FS challenges)
- `crates/pvthfhe-aggregator/src/folding/mod.rs` — `HashChainCycloAdapter`, `FoldAccumulator`, `FoldStatement`, `FoldWitness`
- `crates/pvthfhe-compressor/src/latticefold/` — directory exists, currently sparse

**Compiler dependencies to remove:**
```toml
nova-snark = { version = "0.71", features = ["test-utils"] }
ark-bn254 = "0.5"
ark-grumpkin = "0.5"
ark-ec = "0.5"
ark-r1cs-std = "0.5"
bellpepper-core = "0.4"
ark-relations = "0.5"
# Also: any folding-schemes references behind legacy-nova
```

## Design

### Strategy: Rewrite `latticefold/compressor.rs` — don't create a new file

The existing `LatticeFoldCompressor` (380 lines) imports `crate::nova::{decode_quad, decode_triple, ExternalInputs3}` — these are Nova-specific encoding helpers. Since we're deleting `nova/`, we must rewrite it to use Cyclo directly.

**What stays:** `LatticeFoldCompressor` struct name stays (CLI already uses it behind `enable-latticefold` feature). VerifierKey, SRS identity, proof format unchanged.

**What changes:** Replace Nova encoding utilities with Cyclo-native equivalents from `pvthfhe_cyclo`:
- `decode_quad(..)` / `decode_triple(..)` → replace with direct Cyclo fold operations
- `ExternalInputs3` → remove (Nova-specific)
- `ark_bn254::Fr` → keep for now (it's used for field arithmetic, not Nova-specific)

### lib.rs: Remove `ivc_binding` from `CompressedProof`

```rust
// BEFORE:
pub ivc_binding: Option<crate::nova::snark_bridge::IvcBindingData>,

// AFTER: remove the field. It's optional and used by Nova-specific IVC mode only.
// Consumers that read ivc_binding (compressor_glue.rs, full_pipeline.rs) will
// simply stop reading it — the IVC proof hash already covers the binding data.
```

### No new trait — `ProofCompressor` stays

The existing `ProofCompressor` trait is used by the CLI as a trait object boundary. We keep the trait but simplify its Nova-specific methods to no-ops. The existing `impl ProofCompressor for LatticeFoldCompressor` at lines 198-221 of compressor.rs is ported to use Cyclo operations.

## Implementation Phases

### Phase 0: Dependency Scan (completed inline)

Reference count (grep verified):
- `NovaCompressor`: 28 files (compressor lib, CLI, offchain-verifier, tests)
- `ProofCompressor`: 10 files
- `IvcBindingData`: 3 files (compressor_glue.rs, full_pipeline.rs, lib.rs)
- `crate::nova` imports in latticefold/compressor.rs: 1 file, 3 symbols

### Phase 1: Fix lib.rs — Remove Nova dependency from public API

**Files:** `crates/pvthfhe-compressor/src/lib.rs`
**Task:** Remove `pub ivc_binding: Option<crate::nova::snark_bridge::IvcBindingData>` field from `CompressedProof`. Remove `pub mod nova;` and `pub mod micronova;` module declarations.

### Phase 2: Rewrite latticefold/compressor.rs — Remove Nova imports

**Files:** `crates/pvthfhe-compressor/src/latticefold/compressor.rs`
**Task:** Replace `crate::nova::{decode_quad, decode_triple, ExternalInputs3}` imports with Cyclo-native equivalents. The `prove()` method rewires to call Cyclo's fold operations. `verify()` rewires to Cyclo's verify_fold.

### Phase 3: Delete nova/ and micronova/ modules

**Files to delete:**
- `crates/pvthfhe-compressor/src/nova/` — entire directory tree (~20 files, ~4500 lines)
- `crates/pvthfhe-compressor/src/micronova/` — entire directory (~3 files)
- `crates/pvthfhe-compressor/examples/nova_isolated.rs`

**Files to update:**
- `crates/pvthfhe-compressor/Cargo.toml` — remove deps

### Phase 4a: Fix compressor crate tests

**Files:** `crates/pvthfhe-compressor/tests/` — approx. 20 test files
**Task:** Remove Nova-specific tests, update remaining tests to use Cyclo/LatticeFold.

### Phase 4b: Fix CLI crate

**Files:** `crates/pvthfhe-cli/src/compressor_glue.rs` (465 lines), `full_pipeline.rs`
**Task:** Remove `nova-compressor` feature path, simplify to `latticefold` + `surrogate`. Remove `ivc_binding` reads.

### Phase 4c: Fix offchain-verifier

**Files:** `crates/pvthfhe-offchain-verifier/`
**Task:** Remove Nova-specific verification paths.

### Phase 5: Verification

```bash
cargo check -p pvthfhe-compressor
cargo test -p pvthfhe-cyclo --lib
cargo test -p pvthfhe-aggregator --lib
cargo check --workspace
```

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Downstream crates depend on Nova types | High | Phase 4 addresses this — we find and fix all references |
| Cyclo fold doesn't support all Nova step circuits | Medium | Step circuits (FheCompute, Bootstrap) were Nova-specific — they may not have Cyclo equivalents. The aggregator folding path uses plain `CcsPShareInstance` which Cyclo natively supports |
| `ProofCompressor` trait is used in CLI/tests | Medium | We simplify the trait rather than replicating all Nova methods |
| On-chain verifier format changes | Low | The on-chain verifier (`PvtFheVerifier.sol`) uses UltraHonk, not Nova. Cyclo accumulator hash can be embedded in the same public inputs |
| Performance regression without Nova | Low | Cyclo fold is lattice-native (no curve ops) — likely faster than Nova's BN254+Grumpkin cycle |

## Acceptance Criteria

1. `CycloCompressor` exists with fold + finalize + verify
2. Aggregator uses `CycloCompressor` for fold path
3. All Nova code removed from compressor crate
4. `cargo check --workspace` passes
5. All existing cyclo + aggregator tests pass
6. At least one integration test: fold 4 instances, finalize, verify
7. DOCUMENTATION updated: ARCHITECTURE.md reflects Track B as sole backend, SECURITY.md mentions Track A removal
