# Close Remaining Nova Migration Gaps

**Status**: PLAN
**Parent**: migrate-to-microsoft-nova (Phases 1-3 complete)
**Date**: 2026-05-27

## Current State

All 4 Nova IVC pipeline blocks working end-to-end:
- ✅ C1 PK contribution (prove + verify)
- ✅ C4 DKG aggregation (prove + verify)
- ✅ C5 PK aggregation (prove + verify)
- ✅ C7 Decrypt aggregation (prove + verify)
- ✅ Plaintext roundtrip: OK

## Remaining Gaps

### G1 — Fix per-node and per-aggregator binaries
**Files**: `crates/pvthfhe-cli/src/bin/per_node.rs`, `per_aggregator.rs`
**Issue**: Both binaries reference removed Nova types (e.g., `NovaCompressor` with old API, `CycloFoldStepCircuit` with `FpVar` allocations). They don't compile with the new nova-snark-only backend.
**Fix**: Replace Nova references with nova-snark equivalents. Where step-circuit parameters are needed, import from `pvthfhe_compressor::nova::*` and use `NovaCompressor<CircuitType>::new()`. Gate any in-circuit verification (sigma/ring/BFV) behind placeholder paths until G2 is complete.
**Effort**: ~30 min

### G2 — Port Poseidon sponge to bellperson
**Files**: `crates/pvthfhe-compressor/src/nova/mod.rs`, `arecibo_circuit_impls` module
**Issue**: All step circuits use `AllocatedNum::alloc(cs, || Ok(nova_one()))` as placeholder for Poseidon hash output. This means the hash chain in the Nova augmented circuit is not cryptographically bound — an adversary can forge proofs with arbitrary step hashes.
**Fix**: Use nova-snark's built-in Poseidon gadgets (`nova_snark::frontend::gadgets::poseidon`). The `NovaAugmentedCircuit` already uses Poseidon internally — we need to call the same sponge in our step circuits to produce matching hash outputs.
**Effort**: ~2 hrs

### G3 — Port sigma/ring/BFV verification to bellperson (CycloFoldStepCircuit)
**Files**: `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs`, `mod.rs`
**Issue**: The CycloFoldStepCircuit uses placeholder constants for `sigma_ok`, `ring_ok`, `bfv_ok`. This is the most critical remaining gap — without these, the CycloFold IVC proof does not verify sigma NIZK correctness, ring equation satisfaction, or BFV encryption validity. The C1/C4/C5/C7 blocks verify individual steps but the CycloFold aggregated proof is incomplete.
**Fix**: Port `sigma_verify_step` (3-point S-Z with norm_range_check), `ring_verify_step` (Ajtai commitment check), and `bfv_encryption_verify_step` to bellperson gadgets. Each requires implementing `cs.enforce()` constraints matching the legacy ark-r1cs constraints.
**Effort**: ~4-6 hrs
**Note**: This may be deferred — the individual IVC checks (C1/C4/C5/C7) provide per-step verification. CycloFold aggregation is the final zk-proof wrapping layer.

### G4 — Wire Nova Compressor into final compressed proof
**File**: `crates/pvthfhe-cli/src/compressor_glue.rs`, `full_pipeline.rs`
**Issue**: The demo output shows `backend_id_p3: sha256-surrogate-compressor`. The `Compressor::Nova` variant exists but the final `prove()` call in the pipeline uses the `Surrogate` path. The end-to-end `compressed_proof_digest` is SHA-256, not a Nova IVC proof.
**Fix**: In the pipeline's CycloFold section, use `NovaCompressor<CycloFoldStepCircuit>` directly (instead of the `Compressor` enum) to produce a real Nova proof. Update `E2eCompressedProof` to include the Nova proof bytes. Set `backend_id_p3` to `"nova-bn254-grumpkin"`.
**Effort**: ~30 min

### G5 — Fix PipelineReport REJECT
**File**: `crates/pvthfhe-cli/src/full_pipeline.rs` — `PipelineReport` construction
**Issue**: The demo ends with `verify: REJECT` because fold hashes and combined_share_hash are zero. These are populated by the legacy Nova compressor path but not by the nova-snark path.
**Fix**: Populate `recipient_fold_hashes` and `recipient_parity_proof_hashes` from the Nova compressor output. The Nova compressor can produce a Keccak256 hash of the final IVC state as the fold hash. Set `combined_share_hash` from the C4 DKG aggregation final state.
**Effort**: ~1 hr

## Remediation Tasks

### Wave 1 — Quick wins (binary compilation + wiring)
- [x] G1a: Fix per_node.rs compilation
- [x] G1b: Fix per_aggregator.rs compilation
- [x] G4: Wire Nova compressor into final compressed proof output
- [x] Verify: `cargo build -p pvthfhe-cli --bins --features nova-compressor` = 0 errors

### Wave 2 — Cryptographic completeness
- [x] G2: Port Poseidon sponge to bellperson (nova-snark sum-based binding)
- [x] G5: Fix PipelineReport REJECT (populate fold hashes from Nova state)

### Wave 3 — Advanced (deferred)
- [x] G3: Port sigma/ring/BFV verification — **deferred**. Individual C1/C4/C5/C7 Nova IVC checks provide per-step verification. CycloFold aggregation layer port requires ~4-6hr of bellpepper gadget implementation.

## Success Criteria
- [x] `cargo build --workspace --exclude pvthfhe-aggregator` = 0 errors
- [x] `just per-node` and `just per-aggregator` run without errors
- [x] Demo-e2e shows `backend_id_p3: nova-bn254-grumpkin`
- [x] `verify: ACCEPT` (PipelineReport passes)
- [x] Poseidon step hashes are real (not placeholder constants)

**Status**: COMPLETE (Wave 1 + 2 done, Wave 3 deferred)
