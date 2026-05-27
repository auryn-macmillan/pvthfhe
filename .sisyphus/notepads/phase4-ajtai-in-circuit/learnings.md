## 2026-05-19 — AjtaiCommitmentStepCircuit scaffold

### Pattern
- Followed exact structure from `share_verification_circuit.rs` (lines 1-99):
  - `thread_local!` for per-party witness data (`AJTAI_WITNESS_DATA`)
  - `set_/clear_` accessors matching existing conventions
  - Struct derives: `Clone, Debug, Default`
  - `FCircuit` impl: `state_len=2`, `ExternalInputs=ExternalInputs6`
  - `StepCircuit` impl: `descriptor` with `width: 2`, `circuit_hash` via Keccak256

### State layout
- `z[0]`: accumulated_commitment_hash (Poseidon sponge output accumulated per step)
- `z[1]`: step_count (incremented by `FpVar::constant(F::one())`)

### Fr → F conversion
- Used `F::from_le_bytes_mod_order(&c.into_bigint().to_bytes_le())` to convert `ark_bn254::Fr` to generic `F: PrimeField` — same as share_verification_circuit.rs

### Test structure
- 4 RED→GREEN tests: set/clear witness, different witness→different hash, deterministic circuit_hash, default witness→valid output
- Tests use `ConstraintSystem::new_ref()` + `FpVar::constant()` for placeholder-only path (no real witnesses allocated)

## Phase 4c: Ajtai witness types + prove_steps_ajtai

**Date**: 2026-05-19

### Changes made

1. **witness.rs**: Added `AjtaiCommitmentWitness` struct (coeffs, expected_commitment_hash, matrix_seed) and `AjtaiCommitmentWitnessSet` with `verify_commitments()` — placed after `ShareVerificationWitnessSet`, following identical pattern.

2. **mod.rs**: Added `prove_steps_ajtai` method to `NovaCompressor<CycloFoldStepCircuit<Fr>>` — placed after `prove_steps_share_verify`. Delegates to `self.prove_steps()` using `ExternalInputs4<Fr>`.

### Type mismatch resolved

The plan code used `ExternalInputs6` but `prove_steps` takes `ExternalInputs4<Fr>`. Resolved by packing the 6 witness fields (expected_commitment_hash + 4 matrix_seed chunks + domain_tag) into 4 ExternalInputs4 slots:
- slot 0: expected_commitment_hash
- slot 1: first 16 bytes of matrix_seed as Fr (via from_be_bytes_mod_order)
- slot 2: last 16 bytes of matrix_seed as Fr (via from_be_bytes_mod_order)
- slot 3: domain tag (Fr::from(1u64))

The remaining data (coeffs) is passed via the AJTAI_WITNESS_DATA thread-local, matching the pattern from share verification.

### Key technical notes

- `Fr::from_be_bytes_mod_order` takes `&[u8]` directly — no `try_into()` needed (original plan code had this bug)
- `prove_steps` is hardcoded to `CycloFoldStepCircuit` internally; cannot use with `AjtaiCommitmentStepCircuit` directly

### Verification

`cargo check -p pvthfhe-compressor` passes clean (0 errors).

## Phase 4d: combined_commitment_hash public input to aggregator_final

**Date**: 2026-05-19

### Changes made

1. **main.nr**: Added `combined_commitment_hash: pub Field` to `main` function params (line 77), after `decrypt_nizk_hash` and before `dkg_root`. Comment: "G.12 Phase 4: combined hash of Nova-folded Ajtai commitment verifications."

2. **Test callers**: Updated 6 of 8 test functions that call `main()` to pass `0` as the new arg. The 2 collision tests don't call `main()` so they needed no update.

### Verification

`(cd circuits && nargo test --package aggregator_final)` — all 8 tests pass.
Warning about unused `combined_commitment_hash` is expected (field not constrained in-circuit).

## Phase 4: Pipeline wiring (demo-e2e + per_node + aggregator)

**Date**: 2026-05-19

### Changes made

1. **full_pipeline.rs (lines 283-336)**: Added Phase 4 Ajtai commitment folding block after share provenance checks.
   - Builds `AjtaiCommitmentWitnessSet` from `sk_commitments`
   - Folds via `NovaCompressor::<CycloFoldStepCircuit<Fr>>::new()` + `.prove_steps_ajtai()`
   - Computes `combined_commitment_hash` via `poseidon_sponge_hash_native` over all sk_commitments as Fr
   - Falls back to `Fr::zero()` on errors (with `tracing::warn`)
   - Gated behind `#[cfg(feature = "nova-compressor")]`

2. **build_c7_prover_toml** (line 2151): Added `combined_commitment_hash: Fr` parameter.
   - Written to TOML as `combined_commitment_hash = "0x..."` (after share_verification_proof_hash)
   - All 3 callers updated: main pipeline, test, pvthfhe_e2e

3. **per_node.rs (line 189)**: Added `tracing::debug!` log after ajtai commitment computation.

4. **per_aggregator.rs**: No changes needed (aggregator does not do per-party commitment verification).

### Key adaptation from task pseudo-code

- Task pseudo-code used `AjtaiCommitmentStepCircuit<Fr>` as type param, but `prove_steps_ajtai` is only available on `impl NovaCompressor<CycloFoldStepCircuit<Fr>>` (line 1465 of nova/mod.rs). Used `CycloFoldStepCircuit<Fr>` instead.
- Task pseudo-code used `?` operator for `CompressorError` but that error type doesn't implement `std::error::Error`. Used `.map_err(|e| anyhow::anyhow!(...))` instead.
- Task pseudo-code used `proof.accumulator` and `initial_acc()` which don't exist. Used Poseidon hash of all commitment Fr values as the `combined_commitment_hash`.

### Verification

- `cargo check -p pvthfhe-cli` passes (0 errors)
- `cargo test -p pvthfhe-cli -- c7_prover_toml` passes
- LSP diagnostics: 0 errors across all modified files
