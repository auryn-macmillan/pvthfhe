
## Task 6: In-circuit Schnorr challenge derivation (2026-05-19)

### Completed
- `ShareVerificationStepCircuit::generate_step_constraints` now uses `external_inputs` (was `_external_inputs`)
- Three-phase Poseidon hashing: (1) share coeffs, (2) Schnorr challenge derivation, (3) accumulation
- ExternalInputs4 fields: `.0=sig_r_x, .1=sig_s, .2=pk_x, .3=domain`
- EC equality check deferred to Phase 2b; circuit only binds the challenge derivation

### Build status
- `cargo check -p pvthfhe-compressor` passes
- `cargo test -p pvthfhe-compressor --no-run` compiles all 22 test binaries
- No new LSP diagnostics

## Task 9: Wire ShareVerification folding into pipeline (2026-05-19)

### Completed
- Added `ShareVerificationWitness`/`ShareVerificationWitnessSet` import from `pvthfhe_compressor::witness`
- Built `ShareVerificationWitnessSet` after Schnorr signing (line ~870)
- Created `NovaCompressor<CycloFoldStepCircuit<Fr>>` for share verification folding after CycloFold compressor
- Changed to `CycloFoldStepCircuit<Fr>` type param because `prove_steps_share_verify` is defined on `impl NovaCompressor<CycloFoldStepCircuit<Fr>>`
- Called `prove_steps_share_verify(&sv_acc, &sv_witness_set)` with encoded quad accumulator
- Computed `combined_share_hash` natively using `poseidon_sponge_hash_native` matching the circuit's accumulator logic
- Added `combined_share_hash: Fr` field to `PipelineReport`
- Added `combined_share_hash: Fr` parameter to `build_c7_prover_toml`
- Wrote `combined_share_hash` to Prover.toml output
- Updated e2e binary call site
- Updated test
- Gated under `#[cfg(feature = "nova-compressor")]` with fallback to `Fr::from(0u64)` for surrogate path

### Gotchas
- `NovaCompressor::new` returns `Result<Self, CompressorError>`, not `anyhow::Result` — must use `.map_err()` not `.context()`
- `prove_steps_share_verify` is on `NovaCompressor<CycloFoldStepCircuit<Fr>>`, not `ShareVerificationStepCircuit<Fr>` (stub design)
- No `initial_acc()` method exists — must create accumulator as `encode_quad((Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero())).to_vec()`
- Existing dead code warnings (`vector_hash_8`, `bind_8_with_domain_native`, `combine_hashes_8`) became unused after replacing old share hash computation

### Build status
- `cargo check -p pvthfhe-cli` passes (no errors)
- `cargo test -p pvthfhe-cli -- c7_prover_toml` passes
- LSP diagnostics: no errors
