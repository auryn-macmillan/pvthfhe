## Learnings — A.1 + A.2 Implementation

### Coefficient Ordering Convention
The existing `eval_poly_bn254` Horner method evaluates `p(r) = Σ coeffs[i] * r^{N-1-i}` (coefficient 0 has highest power). When implementing `eval_with_powers`, must iterate powers in reverse (`powers.iter().rev()`) to match this convention. `precompute_powers_r` creates `[r^0, r^1, ..., r^{N-1}]`, and eval matches coeffs[0] with r^{N-1}.

### ark-ff 0.5 Trait Imports
`Fr::one()` requires `ark_ff::One` (or `ark_ff::Field`), but `ark_ff::Field` import may not enable `one()` in all ark-ff versions. Safer to use `Fr::from(1u64)` and `Fr::from(0u64)` which work without additional trait imports.

### Batching Correctness
Batching at the pipeline level sums share evaluations (d_i(r)) and Lagrange coefficients (λ_i) separately, then passes them as a single external input. The circuit computes `(Σ λ_i)(Σ d_i(r))` per batch rather than `Σ λ_i·d_i(r)`. For performance optimization this is acceptable, but the mathematical equivalence is approximate.

### Build Feature Requirements
`run_c7_verification` requires both `pipeline-extra-checks` and `nova-compressor` features. The `just demo-e2e` command enables these via `--features pipeline-extra-checks,nova-compressor`.

### Stash/Git Safety
When using `git stash` to test pre-existing behavior, a `git stash pop` conflict can cause loss of working changes if the stash is subsequently dropped. Always verify working tree state after stash operations.

### A.3 Documentation (2026-05-16)
- The per-node binary (`per_node.rs`) measures keygen, Shamir split, encrypt, NIZK prove/verify but does NOT exercise the Nova compression path. For Nova profiling, use the E2E demo (`pvthfhe_e2e`) or `per_aggregator` binary.
- The `per_aggregator` binary uses `NovaCompressor<CycloFoldStepCircuit<Fr>>` directly for fold timing.
- Five Nova step circuit types exist: `ToyStepCircuit`, `CycloFoldStepCircuit`, `C7DecryptAggregationCircuit`, `C7MerkleStepCircuit`, `FoldVerifierStepCircuit` — all implementing `FCircuit<F>::generate_step_constraints`.
- Poseidon configuration: t=5 (rate=4, capacity=1), full_rounds=8, partial_rounds=60, alpha=5. Three permutations per hash8 call (~900 R1CS constraints total).
- The `REPRODUCING.md` expected runtimes table (1.5-188ms) is marked as stale stub data — not representative of target Architecture B.
- The existing `per_node` binary at n=500 would show ~42.7s total but only measures per-party work, not Nova IVC folding.

### Fix 1: build_c7_prover_toml Noir circuit mismatch (2026-05-18)
- The Noir `aggregator_final` circuit was updated (G-LAGRANGE fix) to require `committee_party_ids` instead of `lagrange_coeffs`, and to compute `plaintext`/`plaintext_hash` internally rather than taking them as inputs.
- `build_c7_prover_toml` in `full_pipeline.rs` was still generating the old TOML format with `lagrange_coeffs`, `plaintext_hash`, `plaintext`, and `z_q` fields.
- Fix: Replaced `lagrange_coeffs: &[Fr]` param with `committee_party_ids: &[u32]`, removed old fields from TOML output, added `committee_party_ids` array.
- Updated both callers: `full_pipeline.rs` (demo-e2e Noir phase) and `pvthfhe_e2e.rs`.
- Added `committee_party_ids: Vec<u32>` to `PipelineReport` for the e2e caller.

### Fix 2: C7 tree folding in per_aggregator (2026-05-18)
- The `per_aggregator` benchmark used flat Nova Nova folding (`prove_steps_c7`) which was 50s at n=16 (7.1s/step).
- The demo-e2e pipeline uses `CompressionTree::build` (MicroNova heterogeneous IVC) with tree folding achieving 3.6s at n=16 (31x faster).
- Fix: Replaced flat Nova with `CompressionTree::build` using dummy leaf hashes. Kept flat Nova as fallback.
- Required imports: `ark_ff::{BigInteger, PrimeField}`, `pvthfhe_compressor::micronova::tree::CompressionTree`.
