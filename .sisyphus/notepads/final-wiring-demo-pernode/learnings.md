# Learnings — final-wiring-demo-pernode

## W1: Close p2-m6 ring equation gap

- The native ring equation check (full_pipeline.rs:559-564) already gates pipeline acceptance via `anyhow::bail!` with `?` propagation.
- Added a documentation comment (lines 574-581) explaining the defense-in-depth: the native check gates pipeline acceptance, the compressor's internal `verification_count == fold_count` check (mod.rs:462-478) provides defense-in-depth when ext.2 is properly populated.
- Added 6 new native `verify_ring_equation` tests to `cyclo_r1cs_verifier.rs` covering: honest witness (c=1, c=-1, c=0) and broken witness (c=1, c=-1, c=0).
- All 10 tests pass (4 original R1CS + 6 new native).

## W4: Make C7 tree folding default

- Removed `if std::env::var("PVTHFHE_C7_TREE").is_ok()` gate at line 1485.
- Tree path now always runs first. On success, returns `true`. On failure, logs warning and falls through to flat sequential folding path.
- The tree code and flat Sonobe path are both gated by `#[cfg(feature = "sonobe-compressor")]` on the enclosing function.
- No API changes to the compressor.

## Pre-existing issues

- `demo-e2e` fails at step 7/10 (`compressor_verify`: "sonobe compressed proof verification failed"). This is a pre-existing issue NOT caused by these changes — occurs before the C7 tree code runs.
- `red_3_records_all_full_pipeline_phases` test has the same pre-existing failure.
- `per-node` and `per-aggregator` binaries have pre-existing `Zero` trait import errors.

## W2+W3 Implementation (2026-05-16)

### W2.1: Track support in per_node
- Added local `Track` enum (mirrors `full_pipeline::Track`) because `full_pipeline` module requires `sonobe-compressor` feature but per-node only requires `with-fhe`
- Parsed from `--track` CLI arg with case-insensitive matching ("A"/"B")

### W2.2: AjtaiMatrix for Track B
- Used `compute_ajtai_matrix_commitment()` inline (same logic as `full_pipeline::compute_ajtai_commitment_for_track` Track B path)
- Uses `pvthfhe_cyclo::ajtai` and `pvthfhe_cyclo::ring` (always available, not feature-gated)
- Track A (Cyclo NIZK) is default and untouched

### W3.1: C7 tree in per_node
- Gated behind `#[cfg(feature = "sonobe-compressor")]` since Compressor crate requires that feature
- `time_c7_tree_folding()` uses `CompressionTree::build()` from MicroNova
- `time_c7_flat_folding()` uses standard `SonobeCompressor<C7DecryptAggregationCircuit<Fr>>`
- `--use-c7-tree` flag controls which path; default is flat folding

### W3.2: MicroNova in per_aggregator
- Added `--use-micronova` flag; default is standard Sonobe compressor
- `time_micronova_compressor()` uses `MicroNovaCompressor::new(depth, epoch_hash)` with tree depth = ceil(log2(batch_count))

### Build verification
- Both binaries compile with `cargo build -p pvthfhe-cli --bin per-node --bin per-aggregator`
- Pre-existing test failure in `full_pipeline::tests::red_3_records_all_full_pipeline_phases` (unrelated sonobe proof verification issue)
- Smoke tests confirmed: Track A (default), Track B, `--use-c7-tree`, `--use-micronova` all work
