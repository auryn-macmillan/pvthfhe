# Per-Aggregator C7 Tree Path Fix — Learnings

## Issue
The per_aggregator C7 tree path was ~327s for 8 leaves because it was double-proving:
1. Per-leaf Nova proving via `SonobeCompressor<C7DecryptAggregationCircuit>` + `prove_steps_c7`
2. Then `CompressionTree::build` which internally does Nova proving via `MicroNovaCompressor::prove_tree`

The demo-e2e pipeline (full_pipeline.rs) correctly only hashes leaf data and calls
`CompressionTree::build` — no per-leaf Nova proving.

## Fix Applied
Replaced the per-leaf Nova proving loop with:
1. Hash leaf data directly using `rayon::par_iter` for parallel computation
2. Pad to power of 2
3. Call `CompressionTree::build(&padded_hashes)` — handles all proving internally

## Result
- **Before**: 327s for n=16, t=7 (8 leaves padded)
- **After**: 3.9s for n=16, t=7 (tree depth=3, 8 leaves)
- **Speedup**: ~84x

## Files Changed
- `crates/pvthfhe-cli/src/bin/per_aggregator.rs`: Replaced tree path (old lines 175-237)
  - Removed per-leaf `SonobeCompressor<C7DecryptAggregationCircuit>` loop
  - Added parallel leaf hash computation with `rayon::par_iter`
  - Moved `hash_all_coeffs` computation into flat Nova fallback block
  - Added `use ark_ff::{BigInteger, PrimeField}` at module level

## Key Design Insight
`CompressionTree::build` uses `MicroNovaCompressor::prove_tree` which takes a flat
vector of `ExternalInputs3` steps covering ALL tree nodes (leaves + internal). Each
step uses circuit-variant encoding to distinguish leaf vs internal nodes. There is
no per-leaf Nova prover — the tree build IS the proving. You feed it raw 32-byte
leaf hashes and it does everything.
