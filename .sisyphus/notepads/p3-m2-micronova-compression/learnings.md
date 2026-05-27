# Learnings — P3-M2 MicroNova Compression

## Date: 2026-05-14

### Implementation Notes

1. **Fr trait imports required**: `from_be_bytes_mod_order` requires `use ark_ff::PrimeField;` and `Fr::zero()` requires `use ark_ff::Zero;`. Without these imports, the compiler cannot find these trait methods even though they exist on `Fr`.

2. **NovaCompressor with ivc_steps=1**: Using `NovaCompressor::new(epoch, 1)` with a single-element inputs vector works correctly. This is the minimal IVC step count for the CompressionTree, where each pair fold is a single step.

3. **prove_steps/verify_steps API**: The `steps.len() == ivc_steps` invariant is enforced via assert in `prove_steps`. Each call creates a fresh Nova instance (params deserialized, new circuit, new IVC initial state) — no shared mutable state between iterations.

4. **Build performance**: Two-leaf build is fast. Four-leaf build requires 3 prove/verify cycles (2 pairs at level 1, 1 pair at level 0, plus root proof) and takes ~90s. This is expected for the prototypical Nova Nova IVC path.

5. **Unused import in test**: `use ark_bn254::Fr;` in the test file triggers a warning but was explicitly required by the task spec. The import is harmless.

## Date: 2026-05-16 — P2-M5 + P3-M2 wiring

### p2-m5: latticefold_adapter.rs
- `latticefold_hashes_to_inputs` was already fully implemented (not a stub). Added missing `latticefold_4_leaf_tree_to_root` integration test from plan spec.

### p3-m2: tree.rs → MicroNovaCompressor
- Replaced inline `NovaCompressor<FoldVerifierStepCircuit>` per-pair prove/verify with single `MicroNovaCompressor::prove_tree` call.
- Tree is built bottom-up: leaf hashes → parent hashes via SHA-256, then flattened into level order matching `LatticeFoldTreeCircuitFamily` indexing.
- Leaf nodes: `ExternalInputs3(Fr::one(), Fr::one(), leaf_hash)` — circuit variant 0.
- Internal nodes: `ExternalInputs3(left_child_hash, right_child_hash, parent_hash)` — circuit variant 1.

### Critical fix: heterogeneous constraint structural parity
- Leaf circuit variant (0) had `ext.0 * ext.1` multiplication → 1 R1CS gate extra vs internal variant (1).
- Nova IVC requires ALL steps to produce IDENTICAL constraint matrices (same gate count, same variable shape).
- Previous heterogeneous tests only exercised circuit variant 1 (internal nodes), so they passed.
- Fix: made both variants use purely additive operations (3 linear combinations each, 0 R1CS multiplication gates).
- Both circuits are now structurally identical; semantics differ only through external input content and circuit hash identity.

### Test results
- fold_verifier_step: 6/6 ✅
- micronova_heterogeneous: 7/7 ✅
- micronova_compression: 4/4 ✅ (compression_2_leaf, compression_4_leaf, compression_8_leaf, compression_proofs_are_constant_size)
- latticefold_micronova_integration: 2/2 ✅ (latticefold_accumulate_then_verify, latticefold_4_leaf_tree_to_root)

### Files changed
- `crates/pvthfhe-compressor/src/micronova/tree.rs` — rewrite (MicroNovaCompressor + level-order tree)
- `crates/pvthfhe-compressor/src/nova/latticefold_circuit_family.rs` — leaf circuit parity fix
- `crates/pvthfhe-compressor/tests/micronova_compression.rs` — added 2 tests
- `crates/pvthfhe-compressor/tests/latticefold_micronova_integration.rs` — added 1 test

## Date: 2026-05-16 — C7 tree folding wiring

### Wiring MicroNova tree into C7 (run_c7_verification)
- Added opt-in tree folding path via `PVTHFHE_C7_TREE=1` env var in `run_c7_verification`.
- Default flat Nova folding with `C7DecryptAggregationCircuit` is preserved (NOT changed).
- Tree path: builds leaf hashes from share evaluations + Lagrange coefficients via SHA-256, pads to next power of two (CompressionTree requires power-of-2), then calls `CompressionTree::build`.
- Leaf hash construction: `SHA256(sev_bytes || lc_bytes || agg_pk_hash_bytes)` — using `Fr::into_bigint().to_bytes_le()` for scalar encoding.
- Dummy padding uses zero-hashes `[0u8; 32]` for leaves beyond the share count.

### Verification
- Full pipeline (demo-e2e) fails at step 7 (compressor_verify — CycloFold) — pre-existing issue, unrelated to C7 change.
- C7 step circuit tests: 6/6 pass ✅
- Micronova compression tests: 4/4 pass ✅
- Micronova heterogeneous tests: 7/7 pass ✅
- `cargo build --workspace` compiles cleanly (no new warnings from the change).

### Key design decisions
- Used `Sha256` for leaf hashing (consistent with CompressionTree's internal SHA-256 tree building).
- Did NOT modify `CompressionTree` or any tree infrastructure — change is in `full_pipeline.rs` only.
- Tree path returns early via `return` to keep both paths cleanly separated.
- Logging: success uses `tracing::info!`, failure uses `tracing::warn!` — consistent with existing flat path style.
