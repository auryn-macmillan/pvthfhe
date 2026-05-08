# Sonobe migration surface

This note freezes the bounded migration surface for a future compressor backend
swap from Sonobe to MicroNova. The touch-point count stays deliberately small.

- `crates/pvthfhe-compressor/src/lib.rs` — owns the backend-neutral `ProofCompressor` entry point and selects the active backend adapter.
- `crates/pvthfhe-compressor/src/step_circuit.rs` — holds the frozen backend-agnostic step-circuit description whose hash and public-input layout must remain stable.
- `crates/pvthfhe-compressor/src/sonobe/mod.rs` — contains the Sonobe-specific adapter layer that would be replaced by a MicroNova implementation.
- `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` — reports compressor backend identity in operator-facing end-to-end output.
- `crates/pvthfhe-bench/src/bin/bench_comparison.rs` — records compressor backend identity in comparison artifacts so backend swaps remain auditable.
