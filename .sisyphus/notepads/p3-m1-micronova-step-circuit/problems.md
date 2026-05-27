# P3-M1 Problems

## Unresolved
1. NovaCompressor internal state_len constraint (hardcoded 3-element minimum) — needs generalization for future circuits with different state widths.
2. The FoldVerifierStepCircuit uses simplified hash-accumulation logic; real CCS verifier constraints remain unimplemented.

## Deferred
- Recursive compression pipeline (compress_latticefold_tree) → P3-M2
- MicroNova heterogeneous circuits → P3-M2
- On-chain UltraHonk verifier → P3-M3
