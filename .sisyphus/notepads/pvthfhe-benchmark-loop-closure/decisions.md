# Decisions — pvthfhe-benchmark-loop-closure

## 2026-05-06

- FHE backend: gnosisguild/fhe.rs (locked, AGENTS.md)
- Folding compressor: Nova Nova (substituting MicroNova), bounded migration surface
- Path A for PVSS (lattice PVSS), gated on P0a feasibility spike
- Full-dim Noir + real BB-generated UltraHonk, gated on N3a feasibility spike
- Baseline: Interfold published results only (no rerun)

- E1 normalizes the only naming mismatch between Interfold and PVTHFHE comparison output by treating `OnChainUltraHonkVerify` as the canonical baseline name and `onchain_verify` as the emitted row alias through `comparison_row_name`/`mapping_for_comparison_row`.
