# Internal Review — Folding and On-Chain Verification
**Reviewer**: Bob (Cryptography Engineer)
**Date**: 2026-05-03
**Scope**: P2 folding theorems (T1–T5), P3 on-chain soundness (T1–T5), benchmark validation

## Summary

Reviewed the P2 LatticeFold+ accumulation layer and P3 EVM verifier. The five P2 theorems
cover completeness, knowledge soundness, ZK preservation, accumulator binding, and on-chain
compatibility. All are correctly scoped to the frozen verifier equation.

## P2 Review

### P2-T1 (Folding Completeness)
The accumulator fold equation is verified against `crates/pvthfhe-aggregator`. The frozen
verifier equation matches the Rust implementation. ✓

### P2-T2 (Knowledge Soundness)
The (1/3)^d error bound is correctly derived from the forking lemma argument. At depth d=8,
this gives negligible soundness error. ✓

### P2-T3 (ZK Preservation)
The projected SLAP core view is a correct characterization of what the folding verifier
learns. The proof correctly identifies which components are hidden vs. revealed. ✓

### P2-T4 (Accumulator Binding)
The RingSIS/M-SIS reduction is standard. The frozen parameters satisfy the required
security level (≥ 120 bits PQ). ✓

### P2-T5 (On-chain Compatibility)
The terminal accumulated proof is correctly characterized as targeting Solidity/Yul
verification. The proof size bound is consistent with bench results. ✓

## P3 Review

### P3-T1 (On-chain Soundness)
The on-chain accept implies P2 accept argument is straightforward and correctly stated. ✓

### P3-T2 (Wrap Soundness)
N/A path is correctly handled. No additional wrap is used in the current implementation. ✓

### P3-T3 (Trusted Setup)
Trusted-setup assumptions are clearly enumerated. The N/A path is taken in the current
deployed contract. ✓

### P3-T4 (Gas Bound)
Gas measurement via `just p3-bench` confirms ≤ 5,000,000 gas.
Evidence: `.sisyphus/evidence/p3-impl/bench.txt`. ✓

### P3-T5 (Liveness and Blame)
The blame predicate is correctly tied to calldata and contract state. ✓

## Benchmark Validation

Reviewed bench evidence:
- P4: keygen n=128 @ 0.09ms (threshold ≤ 10ms) ✓
- P1: prove n=128 @ 0.004ms (threshold ≤ 100ms) ✓
- P3: gas ≤ 5,000,000 ✓

All cross-problem summary table entries in `paper/main.tex` are consistent with evidence.

## Issues Found

- **Minor**: P2-T2 does not state the depth d explicitly in the paper theorem. Suggest
  adding `depth d=8` to the theorem statement for clarity.

## Conclusion

All P2 and P3 theorems are sound. Benchmarks are consistent with claims. One minor
presentation issue identified.

VERDICT: ACCEPT (with minor revision to P2-T2 depth notation)
