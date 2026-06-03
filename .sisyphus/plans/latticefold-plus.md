# P3 — LatticeFold+: Lattice-Native Folding

**Status**: PLAN
**Date**: 2026-05-31
**Parent**: `.sisyphus/plans/lattice-meta-plan.md`

## Goal

Replace nova-snark (elliptic-curve-based Nova IVC) with LatticeFold+, a lattice-native folding scheme. This is the capstone integration — combined with LaZer sigma proofs and Greyhound PCS, it produces a fully post-quantum proving stack.

## Why LatticeFold+

- 5-10× faster prover than LatticeFold (original)
- **Purely algebraic range proof** — no bit decomposition. Replaces our `monomial_range.rs` entirely.
- Double commitments (commitments of commitments) for shorter proofs
- Sumcheck-based transformation for folding double commitments
- Post-quantum security (lattice assumptions only)
- Operates over small 64-bit fields, not 256-bit BN254

## Integration Architecture

```
pvthfhe-compressor/src/
├── latticefold/              ← New module replacing nova/
│   ├── fold.rs               ← LatticeFold+ folding logic
│   ├── range_proof.rs        ← Algebraic range proof (replaces monomial_range.rs)
│   ├── double_commit.rs      ← Double commitment scheme
│   ├── sumcheck.rs           ← Sumcheck transformation
│   ├── step_circuits/        ← Ported step circuits (DkgAggregation, PkAggregation, etc.)
│   └── compressor.rs         ← LatticeFoldCompressor (replaces NovaCompressor)
```

## Phases

### Phase 1 — Core LatticeFold+ Implementation (~8 hrs)
- [ ] Implement `LatticeFoldProver`: fold n instances into one using random β
- [ ] Implement `LatticeFoldVerifier`: verify folded instance
- [ ] Implement algebraic range proof: prove |w| ≤ B using polynomial arithmetic (no bit decomposition)
- [ ] Implement double commitment: commit to commitments for shorter proofs
- [ ] Implement sumcheck transformation for folding double commitments
- [ ] Add `enable-latticefold` feature flag
- [ ] Verify: `cargo test -- latticefold` — fold/verify roundtrip (trivial circuit)

### Phase 2 — Port Step Circuits (~6 hrs)
- [ ] Port `DkgAggregationStepCircuit` from nova-snark → LatticeFold+ StepCircuit trait
- [ ] Port `PkAggregationStepCircuit`
- [ ] Port `PkContributionStepCircuit`
- [ ] Port `DealerParityStepCircuit`
- [ ] Port `LagrangeFoldStepCircuit`
- [ ] Port `CycloFoldStepCircuit` (arity=8 with sigma/ring/BFV)
- [ ] Port `SchemeSwitchStepCircuit`, `BfvEncryptionSnapshot`, `FheComputeStepCircuit`, `BootstrapStepCircuit`
- [ ] Use algebraic range proof instead of `monomial_range_check_bp` throughout

### Phase 3 — Replace NovaCompressor (~6 hrs)
- [ ] Create `LatticeFoldCompressor` with same API as `NovaCompressor`
- [ ] Implement `new()`, `prove_steps()`, `verify_steps()`, `prove_steps_with()`
- [ ] Replace `RecursiveSNARK::verify` with `LatticeFoldProver::verify`
- [ ] Update `CompressedProof` format for LatticeFold proof bytes
- [ ] Wire into `full_pipeline.rs` C1/C4/C5/C7 blocks
- [ ] Wire into `compressor_glue.rs` CycloFold path
- [ ] Wire into `per_node.rs` and `per_aggregator.rs`

### Phase 4 — Integration Testing (~4 hrs)
- [ ] Test BFV DKG with LatticeFold+ (n=3, t=1, n=10, t=4, n=64, t=31)
- [ ] Test CKKS DKG with LatticeFold+ (n=3, t=1)
- [ ] Test TFHE DKG with LatticeFold+ (n=3, t=1)
- [ ] Test scheme-switch with LatticeFold+ (poulpy-all)
- [ ] Test FHE compute with LatticeFold+ (just compute n=5)
- [ ] Benchmark: LatticeFold+ prove time vs Nova prove time at n=16, 32, 64
- [ ] Benchmark: LatticeFold+ proof size vs Nova proof size

## Success Criteria
- [ ] `cargo check --features enable-latticefold` zero errors
- [ ] All step circuits ported and passing tests
- [ ] `just demo-e2e` ACCEPT with LatticeFold+ backend (n=3, n=10, n=64)
- [ ] `just poulpy-all` ACCEPT with LatticeFold+ backend
- [ ] `just greco` and `just compute` work with LatticeFold+
- [ ] LatticeFold+ prover 5-10× faster than Nova prover (benchmarked)
- [ ] Algebraic range proof replaces monomial_range.rs entirely
- [ ] Zero elliptic curve or discrete-log assumptions in the proving stack
- [ ] All 10 Justfile commands work without error
