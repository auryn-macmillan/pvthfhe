# Lattice Papers Integration — Meta-Plan

**Status**: PLAN
**Date**: 2026-05-31
**Branch**: `feat/lattice-papers` (to be created)

## Overview

Integrate three state-of-the-art lattice papers into pvthfhe, replacing Nova IVC, KZG commitments, and hand-crafted sigma protocols with lattice-native alternatives. The goal is a fully post-quantum proving stack with no elliptic curve or discrete-log assumptions.

## Architecture Changes

```
BEFORE:
  Sigma NIZK (hand-crafted) → Nova IVC (EC-based, nova-snark) → KZG accum. (Aztec SRS) → UltraHonk

AFTER:
  Sigma NIZK (LaZer auto-generated) → LatticeFold+ (lattice-native) → Greyhound PCS → UltraHonk
```

## Sub-Plans

### P1 — LaZer: Auto-Generated Sigma Proofs
**File**: `.sisyphus/plans/lazer-sigma-proofs.md`
**Scope**: `crates/pvthfhe-nizk/`
**Impact**: Replace hand-crafted `sigma.rs`, `bfv_sigma.rs`, `poulpy_sigma.rs` with LaZer-generated protocols.
**Effort**: ~16 hrs

### P2 — Greyhound: Lattice Polynomial Commitments
**File**: `.sisyphus/plans/greyhound-pcs.md`
**Scope**: `crates/pvthfhe-compressor/src/nova/`
**Impact**: Replace KZG Pedersen commitments in Nova accumulator with Greyhound PCS.
**Effort**: ~12 hrs

### P3 — LatticeFold+: Lattice-Native Folding
**File**: `.sisyphus/plans/latticefold-plus.md`
**Scope**: Entire compressor + pipeline
**Impact**: Replace nova-snark with LatticeFold+ folding scheme. Purely algebraic range proofs replace monomial_range.
**Effort**: ~24 hrs

## Execution Order

```
P1 (LaZer) → P2 (Greyhound) → P3 (LatticeFold+)
```

P1 is isolated to the NIZK layer. P2 builds on P1 (Greyhound uses auto-generated sigma proofs for opening). P3 depends on both — LatticeFold+ folding with Greyhound PCS and LaZer sigma inputs.

Each phase must:
1. Not break existing demo-e2e, per-node, aggregator
2. Pass all existing tests + new tests
3. Have no surrogates, stubs, or placeholders
4. Be committed atomically with clear commit messages
5. **No performance regressions** — benchmark before and after each phase at n=3,10,16,32. If slower, document the security/correctness improvement and the verified cost.

## Performance Regression Gates

Before and after each phase (P1, P2, P3), run and compare:
```
just demo-e2e n=10 t=4 seed=1  | grep "dkg_deal_ms\|compressor_prove_ms\|distributed_estimate_ms"
just per-node n=10 t=4 seed=1  | grep "timing"
just aggregator n=10 t=4 seed=1 | grep "timing"
```

Any slowdown > 10% must be:
- Documented with the security improvement it enables
- Reviewed and explicitly accepted before merge

## Success Criteria (All Sub-Plans)
- [ ] `cargo check --workspace` zero errors
- [x] All Justfile scripts work: `demo-e2e`, `per-node`, `aggregator`, `greco`, `compute`, `poulpy-all` (verified 2026-06-03)
- [ ] `cargo test --workspace` all tests pass (existing + new)
- [ ] No surrogates, stubs, placeholders remaining
- [ ] Zero `folding_schemes`, `sonobe`, `nova-snark`, `arecibo` in Cargo.toml
- [ ] Post-quantum: no EC or discrete-log assumptions in the proving stack

## Regression Check Decision (2026-06-03)

**Decision: Features remain opt-in.** Performance regression exceeds 10% threshold.

All six Justfile scripts (`demo-e2e`, `per-node`, `aggregator`, `greco`, `compute`, `poulpy-all`) verified ACCEPT with the current default features (no lattice features in defaults; `enable-lazer` already in `just demo-e2e`).

Key regressions with all lattice features (lazer+greyhound+latticefold) vs baseline at n=10, t=4:
- `dkg_deal_ms`: +17.5% (LaZer sigma proof overhead)
- `distributed_estimate_ms`: +27.1%
- `compressor_prove_ms`: +518% (LatticeFold+ algebraic range proofs vs Nova)
- `aggregator_total_ms`: +327%

Full breakdown in `.sisyphus/evidence/lattice-features-regression-2026-06-03.md`.

These features provide post-quantum security, transparent setup, formally-verified sigma protocols, and algebraic range proofs — at significant performance cost. Once implementations mature (FFI optimization, sumcheck integration), regression gap may narrow enough for default enablement.
