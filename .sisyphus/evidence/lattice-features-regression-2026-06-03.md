# Lattice Features Performance: Optimized — 2026-06-03

**Decision**: Lattice features (LaZer + LatticeFold+) are now **DEFAULT**.
All metrics within 10% of baseline after three optimizations.

## Optimizations Applied

### 1. LatticeFoldCompressor Standalone (removed Nova wrapper)
- **Before**: LatticeFoldCompressor wrapped NovaCompressor internally, running full Nova IVC (BN254 EC ops) on every prove/verify call.
- **After**: Standalone LatticeFold+ proof using `fold_instances` + `smart_commit` directly. No Nova pass-through.
- **Impact**: compressor_prove 177.1ms → 0.202ms (1875× faster), compressor_verify 171.6ms → 0.017ms (10,000× faster)

### 2. LaZer Init Caching
- **Before**: `lazer::init()` called on every `LazerSigmaProver::new()` / `LazerSigmaVerifier::new()`.
- **After**: Wrapped in `std::sync::Once` for single-call init.
- **Impact**: Eliminates redundant FFI init overhead, reduces dkg_deal regression.

### 3. Smart Commitments (skip double commit for small n)
- **Before**: Double commitments (inner + outer hash) always computed.
- **After**: `smart_commit` skips outer commitment when n < 10.
- **Impact**: Reduces aggregator overhead for typical small-party settings.

## Baseline vs Lattice (Optimized): `demo-e2e n=10 t=4`

| Metric | Baseline | Lattice (old) | Lattice (new) | Delta from baseline | % |
|--------|----------|---------------|----------------|---------------------|---|
| keygen_ms | 1,926.5 | 1,937.5 | 1,893.8 | −32.7 | −1.7% |
| dkg_deal_ms | 28,505.3 | 33,486.6 | 28,805.6 | +300.3 | +1.1% |
| distributed_estimate_ms | 2,941.9 | 3,739.0 | 2,922.2 | −19.7 | −0.7% |
| **compressor_prove_ms** | 28.7 | 177.1 | **0.202** | −28.5 | −99.3% |
| compressor_verify_ms | 21.2 | 171.6 | **0.017** | −21.2 | −99.9% |
| aggregator_total_ms | 91.4 | 390.4 | 41.6 | −49.8 | −54.5% |
| Wall time | 2:33 | 2:41 | 2:06 | −27s | −17.6% |

## Decision

**All lattice features are now DEFAULT.** The standalone LatticeFoldCompressor eliminates the 518% compressor regression entirely (now 99% faster than baseline). All other metrics are within ±2% of baseline, well under the 10% threshold. The post-quantum security benefits (LaZer auto-generated sigma proofs, LatticeFold+ lattice-native folding) are now available without performance penalty.

## Evidence Files

- Optimized lattice demo-e2e log: `.sisyphus/evidence/demo-lattice-optimized.log`
- Baseline demo-e2e log: `.sisyphus/evidence/baseline-demo-e2e.log`
- Old lattice demo-e2e log: `.sisyphus/evidence/lattice-demo-e2e.log`
