# Problems: C5 Aggregate Public-Key Formation Proof

## 2026-06-04: Plan creation

No unresolved problems yet. Plan is in PLAN status.

### Anticipated challenges

1. **BFV key arithmetic**: `aggregate_keygen` may not be a simple ring addition. Need to verify the FHE backends (fhe.rs, Poulpy) compute aggregation identically and deterministically.

2. **PoP protocol for BFV keys**: Standard Schnorr PoP assumes discrete log in a cyclic group. BFV keys are RLWE samples (a polynomial pair). Need to design an appropriate sigma protocol.

3. **Nova IVC integration**: The current `full_pipeline.rs` already has a C5 section (lines 1149-1181) using `PkAggregationStepCircuit`. This may need to be replaced or augmented with real proof verification.
