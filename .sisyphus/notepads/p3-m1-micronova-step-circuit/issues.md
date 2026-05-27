# P3-M1 Issues

## Known limitations
- The fold verifier currently uses hash-accumulation placeholders instead of real CCS R1CS constraints.
- Full Cyclo CCS encoding (including ∞-norm and ring-equation checks) deferred to P3-M2.
- MicroNova heterogeneous circuit support not implemented (deferred to M2).

## NovaCompressor 3-element state assumption
- The compressor's prove/prove_steps/verify methods assume state_len >= 3 due to triple encoding.
- This could be fixed in a future PR to support arbitrary state widths.
