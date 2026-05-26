
## G.12 Phase 2b: Schnorr EC Equality — Implementation Notes

### Discovery: Full in-circuit EC arithmetic infeasible

- `ark-bn254` constraints module (`GVar`) uses `Fq` (base field) as constraint field
- Sonobe Nova circuit runs over `Fr` (scalar field)
- Non-native EC arithmetic requires `EmulatedFpVar<Fq, Fr>` with full point addition + scalar multiplication
- Sonobe's `NonNativeAffineVar` is explicitly "not intended to perform operations" — only for hashing
- Decision: defer EC equality to on-chain Solidity verifier; in-circuit check ensures challenge derivation binds full point coordinates

### What was implemented

1. `ExternalInputs6`: (sig_r_x, sig_r_y, sig_s, pk_x, pk_y, domain) in `mod.rs`
2. `ExternalInputs6Var` with `AllocVar` impl following existing pattern
3. `encode_hex6` / `decode_hex6` for 192-byte encoding
4. Challenge derivation now uses all 6 fields: Poseidon(domain, R.x, R.y, PK.x, PK.y, share_hash)
5. ShareVerificationWitness extended with `sig_r_y` and `pk_y`
6. Pipeline: y-coordinates extracted from G1Affine points and propagated through PipelineReport
7. Scaffolding comment documents deferred EC equality verification

### Files changed
- `crates/pvthfhe-compressor/Cargo.toml` — added `ark-ec = "0.5"`
- `crates/pvthfhe-compressor/src/sonobe/mod.rs` — ExternalInputs6, encode/decode functions
- `crates/pvthfhe-compressor/src/sonobe/share_verification_circuit.rs` — ExternalInputs6, y-coords in challenge
- `crates/pvthfhe-compressor/src/witness.rs` — sig_r_y, pk_y fields
- `crates/pvthfhe-cli/src/full_pipeline.rs` — y-coordinate extraction, PipelineReport fields
