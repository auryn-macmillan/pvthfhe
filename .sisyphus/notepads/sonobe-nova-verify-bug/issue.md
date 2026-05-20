## Nova incoming `check_relation` fails for C7DecryptAggregationCircuit

### Environment
- `folding-schemes` at rev `63f2930d`
- `C7DecryptAggregationCircuit` (state_len=3, ExternalInputs5, N_COEFFS=8192)
- C7_STEP_DATA thread-local provides per-step coefficient data
- Coefficients allocated via `FpVar::new_witness` (not `FpVar::constant`)

### Symptom
`SonobeNova::verify()` returns `NotSatisfied` at the incoming instance `check_relation`. Specifically:

```
vp.r1cs.check_relation(&w_i, &u_i) → NotSatisfied
```

All earlier checks pass (`check_incoming`, hash checks, dimension checks).

### Diagnosis
- 695,628 total constraints, **2 fail** (indices 654729, 654730, consecutive)
- Both failing constraints have pattern: `Bz = 1`, `uCz = 0`, meaning the constraint is `Az = 0`
- `Az` evaluates to a large non-zero field element at both indices
- Witness length = 702,934, R1CS columns = 702,937 → dimensions match (702,937 = 1 + 2 + 702,934)
- C7_STEP_DATA is set BEFORE `SonobeCompressor::new` (so R1CS is generated with actual coefficient data, not zeros)
- The prover (`prove_step`) succeeds without error

### Likely cause
The constraint synthesis during `SynthesisMode::Setup` (init) produces different variable ordering than `SynthesisMode::Prove` (prove_step), causing the witness values to be assigned to wrong variable indices in these 2 constraints. This may be specific to large-witness circuits (702K variables) where the Arkworks constraint system optimizer behaves differently between modes.

### Affected code
- `crates/pvthfhe-compressor/src/sonobe/c7_circuit.rs` — C7DecryptAggregationCircuit
- `folding-schemes/src/folding/nova/mod.rs` — `Nova::verify`, incoming instance check
- `crates/pvthfhe-compressor/src/sonobe/mod.rs` — `verify_steps_c7`

### Workaround
Using MicroNova tree folding (`CompressionTree::build`) with `LatticeFoldTreeCircuitFamily` avoids the issue (the tree uses a different code path). The flat Nova path has this verification bug.

### Reproduction
```bash
PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run --release -p pvthfhe-cli \
  --features "sonobe-compressor,demo-seeded-rng,pipeline-extra-checks" \
  -- demo --n 16 --threshold 7 --seed 1
```
With flat Nova as primary C7 path:
- Prove steps 0-3 succeed
- `Nova::verify` fails with `NotSatisfied`
