# P1 — LaZer: Auto-Generated Sigma Proofs

**Status**: PLAN
**Date**: 2026-05-31
**Parent**: `.sisyphus/plans/lattice-meta-plan.md`

## Goal

Replace hand-crafted sigma protocols (`sigma.rs`, `bfv_sigma.rs`, `poulpy_sigma.rs`, `bootstrap_sigma.rs`) with auto-generated protocols from the LaZer library. Users specify lattice relations + norm bounds, and LaZer produces the proof system automatically.

## Why LaZer

- Eliminates protocol-level bugs (weak Fiat-Shamir, missing witness bounds, incorrect challenge derivation)
- Auto-generates parameter-optimized proofs (LaBRADOR succinct or linear-size as appropriate)
- Supports RLWE, LWE, BFV encryption, CKKS encoding, and bootstrapping relations natively
- IBM-maintained C library with Python API — could be wrapped as a Rust FFI crate

## Integration Architecture

```
pvthfhe-nizk/
├── lazer_bridge.rs          ← Rust FFI to LaZer C library
├── sigma.rs                 ← Kept as fallback, gated behind #[cfg(not(feature = "lazer"))]
├── bfv_sigma.rs             ← Replaced by LaZer-generated BFV encryption proof
├── poulpy_sigma.rs          ← Replaced by LaZer-generated CKKS/TFHE proofs
├── bootstrap_sigma.rs       ← Replaced by LaZer-generated bootstrapping proof
└── lazer_specs/             ← Spec files: BFV.toml, CKKS.toml, TFHE.toml, Bootstrap.toml
```

## Phases

### Phase 1 — LaZer FFI Bridge (~4 hrs)
- [ ] Create `crates/pvthfhe-lazer/` crate wrapping LaZer C library via FFI
- [ ] Define `LazerSpec` struct: `{ relation: String, norm_bounds: HashMap<String, u64>, proof_type: ProofType }`
- [ ] Implement `lazer_prove(spec, witness) -> Vec<u8>` and `lazer_verify(spec, proof) -> Result<(), Error>`
- [ ] Add `enable-lazer` feature flag
- [ ] Verify: `cargo build --features enable-lazer` compiles with LaZer C library

### Phase 2 — Port Sigma Protocols to LaZer (~6 hrs)
- [ ] Create `lazer_specs/bfv_encryption.toml` — BFV encryption relation spec
- [ ] Create `lazer_specs/ckks_encryption.toml` — CKKS key correctness spec
- [ ] Create `lazer_specs/tfhe_bootstrap.toml` — TFHE bootstrapping spec
- [ ] Implement `LazerSigmaProver` implementing `SigmaProver` trait
- [ ] Implement `LazerSigmaVerifier` implementing `SigmaVerifier` trait
- [ ] Wire into `full_pipeline.rs` behind `#[cfg(feature = "enable-lazer")]`
- [ ] Verify: all existing sigma tests pass with LaZer backend

### Phase 3 — Integration Testing (~4 hrs)
- [ ] Test BFV DKG ceremony with LaZer sigma (n=3, t=1)
- [ ] Test CKKS DKG ceremony with LaZer sigma (n=3, t=1)
- [ ] Test TFHE bootstrapping with LaZer sigma (n=3, t=1)
- [ ] Test scheme-switch with LaZer sigma (poulpy-all)
- [ ] Benchmark: LaZer prove/verify time vs hand-crafted sigma

### Phase 4 — Cleanup + Hardening (~2 hrs)
- [ ] Remove `#[cfg(not(feature = "lazer"))]` gating — LaZer becomes the default
- [ ] Delete legacy sigma code (or gate behind `legacy-sigma` feature)
- [ ] Update ARCHITECTURE.md, SECURITY.md with LaZer integration details
- [ ] Verify all Justfile scripts work

## Success Criteria
- [ ] `cargo check --features enable-lazer` zero errors
- [ ] All sigma tests pass (existing + new LaZer tests)
- [ ] `just demo-e2e` ACCEPT with LaZer backend
- [ ] `just poulpy-all` ACCEPT with LaZer backend
- [ ] LaZer proof sizes documented and compared against hand-crafted
