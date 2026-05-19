# G.12 Phase 2 — Nova-Folded Schnorr Verification in R1CS

**Status**: DESIGN COMPLETE (q1=a, q2=folding, confirmed)
**Depends on**: Phase 1 (native Schnorr — COMPLETE)
**Next**: Implementation via task delegation
**Estimate**: ~3 days

## Architecture

```
Party i: (pk_i, sig_r_i, sig_s_i, d_i)
    ↓
ShareVerificationStepCircuit (FCircuit)
    └─ 3K constraints: schnorr_verify(pk_i, sig_i, hash(d_i))
    └─ 7K constraints: Poseidon sponge hash of share coefficients
    └─ State: [accumulated_share_hash, step_count]
    ↓
Nova fold n steps → compressed proof (SonobeCompressor)
    ↓
aggregator_final receives: combined_share_hash + proof_hash
```

## Tasks

### Task 5: Create ShareVerificationStepCircuit (FCircuit)
- [x] File: `crates/pvthfhe-compressor/src/sonobe/share_verification_circuit.rs`
- [x] FCircuit trait impl with ExternalInputs4: (sig_r, sig_s, pk, share_points)
- [x] State: [accumulated_hash, step_count]
- [x] In-circuit: Schnorr verify + Poseidon sponge share hash
- [x] Test: single step produces correct hash

### Task 6: Native-side Schnorr in-circuit verification  
- [ ] `poseidon_gadget.rs` or new file: implement Schnorr `schnorr_verify_in_circuit`
- [ ] Scalar multiplication: r·G in R1CS using arkworks' `CurveVar`
- [ ] Poseidon challenge: reuse existing `PoseidonSpongeVar`
- [ ] Constraint count verification

### Task 7: Witness generation for folding
- [ ] `witness.rs`: `ShareVerificationWitness` struct with pk, sig_r, sig_s, share coeffs
- [ ] `ShareVerificationWitnessSet`: collection of per-party witnesses
- [ ] Witness-to-ExternalInputs conversion
- [ ] `verify_commitments` for witness integrity

### Task 8: SonobeCompressor prove/verify integration
- [ ] `mod.rs`: add `ShareVerificationStepCircuit` to `SonobeCompressor` generic impls
- [ ] `prove_steps` support for ShareVerification step arrays
- [ ] `verify` path accepts compressed proof
- [ ] Track compatibility: `prove_steps_share_verify` function

### Task 9: Pipeline wiring (full_pipeline.rs)
- [ ] After Schnorr signing (Phase 1.3), build `ShareVerificationWitnessSet`
- [ ] Call `SonobeCompressor::prove_steps_share_verify` to fold n steps
- [ ] Extract `combined_share_hash` from final accumulator state
- [ ] Pass to `aggregator_final` via Prover.toml (already wired in Task 4)

### Task 10: aggregator_final Noir circuit update
- [ ] Accept `combined_share_hash` as public input (replaces per-share in-circuit hashing)
- [ ] Accept `share_verification_proof_hash` as additional public input
- [ ] Verify `combined_share_hash` matches `d_commitment` binding
- [ ] Remove duplicated per-share hashing (now done in folding circuit)

### Task 11: End-to-end test
- [ ] `demo-e2e` with n=4, verify full pipeline ACCEPT
- [ ] Verify Schnorr reject path: wrong signature → fold detect → pipeline reject
- [ ] Verify share count mismatch detected

## Constraint Budget

| Component | Per step | n=16 | n=64 | n=128 |
|-----------|----------|------|------|-------|
| Schnorr verify | ~3K | 48K | 192K | 384K |
| Share Poseidon | ~7K | 112K | 448K | 896K |
| Step total | ~10K | 160K | 640K | 1.28M |

All within 2.5M WASM limit at n=128. Folding amortizes: Nova proof is ~27K constraints regardless of n.
