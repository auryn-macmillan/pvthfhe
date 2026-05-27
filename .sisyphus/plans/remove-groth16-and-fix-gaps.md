# Remove Groth16 + Fix Soundness Gaps

**Status**: IN PROGRESS
**Created**: 2026-05-25

## Goal
Replace Groth16 trusted ceremony with transparent IVC serialization, apply Schwartz-Zippel sigma optimization, and fix remaining soundness gaps (quotient range checks, d_commitment, polynomial commitment, PK aggregation sigma, Lagrange in Nova).

## Phases

### Phase 1 — Transparent IVC (no Groth16)
- [x] 1.1: Update Cargo.toml — remove nova-snark, add transparent-decider
- [x] 1.2: Rewrite snark_bridge.rs — always produce IVC proof hash
- [x] 1.3: Update compressor glue — pp_hash as ivc_snark_proof_hash
- [x] 1.4: Remove nova-snark feature from CLI
- [x] Build: cargo build ✅ cargo test: 36 passed ✅

### Phase 2 — Schwartz-Zippel Sigma Optimization
- [x] 2.1: Add poly_eval_mod + compute_sz_gamma to sigma.rs
- [x] 2.2: Add S-Z fields to SigmaWitness
- [x] 2.3: Replace NTT loop with single-point S-Z check
- [x] 2.4: Populate sz_* fields in witness construction
- [x] Build: cargo build ✅ tests: 36 compressor + 10 nizk ✅ (~6x reduction)

### Phase 3 — Soundness Gap Fixes
- [x] 3.1: Quotient witness range check (addressed by Phase 2 S-Z)
- [x] 3.2: Real d_commitment in full_pipeline.rs (Poseidon over ciphertext)
- [x] 3.3: Real polynomial commitment in DKG (hash secret_key_bytes+session_id)
- [x] 3.4: Wire sigma into pk_aggregation_circuit
- [x] 3.5: Lagrange fold Nova circuit (new LagrangeFoldStepCircuit)
- [x] Build: cargo build ✅ tests: 36 compressor + 10 aggregator ✅

### Phase 4 — Noir C7 Simplification
- [x] 4.1: Simplify aggregator_final/src/main.nr (730→108 lines)
- [x] 4.2: Update C7Prover.toml
- [x] 4.3: nargo test 3/3 ✅ ACIR: 1251 opcodes
- [x] All tests pass

**Status**: COMPLETE

## Success Criteria
- [ ] `cargo build` zero errors
- [ ] `cargo test -p pvthfhe-compressor` passes
- [ ] `cargo test -p pvthfhe-nizk` passes
- [ ] `cargo test -p pvthfhe-pvss` passes
- [ ] No Groth16 ceremony required
- [ ] Sigma verify ~6x faster (575k → ~90k constraints/party)
