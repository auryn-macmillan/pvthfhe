# Plan: Comprehensive Surrogate Replacement — Track B Default

**Plan**: `surrogate-replacement-track-b`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-15
**Goal**: Replace ALL 15 surrogates in demo-e2e with real cryptography using real pipeline values. Make Track B / MicroNova the default track. Zero synthetic data, zero hardcoded constants in cryptographic paths.

---

## Layer 0: Foundation — R1CS Cyclo Ring Equation (P2-M6)

**Prerequisite for all layers below.** Converts the native `CycloVerifierCCS` to R1CS constraints.

| Task | Files | Effort |
|------|-------|--------|
| L0.1 | Implement `RingElementVar<F>` — FpVar-based ring arithmetic (add, sub, negate) over N=256 | `sonobe/ring_element_var.rs` (extend existing) | 2 days |
| L0.2 | Implement `verify_ring_equation_r1cs()` in `CycloFoldStepCircuit::generate_step_constraints` — ternary c means zero multiplications (only addition and negation across 256 coefficients) | `sonobe/mod.rs:177-196`, `sonobe/cyclo_verifier.rs:33-81` | 2 days |
| L0.3 | 4 RED tests: honest R1CS passes, wrong witness fails, c=-1/0/1 cases | `tests/cyclo_r1cs_verifier.rs` | 1 day |

## Layer 1: Compressor — Real Lattice Folding in Nova

| Task | Files | Effort |
|------|-------|--------|
| L1.1 | Inject `RingElementVar`-based external inputs into `CycloFoldStepCircuit` state — state grows from 3 Fr to 3+N×2 Fr (3 + 512 = 515) or use a polynomial-element encoding | `sonobe/mod.rs:177-210` | 3 days |
| L1.2 | Replace 1×1 identity CCS matrix with real Cyclo verifier matrix derived from `CycloVerifierCCS::to_ccs_matrix()` — encode ring equation as actual CCS constraints | `full_pipeline.rs:779-794` | 2 days |
| L1.3 | Replace zero CCS witness with real witness from `RealNizkAdapter` proof secret-share/error values | `full_pipeline.rs:828-840` | 1 day |
| L1.4 | Replace deterministic ChaCha20Rng with `OsRng` for Nova prove_step (or keep ChaCha20 seeded from per-session nonce — document choice) | `sonobe/mod.rs:376,550,682` | 0.5 day |
| L1.5 | 6 RED tests: R1CS ring equation passes with real data, rejects tampered witness, CCS satisfiability non-trivial, OsRng proof differs per run | Tests | 2 days |

## Layer 2: MicroNova Circuits — Real Heterogeneous Verification

| Task | Files | Effort |
|------|-------|--------|
| L2.1 | Replace placeholder leaf circuit (circuit 0) with real `verify_ring_equation_r1cs()` — verifies `c·z_s + z_e - t - c·d ≡ 0` with ∞-norm enforcement from norm.rs | `latticefold_circuit_family.rs:104-113` | 2 days |
| L2.2 | Replace placeholder internal circuit (circuit 1) with real fold verification — checks that two child accumulators correctly fold to parent under Cyclo CCS relation | `latticefold_circuit_family.rs:119-124` | 2 days |
| L2.3 | Fix per-variant verifier key — add commitment to circuit variant index per step, checked by verifier (MicroNova paper approach) | `micronova/compressor.rs:108-127`, `heterogeneous.rs` | 3 days |
| L2.4 | 5 RED tests: leaf rejects wrong ring equation, internal rejects bad fold, variant miss detected, tree roundtrip depth=3 | Tests | 2 days |

## Layer 3: C7 + NIZK Data — Real Pipeline Values

| Task | Files | Effort |
|------|-------|--------|
| L3.1 | Replace `ext.2 = Fr::zero()` in `run_c7_verification` with real Merkle root from `C7WitnessSet::new()` — enables share-correctness binding | `full_pipeline.rs:1185` | 1 day |
| L3.2 | Build real Merkle trees from decryption share polynomials (already in `C7WitnessSet::new()`) and wire into C7 circuit external inputs | `full_pipeline.rs:1140-1199` | 1 day |
| L3.3 | Replace approximated z_s/z_e in norm enforcement with actual masked values from `NizkWitness` + `RealNizkAdapter` sigma proof — extract `z_s = y_s + c·s` and `z_e = y_e + c·e` from proof payload | `full_pipeline.rs:366-373` | 2 days |
| L3.4 | Replace synthetic error polynomial (`derive_demo_error_poly`) with actual BFV encryption error from `EncryptionWitness` produced by `partial_decrypt_with_witness` | `demo_nizk.rs:86-98` | 1 day |
| L3.5 | 4 RED tests: C7 Merkle roundtrip with real data, norm enforcement rejects tampered z_s/z_e, error polynomial matches backend EncryptionWitness | Tests | 2 days |

## Layer 4: Track B / MicroNova Default

| Task | Files | Effort |
|------|-------|--------|
| L4.1 | Change Track default from `B` to `B` (already default) — verify `PVTHFHE_TRACK=A` still works for Track A fallback | `full_pipeline.rs` | 0.5 day |
| L4.2 | Enable MicroNova compressor by default (replace `PVTHFHE_COMPRESSOR=micronova` opt-in with hard default) — wire `HeterogeneousStepCircuit<LatticeFoldTreeCircuitFamily>` as active compressor | `full_pipeline.rs:452-458`, `compressor_glue.rs:61` | 1 day |
| L4.3 | Document Track B defaults in ARCHITECTURE.md, Justfile, paper | Docs | 0.5 day |
| L4.4 | 2 regression tests: Track A fallback produces identical output, Track B default ACCEPT | Tests | 1 day |

## Layer 5: Remaining Surrogates

| Task | Files | Effort |
|------|-------|--------|
| L5.1 | Replace simulator `encrypted_shares: vec![0x11, 0x22]` with real BFV ciphertexts from backend (reuse `lattice_pvss_bfv_adapter` encrypt path) | `simulator.rs:323` | 2 days |
| L5.2 | Replace simulator `mock_cbor_hash_of_everything` with real transcript hash (SHA-256 over serialized Round1Message set) | `simulator.rs:288` | 0.5 day |
| L5.3 | Replace simulator `commitment: hash_bytes(&party_id)` with real homomorphic commitment | `simulator.rs:174` | 1 day |
| L5.4 | Wire `AjtaiMatrix` from aggregator for Track B (replaces `pvthfhe-cyclo::ajtai`) | `full_pipeline.rs:847-858` | 2 days |
| L5.5 | Replace M1 placeholder `FoldVerifierStepCircuit` with real fold verification using Cyclo CCS R1CS encoding | `fold_verifier_circuit.rs:33-36` | 2 days |
| L5.6 | Fix `compressor_glue.rs:191` hardcoded fold count to actual depth | `compressor_glue.rs:191` | 0.5 day |
| L5.7 | 5 RED tests | Tests | 2 days |

---

## Acceptance Criteria

- [ ] ALL 15 surrogates replaced with real cryptography or real pipeline values
- [ ] `just demo-e2e` defaults to Track B / MicroNova
- [ ] `PVTHFHE_TRACK=A just demo-e2e` runs Track A as fallback (identical output)
- [ ] Demo ACCEPT — both tracks
- [ ] No hardcoded zeros, ones, or synthetic arrays in cryptographic paths
- [ ] All existing tests pass
- [ ] 24 new RED tests pass (L0-L5)
- [ ] ARCHITECTURE.md, SECURITY.md, paper updated

## Execution Order

Layer 0 (foundation) → Layer 1 (compressor) → Layer 2 (MicroNova) → Layer 3 (C7/NIZK) → Layer 4 (default) → Layer 5 (remaining)

Layers 0+1 can overlap. Layer 2 requires Layer 1. Layer 3 can start after Layer 1. Layer 4 requires Layers 1-3. Layer 5 can run in parallel with Layer 4.

## Estimated Total Effort

~6-8 weeks. Layer 0-1: 2 weeks. Layer 2: 1.5 weeks. Layer 3: 1 week. Layer 4: 0.5 weeks. Layer 5: 1.5 weeks.
