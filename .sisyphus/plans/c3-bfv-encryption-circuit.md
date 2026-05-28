# C3 — BFV Encryption Relation Circuit

**Plan**: `c3-bfv-encryption-circuit`
**Status**: PLAN
**Created**: 2026-05-28
**Parent**: `.sisyphus/plans/resolve-status-gaps.md`
**Depends on**: CycloFoldStepCircuit (stable), BFV encryption witness pipeline (existing)
**Goal**: Port the BFV encryption relation (`ct = Encrypt(pk, m; r)`) into a proper Nova `StepCircuit`, thread it through the CycloFoldStepCircuit pipeline so the verifier cryptographically verifies ciphertext well-formedness in-circuit rather than trusting a native Rust hash.

---

## Current State

The codebase has partial BFV encryption in-circuit support:

| Component | File | Status |
|-----------|------|--------|
| `bfv_encryption_verify_step()` | `bfv_encryption_circuit.rs:78-202` | ✅ Helper function — S-Z batched BFV relation check across L=3 moduli |
| `bfv_verify_step_bp()` | `nova_gadgets.rs:535-747` | ✅ Bellpepper gadget — same logic for arecibo backend |
| `BFV_ENCRYPTION_DATA` thread-local | `bfv_encryption_circuit.rs:56-68` | ✅ Data pipeline — 28 Fr elements per step |
| CycloFoldStepCircuit `bfv_ok` field | `cyclo_fold_circuit.rs:63` | ✅ Field exists but is **prover-trusted** (not constrained) |
| CycloFoldStepCircuit `bfv_count` state | `cyclo_fold_circuit.rs:17` | ✅ State index 6 — but only accumulates prover-claimed `bfv_ok` |
| BFV encryption witness generation | `fhers.rs:911-984` | ✅ `encrypt_with_witness()` produces `EncryptionWitness` with u, e0, e1 |
| Full `StepCircuit` for BFV | — | ❌ **Nothing implements `StepCircuit` for BFV encryption** |

**The gap**: The `bfv_encryption_verify_step` function exists and works in R1CS, but the CycloFoldStepCircuit's use of it is **pass-through counting only** — the verifier receives `bfv_ok = Fr::one()` as a prover claim. The circuit does not actually enforce the BFV relation as R1CS constraints in the active nova-snark path (commented out at line 27-28 of cyclo_fold_circuit.rs: "Sigma NIZK, ring equation, and BFV encryption verification gadgets are not yet ported to bellpepper").

From `cyclo_fold_circuit.rs:91-127`, the `synthesize` method allocates `bfv_ok` as a witness (`AllocatedNum::alloc(cs, || Ok(self.bfv_ok))`) without any constraint connecting it to the `BFV_ENCRYPTION_DATA`. The bfv_count is just a trust accumulator.

The legacy-nova path (`mod.rs:1022-1157`) DOES call `bfv_encryption_verify_step(cs, _i)` in its `generate_step_constraints` at line 1092-1093, but this is gated behind `legacy-nova` which is not the default backend.

---

## Success Criteria

- [ ] `BfvEncryptionStepCircuit` created, implementing `nova_snark::traits::circuit::StepCircuit<NovaScalar>` (arity=1)
- [ ] RNS-modular polynomial arithmetic (add, mul, mod-q) implemented in bellpepper constraint system
- [ ] Schwartz-Zippel batch verification across L=3 CRT moduli wired in constraints
- [ ] Norm bounds enforced: `|u| ≤ B_U`, `|e0| ≤ B_E`, `|e1| ≤ B_E`, `|m| ≤ B_M`
- [ ] `bfv_verify_step_bp` wire into `CycloFoldStepCircuit::synthesize` — removes prover-trusted `bfv_ok`
- [ ] CycloFoldStepCircuit state[6] (`bfv_count`) increments only when BFV constraints SATISFY
- [ ] Adversarial test: tampered `pk0` causes prove_step failure (R1CS unsatisfiable)
- [ ] `just demo-e2e` ACCEPTs with BFV encryption verified in-circuit
- [ ] `cargo test -p pvthfhe-compressor` — all existing tests pass (nova_roundtrip, bfv_encryption_adversarial, step_circuit_fold_relation)

---

## Task Breakdown

### Task 1: Create `BfvEncryptionStepCircuit` as a full StepCircuit

**Files**:
- `crates/pvthfhe-compressor/src/nova/bfv_encryption_circuit.rs` (extend, lines 1–237)
- `crates/pvthfhe-compressor/src/nova/mod.rs` (add module re-export)

- [ ] 1.1 Define `BfvEncryptionStepCircuit` struct implementing the nova-snark `StepCircuit` trait:
  ```rust
  #[derive(Clone, Debug, Default)]
  pub struct BfvEncryptionStepCircuit<F> {
      _phantom: PhantomData<F>,
      /// Per-step BFV relation result: Fr::one() if satisfied, Fr::zero() otherwise.
      /// Properly constrained via generate_step_constraints — not prover-trusted.
      pub bfv_satisfied: F,
      /// Accumulated BFV verification count.
      pub bfv_count: usize,
  }
  ```

- [ ] 1.2 Implement `nova_snark::traits::circuit::StepCircuit<NovaScalar>`:
  ```rust
  impl nova_snark::traits::circuit::StepCircuit<NovaScalar>
      for BfvEncryptionStepCircuit<NovaScalar>
  {
      fn arity(&self) -> usize { 2 }  // state: (bfv_count, bfv_ok)
      fn synthesize<CS: ConstraintSystem<NovaScalar>>(
          &self, cs: &mut CS,
          z: &[AllocatedNum<NovaScalar>],
      ) -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
          // 1. Read step counter from thread-local
          let step = CYCLO_FOLD_STEP_COUNTER.with(|c| c.get());
          
          // 2. Call existing bfv_verify_step_bp (from nova_gadgets.rs)
          //    with proper namespace isolation
          let bfv_ok = nova_gadgets::bfv_verify_step_bp(
              cs.namespace(|| "bfv_verify"), step,
          )?;
          
          // 3. State transition: count += bfv_ok
          let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(NovaScalar::one()))?;
          let new_count = z[0].add(cs.namespace(|| "count_inc"), &bfv_ok)?;
          
          Ok(vec![new_count, bfv_ok])
      }
  }
  ```

- [ ] 1.3 Implement crate-local `StepCircuit` trait (from `lib.rs:137`):
  ```rust
  impl<F> StepCircuit for BfvEncryptionStepCircuit<F> {
      fn descriptor(&self) -> StepCircuitDescriptor {
          StepCircuitDescriptor { width: 2 }
      }
      fn circuit_hash(&self) -> [u8; 32] {
          Keccak256::digest(b"pvthfhe/bfv-encryption/v1").into()
      }
  }
  ```

- [ ] 1.4 Add to `mod.rs` exports:
  ```rust
  pub use bfv_encryption_circuit::BfvEncryptionStepCircuit;
  ```

**Effort**: 1 day (medium — wiring existing `bfv_verify_step_bp` into a StepCircuit wrapper)
**Success**: `BfvEncryptionStepCircuit` compiles; `cargo test -p pvthfhe-compressor -- lib` finds the circuit

---

### Task 2: Implement RNS-modular polynomial arithmetic in bellpepper

**Files**:
- `crates/pvthfhe-compressor/src/nova/bfv_encryption_circuit.rs` (lines 70–202, existing)
- `crates/pvthfhe-compressor/src/nova/ring_element_var.rs` (extend if needed)

**Background**: The existing `bfv_encryption_verify_step` (arkworks R1CS path) at `bfv_encryption_circuit.rs:78-202` handles per-coefficient arithmetic. The bellpepper path at `nova_gadgets.rs:535-747` duplicates this. Both already implement:

- **S-Z batched verification** across L=3 moduli with γ-l challenge powers (lines 165–186)
- **Per-modulus modular reduction** with quotient witnesses q_l (lines 163, 175)
- **Norm bounds** via 31-bit bit-decomposition (lines 204–237)

What needs **enhancement**:
- [ ] 2.1 Replace fixed 31-bit decomposition with adaptive bit count using `symphony-t3` monomial range checks:
  ```rust
  #[cfg(feature = "symphony-t3")]
  use crate::nova::monomial_range::adaptive_norm_range_check;
  ```
  This reduces per-coefficient constraints from 31 to 18 bits for B_U=10,000 and B_E=10,000.

- [ ] 2.2 Add in-circuit quotient witness verification — currently the quotient witness `quot0[l], quot1[l]` is allocated as an unconstrained witness. Add:
  ```rust
  // Enforce that quotient is correct:
  // (pk0[l]·u + e0 + Δ[l]·m - ct0[l]) mod q[l] == 0
  // ⇔ pk0[l]·u + e0 + Δ[l]·m - ct0[l] == q[l]·quot0[l]
  // Already done via the S-Z batch check (lines 165-176). Verified.
  ```

- [ ] 2.3 Add **RNS modular arithmetic helpers** to `bfv_encryption_circuit.rs` for potential future RNS-native BFV operations (if scaling to full polynomial multiplication becomes needed):
  ```rust
  /// RNS-modular multiplication with quotient witness.
  /// Enforces: a * b = q * quotient + result, with 0 ≤ result < q.
  fn rns_mul_constrain<F: PrimeField>(
      cs: ConstraintSystemRef<F>,
      a: &FpVar<F>, b: &FpVar<F>,
      q: u64, quotient: &FpVar<F>,
  ) -> Result<FpVar<F>, SynthesisError> {
      let product = a * b;
      let q_var = FpVar::constant(F::from(q));
      let modded = product - q_var * quotient;
      // Range-check modded is < q (done by caller)
      Ok(modded)
  }
  ```

**Note on polynomial arithmetic**: The current per-coefficient approach (treating each RNS token as a scalar in Fr) works because:
- BFV moduli q[l] ~ 58 bits << Fr(~254 bits) — no wrap-around
- Each coefficient of ct0, ct1, pk0, pk1 is a single field element
- The S-Z batch handles the full 8192-coefficient polynomial via challenge folding

Full NTT-domain polynomial multiplication in-circuit would require ~N·log N constraints — not needed for the coefficient-level verification approach.

**Effort**: 1 day (enhance existing implementation)
**Success**: RNS modular arithmetic constrained; quotient witnesses properly verified.

---

### Task 3: Wire BFV verification into CycloFoldStepCircuit

**Files**:
- `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs` (lines 77–131)
- `crates/pvthfhe-compressor/src/nova/mod.rs` (lines 104–163)
- `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` (lines 535–747)

**Current state** (cyclo_fold_circuit.rs:91-92):
```rust
let bfv_ok =
    AllocatedNum::alloc(cs.namespace(|| "bfv_ok"), || Ok(self.bfv_ok))?;
// NOT constrained — just witness allocation!
```

**Target**: Replace witness allocation with actual constraint verification:

- [ ] 3.1 In nova-snark `StepCircuit` impl (mod.rs:127):
  ```rust
  // OLD (line 127): let bfv_ok = nova_gadgets::bfv_verify_step_bp(cs, step)?;
  // This already exists and is called! But it's in the nova-snark impl, not arecibo.
  // Verify: is nova-gadgets::bfv_verify_step_bp actually constraining or just counting?
  ```
  
  Check `nova_gadgets.rs:535-747` — the `bfv_verify_step_bp` function **does** enforce constraints (S-Z batch check + norm bounds). It returns the verification result. So the nova-snark path (lines 104-163) **already** constrains BFV verification. But the arecibo path (cyclo_fold_circuit.rs:85-131) does **not** — it just allocates the witness field without constraints.

- [ ] 3.2 Wire BFV constraints into arecibo `CycloFoldStepCircuit::synthesize` (cyclo_fold_circuit.rs:85-131):
  ```rust
  fn synthesize<CS: ConstraintSystem<F>>(
      &self, cs: &mut CS,
      z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
      let step = CYCLO_FOLD_STEP_COUNTER.with(|c| c.get());
      
      // Existing sigma and ring verification (lines 125-126):
      let sigma_ok = nova_gadgets::sigma_verify_step_bp(cs, step)?;
      let ring_ok = nova_gadgets::ring_verify_step_bp(cs, step)?;
      
      // NEW: BFV encryption verification (replaces prover-trusted bfv_ok field):
      let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::from(1u64)))?;
      let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(F::from(0u64)))?;
      
      // Call the existing BFV verification gadget  
      let bfv_ok = nova_gadgets::bfv_verify_step_bp(
          cs.namespace(|| "bfv_encryption"),
          step,
      )?;
      
      // If BFV_DATA is empty, bfv_verify_step_bp returns zero
      // (existing behavior: returns zero when no data, line 540-544 of nova_gadgets.rs)
      
      // ... rest of state transitions use bfv_ok (not self.bfv_ok)
  }
  ```

- [ ] 3.3 Remove or deprecate the `pub bfv_ok: F` struct field in CycloFoldStepCircuit (cyclo_fold_circuit.rs:63) — it's now replaced by in-circuit verification. Add a comment:
  ```rust
  /// DEPRECATED: bfv_ok was previously set by the caller before prove_step.
  /// Now derived in-circuit via bfv_verify_step_bp. This field is kept for
  /// backward compatibility but should always be set to Fr::one().
  /// TODO(c3-gate): Remove this field once all callers use the in-circuit path.
  pub bfv_ok: F,
  ```

**Effort**: 1 day (wiring existing gadget into the arecibo synthesize path)
**Risk**: The `bfv_verify_step_bp` function in `nova_gadgets.rs` was written for the nova-snark backend. It uses `AllocatedNum<NovaScalar>` which is the same type as `AllocatedNum<F>` (since `NovaScalar = Fr = F`). Need to verify type compatibility in the arecibo `synthesize<CS>` where `F: bp_ff::PrimeField`.
**Success**: CycloFoldStepCircuit's `bfv_count` only increments when BFV constraints are actually satisfied.

---

### Task 4: Thread BFV ciphertext commitment through the pipeline

**Files**:
- `crates/pvthfhe-cli/src/full_pipeline.rs` — BFV witness data generation
- `crates/pvthfhe-compressor/src/nova/bfv_encryption_circuit.rs` — thread-local `BFV_ENCRYPTION_DATA`
- `crates/pvthfhe-pvss/src/encrypt.rs` — `LatticePvssBfvAdapter::deal()`

**Current flow**:
1. `LatticePvssBfvAdapter::deal()` (encrypt.rs:176-270) calls `backend.encrypt()` for each recipient
2. The `EncryptionWitness` is produced but **not yet set** into `BFV_ENCRYPTION_DATA` thread-local
3. `NovaCompressor::prove_steps` (mod.rs:1349) calls `prove_step` which triggers `synthesize`
4. `bfv_encryption_verify_step` reads `BFV_ENCRYPTION_DATA` — but if it was never populated, it returns `FpVar::one()` (passes vacuously)

- [ ] 4.1 In `full_pipeline.rs`, after encrypt phase (around line 1040), add:
  ```rust
  // Build BFV encryption witness data from the LatticePvssBfvAdapter deal output
  let mut bfv_step_data: Vec<Vec<Fr>> = Vec::with_capacity(cfg.n);
  for party_idx in 0..cfg.n {
      let witness = &encryption_witnesses[party_idx]; // EncryptionWitness
      let bfv_flat = build_bfv_step_data(
          witness, &ciphertext.pk0, &ciphertext.pk1,
      )?;
      bfv_step_data.push(bfv_flat);
  }
  pvthfhe_compressor::nova::set_bfv_encryption_data(bfv_step_data);
  ```
  
  Where `build_bfv_step_data` converts `EncryptionWitness` fields into the flat 28-element Fr layout:
  ```
  [ct0_l0, ct0_l1, ct0_l2, ct1_l0, ct1_l1, ct1_l2,
   pk0_l0, pk0_l1, pk0_l2, pk1_l0, pk1_l1, pk1_l2,
   delta_l0, delta_l1, delta_l2,
   u, e0, e1, m,
   quot0_l0, quot0_l1, quot0_l2,
   quot1_l0, quot1_l1, quot1_l2,
   gamma_power_0, gamma_power_1, gamma_power_2]
  ```

- [ ] 4.2 Add `build_bfv_step_data()` helper to `bfv_encryption_circuit.rs`:
  ```rust
  pub fn build_bfv_step_data(
      witness: &pvthfhe_types::EncryptionWitness,
      pk0: &[u64], pk1: &[u64],
  ) -> Result<Vec<Fr>, CompressorError> { ... }
  ```
  This function:
  - Parses ct0/ct1 from `EncryptionWitness::ct0_poly_bytes`
  - Decomposes into L=3 RNS limbs using `RLWE_Q0`, `RLWE_Q1`, `RLWE_Q2`
  - Computes Δ[l] = floor(q[l]/t) for plaintext modulus t=65536
  - Computes quotient witnesses: `quot0[l] = (pk0[l]·u + e0 + Δ[l]·m - ct0[l]) / q[l]`
  - Derives γ = Poseidon challenge from public inputs
  - Returns `[Fr; BFV_STEP_DATA_LEN]`

- [ ] 4.3 Ensure `clear_bfv_encryption_data()` is called after `prove_steps` completes (already handled by `ThreadLocalClearGuard` at mod.rs:741).

**Effort**: 1.5 days (wiring witness data through the pipeline)
**Risk**: EncryptionWitness polynomials (8192 coefficients each) must be correctly mapped to per-coefficient Fr values. Test with single-coefficient first.
**Success**: BFV_ENCRYPTION_DATA populated before prove_step; in-circuit BFV verification constrains actual ciphertext data.

---

### Task 5: Update `aggregator_final/src/main.nr` for BFV encryption hash

**Files**:
- `circuits/aggregator_final/src/main.nr` (lines 1–108)

- [ ] 5.1 Add BFV encryption verification hash to public inputs:
  ```rust
  fn main(
      // ... existing public inputs ...
      ivc_snark_proof_hash: pub Field,
      bfv_encryption_hash: pub Field,  // NEW: Poseidon hash of all BFV verification results
  
      nova_final_plaintext: pub [Field; N],
      nova_share_chain_hash: pub Field,
  ) -> pub [Field; N] {
      // ... existing checks ...
      
      // NEW: Bind BFV encryption verification
      assert(bfv_encryption_hash != 0, "BFV encryption hash must be non-zero");
      
      nova_final_plaintext
  }
  ```

- [ ] 5.2 The `bfv_encryption_hash` is computed from the CycloFoldStepCircuit state[6] (`bfv_count`) via Poseidon:
  ```rust
  // In full_pipeline.rs:
  let bfv_count = extract_bfv_count_from_nova_state(&nova_final_state);
  let bfv_hash = poseidon::poseidon::bn254::sponge([
      Fr::from(bfv_count as u64),
      session_id,
  ]);
  ```

**Effort**: 0.5 day (minor addition to Noir circuit + Rust plumbing)
**Success**: On-chain verifier can check that BFV encryption was verified in-circuit

---

### Task 6: Integration tests and adversarial tests

- [ ] 6.1 `cargo test -p pvthfhe-compressor`:
  - `bfv_encryption_adversarial.rs` — existing tests should now exercise the in-circuit path
  - New test: `test_bfv_circuit_accepts_honest` — BfvEncryptionStepCircuit prove_step succeeds
  - New test: `test_bfv_circuit_rejects_tampered_pk0` — modify pk0, prove_step fails
  - New test: `test_bfv_circuit_rejects_norm_violation_u` — u > B_U, range check fails
  - New test: `test_bfv_circuit_rejects_wrong_gamma` — wrong S-Z challenge γ, batch check fails

- [ ] 6.2 `cargo test -p pvthfhe-cli`:
  - Pipeline test with `SIGMA_REPETITIONS=1`, `n=5` — BFV encryption verified in-circuit

- [ ] 6.3 `just demo-e2e`:
  - ACCEPTs with BFV encryption constrained in-circuit
  - Tampered ciphertext causes proof rejection

- [ ] 6.4 `just phase3-gate` ACCEPTs

**Effort**: 1 day (testing + debugging)
**Success**: All adversarial cases correctly rejected; honest path ACCEPTs

---

## Effort Summary

| Task | Description | Effort | Dependencies |
|------|-------------|--------|--------------|
| 1 | Create BfvEncryptionStepCircuit as full StepCircuit | 1 day | — |
| 2 | Implement RNS-modular polynomial arithmetic | 1 day | Task 1 |
| 3 | Wire BFV verification into CycloFoldStepCircuit | 1 day | Task 2 |
| 4 | Thread BFV ciphertext commitment through pipeline | 1.5 days | Task 3 |
| 5 | Update aggregator_final Noir circuit | 0.5 day | Task 4 |
| 6 | Integration tests + adversarial tests | 1 day | Tasks 3–5 |
| **Total** | | **~6 days** | |

## Execution Order

```
Task 1 (StepCircuit) → Task 2 (arithmetic) → Task 3 (wire into CycloFold)
                                               → Task 4 (pipeline) → Task 5 (Noir) → Task 6 (tests)
```

Tasks 1+2 are tightly coupled (StepCircuit needs arithmetic). Tasks 3 and 4 can be developed iteratively.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| BFV_ENCRYPTION_DATA not populated before prove_step | Medium | High | Add debug assertion in prove_steps: panic if steps > 0 but data is empty |
| EncryptionWitness-to-Fr conversion mismatches q[l] | Low | Medium | Use the same modulus constants (RLWE_Q0/1/2) defined in `sigma.rs` |
| S-Z batch challenge γ not reproducible verifier-side | Low | High | Derive γ deterministically from Poseidon(ciphertext_hash, pk_hash) |
| Quotient witness computation leaks timing | Low | Low | Quotients computed off-circuit; side-channel not applicable to ZK |
| Schnorr-like BFV sigma (bfv_sigma.rs) vs scalar-challenge sigma (sigma.rs) confusion | Low | Medium | This plan targets the scalar-challenge sigma path only. bfv_sigma.rs uses binary polynomial challenges with different soundness — separate D.1 blocker. |

## References

- `.sisyphus/plans/bfv-encryption-sigma-gap.md` — Original BFV sigma gap plan (existing, 148 lines) — partly superseded by this plan
- `crates/pvthfhe-compressor/src/nova/bfv_encryption_circuit.rs` — BFV encryption R1CS verification function (237 lines): `bfv_encryption_verify_step` (line 78), `norm_range_check_bfv` (line 205)
- `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` — Bellpepper BFV gadget: `bfv_verify_step_bp` (lines 535–747)
- `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs` — CycloFoldStepCircuit arecibo impl (142 lines): synthesize (line 85), bfv_ok field (line 63)
- `crates/pvthfhe-compressor/src/nova/mod.rs` — CycloFoldStepCircuit nova-snark impl (lines 104–163), legacy-nova FCircuit impl (lines 1022–1157)
- `crates/pvthfhe-fhe/src/fhers.rs` — FhersBackend::encrypt_with_witness (line 911–984)
- `crates/pvthfhe-types/src/lib.rs` — EncryptionWitness struct (lines 348–367)
- `crates/pvthfhe-pvss/src/encrypt.rs` — LatticePvssBfvAdapter::deal (lines 176–270)
- `circuits/aggregator_final/src/main.nr` — Noir C7 aggregator circuit (108 lines)
- `crates/pvthfhe-compressor/Cargo.toml` — symphony-t3 feature flag for monomial range checks
