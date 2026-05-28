# P2 — Lattice Folding: Complete Symphony Adoption

**Plan**: `p2-lattice-folding`
**Status**: PLAN
**Created**: 2026-05-28
**Parent**: `.sisyphus/plans/resolve-status-gaps.md`
**Depends on**: Symphony techniques T1–T4 implemented but feature-gated (`.sisyphus/plans/symphony-adoption.md`)
**Goal**: Complete Symphony adoption — enable T1 (high-arity folding) and T2 (FS outside circuit) by default, benchmark at n=16,32,64,128, document gains.

---

## Current State

Symphony techniques were implemented in `feat/symphony-techniques` and tracked in `.sisyphus/plans/symphony-adoption.md` (marked COMPLETE). However, code inspection reveals:

| Technique | Feature flag | Implemented? | Actually doing anything? | Default status |
|-----------|-------------|--------------|--------------------------|----------------|
| T1: High-arity folding | `symphony-t1` | ✅ Code exists | ⚠️ `prove_steps_high_arity` delegates to `prove_steps` — no actual batching | Off (feature-gated) |
| T2: FS outside circuit | `symphony-t2` | ❌ Defined in Cargo.toml only | No `#[cfg(feature = "symphony-t2")]` usage anywhere in code | Off (stub) |
| T3: Monomial embedding range proofs | `symphony-t3` | ✅ Code exists | Yes — `monomial_range.rs` with `adaptive_norm_range_check` | Off (feature-gated) |
| T4: Random projection | `symphony-t4` | ✅ Code exists | Yes — requires `symphony-t3` | Off (feature-gated) |

**The gap**: T1's `prove_steps_high_arity` at `mod.rs:1453` is a one-line wrapper that delegates to the sequential `prove_steps`. It does NOT perform batch folding. T2's feature flag exists in `Cargo.toml` but is entirely unused in source code. The Nova IVC works as a folding substitute (P2 ⚠️), but Symphony's lattice-native folding is not yet a drop-in replacement.

## Success Criteria

- [ ] `symphony-t1` feature gate removed — high-arity folding enabled **unconditionally** in default build
- [ ] T1 `prove_steps_high_arity` implements actual batch folding (not just a passthrough to `prove_steps`)
- [ ] `symphony-t2` feature converted from stub to real implementation: Fiat-Shamir commitments outside the Nova circuit
- [ ] T1 and T2 enabled by default (no feature gate required) in `Cargo.toml`
- [ ] Benchmarks run at n ∈ {16, 32, 64, 128} before and after changes, recording fold time and constraint count
- [ ] Gains documented in `bench/results/lattice-folding-gains.md`
- [ ] `just demo-e2e` ACCEPTs with T1+T2 enabled
- [ ] `just test-all` passes for `pvthfhe-compressor` and `pvthfhe-cli`
- [ ] No regression in compressor verifier (`just phase3-gate` ACCEPTs)

---

## Task Breakdown

### Task 1: Enable T1 high-arity folding by default (remove feature gate)

**Files**:
- `crates/pvthfhe-compressor/Cargo.toml` (lines 47–49)
- `crates/pvthfhe-compressor/src/nova/mod.rs` (line 1453)
- `crates/pvthfhe-cli/src/full_pipeline.rs` (lines 329–336, 591–598, 1020–1027)

**Steps**:

- [ ] 1.1 Remove `#[cfg(feature = "symphony-t1")]` gate from `mod.rs:1453` — make `prove_steps_high_arity` always available
- [ ] 1.2 Remove `#[cfg(feature = "symphony-t1")]` / `#[cfg(not(feature = "symphony-t1"))]` conditional branches from `full_pipeline.rs` — always use `prove_steps_high_arity` (c1 at line 329–336, c4 at line 591–598, c5 at line 1020–1027)
- [ ] 1.3 Remove `symphony-t1 = []` from `Cargo.toml` features list (line 48–49)
- [ ] 1.4 Run `cargo build -p pvthfhe-compressor -p pvthfhe-cli` to verify compilation

**Effort**: 0.25 day (trivial gate removal)
**Success**: `symphony-t1` feature flag no longer exists; `prove_steps_high_arity` used unconditionally in the pipeline

---

### Task 2: Implement actual batch folding in T1

**Files**:
- `crates/pvthfhe-compressor/src/nova/mod.rs` (lines 1340–1460)
- `crates/pvthfhe-compressor/src/nova/high_arity_fold.rs` (NEW)

**Background**: Current `prove_steps` at `mod.rs:1349` loops `prove_step` sequentially for `ivc_steps` iterations. The Nova `RecursiveSNARK` supports multi-step proving natively in IVC mode — each `prove_step` call folds the next circuit instance into the accumulator. The "high arity" approach from Symphony should batch `batch_size` instances into a single fold before calling `prove_step` once.

**Current code** (mod.rs:1453–1460):
```rust
#[cfg(feature = "symphony-t1")]
pub fn prove_steps_high_arity(
    &self, acc: &[u8], steps: &[ExternalInputs3<Fr>],
) -> Result<CompressedProof, CompressorError> {
    self.prove_steps(acc, steps)  // ← just passes through!
}
```

**Target implementation**:

- [ ] 2.1 Create new file `crates/pvthfhe-compressor/src/nova/high_arity_fold.rs` with:
  - `pub struct HighArityConfig { pub batch_size: usize }` (default: `n` — fold all n steps)
  - `pub fn derive_beta_vector(session_id: &[u8], num_steps: usize) -> Vec<Fr>` — deterministic Fiat-Shamir β vector via `Keccak256(session_id || step_index)`
  - `pub fn fold_witnesses(witnesses: &[Vec<Fr>], beta: &[Fr]) -> Vec<Fr>` — linear combination `Σ β_k · w_k`
  - `pub fn fold_external_inputs(inputs: &[ExternalInputs3<Fr>], beta: &[Fr]) -> ExternalInputs3<Fr>` — linear combination of public inputs

- [ ] 2.2 Rewrite `prove_steps_high_arity` in `mod.rs:1453–1460`:
  ```rust
  pub fn prove_steps_high_arity(
      &self, acc: &[u8], steps: &[ExternalInputs3<Fr>],
  ) -> Result<CompressedProof, CompressorError> {
      let batch_size = steps.len().min(128); // cap at 128 for memory
      let beta = derive_beta_vector(&self.session_id, steps.len());
      let folded_inputs = fold_external_inputs(steps, &beta);
      // Still use prove_steps but with folded inputs for each batch
      let folded_steps = vec![folded_inputs; (steps.len() + batch_size - 1) / batch_size];
      self.prove_steps(acc, &folded_steps)
  }
  ```

- [ ] 2.3 Add `use high_arity_fold::*;` to `mod.rs`

**Effort**: 2 days (medium — Nova witness folding requires careful interaction with RecursiveSNARK's state)
**Risk**: Nova RecursiveSNARK may not accept externally pre-folded witnesses. Mitigation: fall back to sequential mode if batch folding fails at setup time, with a warning log.
**Success**: `prove_steps_high_arity` produces identical final accumulator to sequential `prove_steps`

---

### Task 3: Implement T2 FS outside circuit (from stub to real)

**Files**:
- `crates/pvthfhe-compressor/Cargo.toml` (line 50–53)
- `crates/pvthfhe-compressor/src/nova/mod.rs` (sigma_verify_step, lines 731–934)
- `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` (sigma_verify_step_bp, lines 10–185)
- `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs` (CycloFoldStepCircuit synthesize, lines 85–131)
- `crates/pvthfhe-nizk/src/sigma.rs` (derive_challenge_scalar, lines 526–563)

**Background**: T2 moves Fiat-Shamir challenge derivation outside the circuit. Instead of deriving `ch` from raw transcript data inside circuit, the verifier derives it from **commitments** to prover messages. The circuit only verifies the commitment-opening binding, not the FS hash itself. Currently no `#[cfg(feature = "symphony-t2")]` guards exist in source — only the Cargo.toml stub.

**Design**: The commit-and-prove pattern from Symphony §6:
1. Prover computes `com_i = Keccak256(t_rns || c_rns || d_i_rns)` for each sigma step
2. Stores `com_i` in `SIGMA_DATA` thread-local alongside `ch`
3. Circuit allocates `com_i` as witness, verifies `com_i == Keccak256Gadget(t, c, d)` 
4. `ch` is derived from `com_i` (verifier-side, outside circuit) and passed as public witness
5. Circuit enforces `ch ∈ {-1, 0, 1}` and the sigma equation

- [ ] 3.1 Add `pub transcript_commitment: [u8; 32]` field to `SIGMA_DATA`/`SIGMA_RESPONSE_DATA` thread-local structures in `mod.rs`
- [ ] 3.2 In `sigma.rs`, add `fn derive_commitment(t_rns, c_rns, d_rns) -> [u8; 32]` using Keccak256
- [ ] 3.3 In `sigma.rs`, add `fn derive_challenge_from_commitment(com: &[u8; 32], session_id, participant_id) -> i64`
- [ ] 3.4 Modify `sigma_verify_step` in `mod.rs` to:
  - Read `transcript_commitment` from thread-local
  - Allocate `com_var` as witness in circuit
  - Re-derive commitment in-circuit via Keccak256 gadget (or Poseidon if Keccak256 not available in arkworks)
  - Pass `ch` as witness derived from commitment (not from raw transcript)
  - Keep existing sigma equation check unchanged
- [ ] 3.5 Modify `sigma_verify_step_bp` in `nova_gadgets.rs` with same pattern (bellpepper path)
- [ ] 3.6 Wire commitment computation into `NovaCompressor::prove_steps` when `symphony-t2` is active
- [ ] 3.7 Remove `symphony-t2` feature gate — make FS-outside-circuit the **default** behavior (stronger security, fewer constraints)
- [ ] 3.8 If Keccak256 gadget is too expensive in-circuit, use Poseidon commitment instead (reuse `poseidon_gadget.rs`) and document as `symphony-t2-poseidon` variant

**Effort**: 3 days (high — requires Keccak256/Poseidon gadget in R1CS + bellpepper paths)
**Risk**: Keccak256 in R1CS is ~25K constraints. Mitigation: use Poseidon hash (~900 constraints per hash8 × 3 hashes = ~2700 constraints) as the commitment function. Document the security trade-off (Poseidon is not collision-resistant against Grobner-basis attacks at 128-bit, but for FS-binding in a NIZK, second-preimage resistance suffices).
**Success**: Verifier computes `ch` from commitments without raw transcript data in-circuit; tampered commitments cause proof failure

---

### Task 4: Benchmark before/after changes at n=16,32,64,128

**Files**:
- `bench/results/lattice-folding-gains.md` (NEW)
- `bench/scripts/reproduce.sh` (existing)
- `crates/pvthfhe-compressor/benches/` (if exists) or inline benchmarks

- [ ] 4.1 Run baseline benchmarks with current defaults (T1 gate ON, T2 stub):
  ```bash
  just bench-scaling  # n=128 to 1024
  ```
  Extract fold_time and constraints for n=16,32,64,128

- [ ] 4.2 Run benchmarks after T1 implementation (actual batch folding):
  - Measure: fold_time_ms, prove_steps_count (should decrease by factor ≈ batch_size)
  - Expected: T1 reduces `prove_step` calls from n to n/batch_size

- [ ] 4.3 Run benchmarks after T2 implementation (FS outside circuit):
  - Measure: constraint count per sigma step (should not increase — FS is now outside)
  - Measure: total compressor constraints (may decrease by ~2.7K × 128 ≈ 345K)

- [ ] 4.4 Record results in `bench/results/lattice-folding-gains.md`:
  - Table: n, before_T1_fold_ms, after_T1_fold_ms, before_T2_constraints, after_T2_constraints
  - Speedup ratio: `T1_speedup = before / after`
  - Constraint reduction: `T2_reduction = before - after`

**Effort**: 0.5 day (scripting + documentation)
**Success**: Quantified gains documented; benchmarks show measurable improvement

---

### Task 5: Document Symphony-lattice-native path vs Nova substitute

**Files**:
- `docs/symphony-folding-path.md` (NEW)
- `README.md` (P2 status row)

- [ ] 5.1 Create `docs/symphony-folding-path.md` explaining:
  - What the current Nova IVC substitute provides (CCS satisfiability, ∞-norm, arity=8 CycloFoldStepCircuit)
  - What the Symphony T1+T2 approach adds (high-arity batching, FS outside circuit)
  - What remains for full lattice-native folding (LatticeFold+/Cyclo Lemma 9 — requires RLWE quotient ring fold which is not yet implemented)
  - Roadmap: T1+T2 (this plan) → lattice-native folding (future research)
- [ ] 5.2 Update `README.md` P2 status row from `⚠️ Real (CCS satisfiability, ∞-norm; P2 OPEN — Nova substitute)` to `⚠️ Real (CCS satisfiability, ∞-norm; T1+T2 enabled by default; P2 OPEN — lattice-native folding)`

**Effort**: 0.5 day (documentation)
**Success**: Clear documentation of path to full lattice-native folding

---

### Task 6: Integration tests and gate validation

- [ ] 6.1 `just demo-e2e` ACCEPTs with T1+T2 enabled by default
- [ ] 6.2 `cargo test -p pvthfhe-compressor` — all existing tests pass (nova_roundtrip.rs, bfv_encryption_adversarial.rs, step_circuit_fold_relation.rs, step_circuit_relation.rs)
- [ ] 6.3 `cargo test -p pvthfhe-cli` — pipeline tests pass
- [ ] 6.4 `just phase3-gate` ACCEPTs (compressor verification gate)
- [ ] 6.5 New test: `high_arity_fold_correctness` — fold 2 instances, verify accumulator matches sequential
- [ ] 6.6 New test: `fs_outside_circuit_soundness` — adversarial prover with different ch than commitment-derived fails

**Effort**: 1 day (testing + debugging)
**Success**: All gates pass, no regressions

---

## Effort Summary

| Task | Description | Effort | Dependencies |
|------|-------------|--------|--------------|
| 1 | Remove T1 feature gate | 0.25 day | — |
| 2 | Implement actual batch folding | 2 days | Task 1 |
| 3 | Implement T2 FS outside circuit | 3 days | — (independent) |
| 4 | Benchmark before/after | 0.5 day | Tasks 2, 3 |
| 5 | Document path | 0.5 day | Tasks 2, 3 |
| 6 | Integration tests + gate | 1 day | Tasks 2–5 |
| **Total** | | **~7 days** | |

Tasks 2 and 3 can be parallelized. Estimated calendar time: ~5 days with parallel T1/T2 work.

## Execution Order

```
Task 1 (ungate T1) → Task 2 (real T1 folding) ─┐
                                                  ├── Task 4 (benchmark) → Task 5 (docs) → Task 6 (tests)
Task 3 (real T2 FS-outside-circuit) ─────────────┘
```

Tasks 2 and 3 are independent and can be developed in parallel. Task 1 is a quick prerequisite for Task 2.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Nova RecursiveSNARK rejects pre-folded witnesses | Medium | High | Implement fallback to sequential mode with warning log |
| Keccak256 gadget too expensive in R1CS | Medium | Medium | Use Poseidon instead with documented security trade-off |
| CycloFoldStepCircuit arity=8 breaks with T2 | High | Medium | Arity-8 already has known RecursiveSNARK setup issue (B7); T2 changes are additive, not breaking |
| Benchmark noise masks T1 improvement | Low | Low | Run 3 trials, report median; document variance |

## References

- `.sisyphus/plans/symphony-adoption.md` — Original Symphony implementation plan (COMPLETE)
- `.sisyphus/plans/production-readiness.md` §B7 — CycloFoldStepCircuit arity-8 limitation
- `crates/pvthfhe-compressor/Cargo.toml` — Feature flag definitions (lines 47–62)
- `crates/pvthfhe-compressor/src/nova/mod.rs` — `prove_steps` (line 1349), `prove_steps_high_arity` (line 1453)
- `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs` — CycloFoldStepCircuit (lines 54–142)
- `crates/pvthfhe-cli/src/full_pipeline.rs` — Pipeline usage (lines 329–336, 591–598, 1020–1027)
- `bench/results/folding-*.json` — Existing folding benchmark results
