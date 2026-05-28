# P1 — Sigma Repetition for Soundness

**Plan**: `p1-sigma-repetition`
**Status**: PLAN
**Created**: 2026-05-28
**Parent**: `.sisyphus/plans/resolve-status-gaps.md`
**Goal**: Add `SIGMA_REPETITIONS` constant and k-round parallel repetition to the sigma NIZK protocol, achieving configurable soundness from 2/3 (1 round) down to (2/3)^k for a target of 2^-128 at k≈90.

---

## Current State

The sigma protocol at `crates/pvthfhe-nizk/src/sigma.rs` uses a **single-round ternary scalar challenge** `ch ∈ {-1, 0, 1}`. This provides ~1.58 bits of soundness per execution (soundness error = 2/3).

From sigma.rs lines 513–518:
```
// P1 OPEN PROBLEM: Ternary scalar challenge (ch = {-1,0,1}) provides ~1.58 bits
// of soundness per execution. With one round, the soundness error is 2/3 —
// an adversary succeeds 66% of the time by guessing the challenge.
// Resolution pending: either parallel repetition (~90 rounds for 2^-128) or
// switching to binary polynomial challenges in {0,1}^N with NTT-optimized gadgets.
```

**No repetition constant exists.** The protocol is single-round:
- `prove()` (line 236): produces one `SigmaProof` with a single `ch`
- `verify()` / `verify_scalar()` (lines 337–416): checks one round
- `sigma_verify_step` (mod.rs line 781): verifies one round in-circuit
- `sigma_verify_step_bp` (nova_gadgets.rs line 10): verifies one round in bellpepper

The SECURITY.md lines 63–85 documents the soundness budget:

| Round count | Soundness error | Effective bits |
|------------|----------------|----------------|
| 1 (CURRENT) | 2/3 ≈ 0.67 | ~1.58 |
| 10 | (2/3)^10 ≈ 0.017 | ~5.9 |
| 45 | (2/3)^45 ≈ 2^-66 | ~66 |
| 90 | (2/3)^90 ≈ 2^-132 | ~132 |

---

## Success Criteria

- [ ] `SIGMA_REPETITIONS` constant added to `sigma.rs` (default: 1 for backward compat, secure: 90)
- [ ] `sigma::prove()` supports k rounds, producing a `SigmaMultiProof` containing `Vec<SigmaProof>`
- [ ] Each round's challenge is derived via sequential Fiat-Shamir: `ch_i = RO(session, participant, t_i, c, d, commitment, i)`
- [ ] `sigma::verify_multi()` checks all k rounds independently, rejects if ANY round fails
- [ ] `sigma_verify_step_bp` in `nova_gadgets.rs` updated for k-round verification (check each round in circuit, accumulate all passes)
- [ ] CycloFoldStepCircuit sigma_count increments by 1 per round (so k rounds → sigma_count += k)
- [ ] Concrete soundness budget computed and documented in `SECURITY.md`
- [ ] Backward compatibility: `SIGMA_REPETITIONS=1` produces identical proofs to current code
- [ ] `just demo-e2e` ACCEPTs with `SIGMA_REPETITIONS=1` (default)
- [ ] `cargo test -p pvthfhe-nizk` — sigma_completeness.rs passes with k=1 and k=10
- [ ] Performance: k=90 rounds should not exceed ~2s overhead (each round is ~3.5ms at N=8192)

---

## Task Breakdown

### Task 1: Add `SIGMA_REPETITIONS` constant

**File**: `crates/pvthfhe-nizk/src/sigma.rs`

- [ ] 1.1 Add after line 69 (`JL_PROJECTION_DIM`):
  ```rust
  /// Number of parallel repetitions for the sigma protocol.
  /// Soundness error = (2/3)^SIGMA_REPETITIONS.
  /// 1     → ~1.58 bits of soundness (backward compatible)
  /// 90    → ~132 bits (2^-128 target)
  /// 128   → ~203 bits (conservative)
  pub const SIGMA_REPETITIONS: usize = 1;
  ```
- [ ] 1.2 Add after `SigmaProof` struct (line 211):
  ```rust
  /// Multi-round sigma proof: k independent repetitions.
  #[derive(Clone, Debug)]
  pub struct SigmaMultiProof {
      pub rounds: Vec<SigmaProof>,  // One proof per repetition
  }
  ```

**Effort**: 0.25 day (trivial constant + type addition)
**Success**: Constant exists, compiles, `SIGMA_REPETITIONS=1` preserves single-round behavior

---

### Task 2: Modify `prove` and `verify` for k rounds

**File**: `crates/pvthfhe-nizk/src/sigma.rs`

- [ ] 2.1 Add `prove_multi()` function (after line 329):
  ```rust
  pub fn prove_multi(
      session_id: &[u8],
      participant_id: u32,
      stmt: &SigmaStatement,
      wit: &SigmaWitness,
      rng: &mut dyn RngCore,
      d_commitment: &[u8; 32],
      num_rounds: usize,
  ) -> Result<SigmaMultiProof, NizkError> {
      let mut rounds = Vec::with_capacity(num_rounds);
      for i in 0..num_rounds {
          // Seed each round's RNG with a domain-separated nonce
          let mut round_rng = derive_round_rng(rng, i);
          let proof = prove(session_id, participant_id, stmt, wit, &mut round_rng, d_commitment)?;
          // Bind round index into FS transcript to prevent round-swapping
          let proof_with_idx = rebind_challenge_for_round(proof, i)?;
          rounds.push(proof_with_idx);
      }
      Ok(SigmaMultiProof { rounds })
  }
  ```
  
  The challenge derivation must include the round index to prevent cross-round replay:
  ```rust
  fn derive_challenge_for_round(
      session_id: &[u8], participant_id: u32,
      t_rns: &[u64], c_rns: &[u64], d_rns: &[u64],
      d_commitment: &[u8; 32], round_index: usize,
  ) -> i64 { ... }
  ```

- [ ] 2.2 Add `verify_multi()` function:
  ```rust
  pub fn verify_multi(
      session_id: &[u8], participant_id: u32,
      stmt: &SigmaStatement, proof: &SigmaMultiProof,
      d_commitment: &[u8; 32],
  ) -> Result<(), NizkError> {
      for (i, round_proof) in proof.rounds.iter().enumerate() {
          verify_scalar(session_id, participant_id, stmt, round_proof, d_commitment)?;
      }
      Ok(())
  }
  ```
  
  Note: Each round has an independently-derived challenge via `derive_challenge_scalar` with `round_index` bound into the transcript. The existing `verify_scalar` re-derives the challenge and checks it matches, so cross-round replay is prevented by the round-index binding.

- [ ] 2.3 Add `derive_round_rng()` helper — derives a deterministic ChaChaRng seed from the parent RNG + round index for reproducible multi-round execution.

- [ ] 2.4 Update existing `prove()` to internally delegate to `prove_multi()` with `SIGMA_REPETITIONS`:
  ```rust
  pub fn prove(/* same params */) -> Result<SigmaProof, NizkError> {
      if SIGMA_REPETITIONS == 1 {
          prove_single(...) // existing single-round code (unchanged)
      } else {
          let multi = prove_multi(..., SIGMA_REPETITIONS)?;
          // Merge rounds: use first proof as the canonical proof
          // All rounds MUST produce same algebraic relation (same witnesses)
          Ok(multi.rounds[0].clone())
      }
  }
  ```

**Effort**: 2 days (medium — careful FS transcript binding crucial for security)
**Risk**: Parallel repetition with identical witnesses across all rounds is fine (the challenge differs). Non-identical witnesses would break the soundness binding — but the same relation is proven each round, so this is safe.
**Success**: `prove_multi(..., 90)` produces 90 valid proofs; `verify_multi` accepts; any tampered round causes rejection.

---

### Task 3: Update `sigma_verify_step_bp` for k-round verification

**File**: `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` (lines 10–185)

- [ ] 3.1 Add k-round loop to `sigma_verify_step_bp`:
  ```rust
  pub fn sigma_verify_step_bp<CS: ConstraintSystem<NovaScalar>>(
      cs: &mut CS,
      step: usize,
  ) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
      let has_data = SIGMA_DATA.with(|cell| { /* check data exists */ });
      if !has_data {
          return Ok(AllocatedNum::alloc(cs, || Ok(NovaScalar::zero()))?);
      }

      let num_rounds = SIGMA_REPETITIONS;
      let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(NovaScalar::one()))?;
      let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(NovaScalar::zero()))?;

      let mut all_rounds_ok = one.clone();

      for round in 0..num_rounds {
          let round_ns = format!("round_{}", round);
          // Existing per-round verification (lines ~13–165 of current code):
          // Allocate ch, z_s, z_e, t, c, d, sz eval points
          // Enforce sigma equation: c·z_s(γ) + z_e(γ) = t(γ) + ch·d_i(γ)
          // Norm enforce per-coefficient z_s, z_e
          let round_ok = /* existing single-round logic, namespaced */;
          
          // Accumulate: all_rounds_ok = all_rounds_ok * round_ok
          all_rounds_ok = all_rounds_ok.mul(
              cs.namespace(|| format!("accum_round_{}", round)),
              &round_ok,
          )?;
      }

      Ok(all_rounds_ok)
  }
  ```

- [ ] 3.2 Update thread-local data format: `SIGMA_DATA` must carry k rounds of per-round data. Currently `SigmaWitness<F>` (mod.rs:608) holds data for 1 round. Add `sigma_rounds: usize` field and widen to hold `Blob3` for each additional round.

- [ ] 3.3 Update `compute_sigma_ntt_data()` / `compute_sigma_sz_data()` in `sigma.rs` to produce k rounds of NTT-domain data when `SIGMA_REPETITIONS > 1`.

**Effort**: 3 days (high — must carefully refactor the bellpepper gadget without breaking existing 108 constraints per step × k rounds = manageable increase)

**Constraint cost estimate** (per round, per step):
- 3 SZ eval points × 3 RNS limbs = 9 enforce_equal constraints
- Per-coefficient norm checks: 8192 × 2 coefficients × 31 bits = ~508K constraints
- Total per round: ~508K constraints (dominated by per-coefficient norm enforcement)

For k=90 rounds: ~45.7M constraints — this is **too expensive** for practical k in R1CS. Two mitigations:

**Mitigation A (recommended)**: Use **JL random projection** (T4) to reduce per-coefficient norm checks to 256 instead of 8192. Then per round: ~256 × 2 × 18 = ~9K constraints, and k=90 → ~810K constraints — workable.
**Mitigation B**: Only norm-enforce in every m-th round (e.g., m=10), with the algebraic equation checked every round. Soundness analysis required.

**Design decision**: Signal in plan that k-round per-coefficient norm enforcement is infeasible without T4 JL projection. For k ≤ 10, full per-coefficient enforcement is fine (~5M constraints).

**Risk**: Constraint blow-up at high k. Mitigation: document that full per-coefficient norm enforcement is limited to k ≤ 10; for k=90, use T4 JL projection (tracked in P2).

**Success**: `sigma_verify_step_bp` supports `SIGMA_REPETITIONS` rounds; CycloFoldStepCircuit sigma_count accumulates k per step.

---

### Task 4: Update CycloFoldStepCircuit for k-round sigma counting

**Files**:
- `crates/pvthfhe-compressor/src/nova/mod.rs` (lines 104–163, nova-snark StepCircuit impl)
- `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs` (lines 85–131, arecibo synthesize)

- [ ] 4.1 In nova-snark StepCircuit impl (mod.rs:124–125):
  ```rust
  // OLD: sigma_count += sigma_ok (1 per step)
  // NEW: sigma_count += sigma_ok (k per step when k rounds pass)
  let sigma_ok = nova_gadgets::sigma_verify_step_bp(cs, step)?;
  // sigma_count is already additive; k rounds produce k contributions
  ```
  
  The `sigma_verify_step_bp` now returns the accumulated round product (≥0, ≤k). The sigma_count continues to add this value.

- [ ] 4.2 In arecibo `synthesize()` (cyclo_fold_circuit.rs:107–110):
  ```rust
  let sigma_count = z[4].add(cs.namespace(|| "sigma_count_add"), &sigma_ok)?;
  ```
  This already accumulates — if `sigma_ok = k`, sigma_count increments by k (correct behavior).

- [ ] 4.3 Update G.30 counter consistency check in `verify_ivc_core` (mod.rs:2584–2661):
  ```
  OLD: fold_count == sigma_count (when sigma_count > 0)
  NEW: fold_count * SIGMA_REPETITIONS == sigma_count (when k > 1)
  ```

**Effort**: 0.5 day (minor counter adjustment)
**Success**: sigma_count correctly reflects k rounds per fold step.

---

### Task 5: Compute concrete soundness budget

**Files**:
- `docs/security-proofs/p1/soundness-budget.md` (NEW)
- `SECURITY.md` (update lines 63–85)

- [ ] 5.1 Create `docs/security-proofs/p1/soundness-budget.md` documenting:
  
  **Soundness model**:
  - Each round: challenge ch_i ∈ {-1, 0, 1} derived via Fiat-Shamir with round-index binding
  - Adversary guesses challenge: Pr[guess correctly] = 1/3 per round
  - Soundness per round = 2/3 (adversary succeeds with prob 2/3)
  - k-round parallel repetition: Pr[false accept] ≤ (2/3)^k
  - FS binding: challenges derived independently per round via `RO(t_i || c || d || commitment || round_i)`
  
  **Target values**:
  | k | Soundness error | Equivalent bits | Feasibility (constraints) |
  |---|----------------|----------------|--------------------------|
  | 1 | 2/3 | ~1.58 | ~508K (baseline) |
  | 10 | (2/3)^10 ≈ 2^-5.85 | ~5.9 | ~5M (fine) |
  | 45 | (2/3)^45 ≈ 2^-26.3 | ~26 | ~23M (heavy) |
  | 90 | (2/3)^90 ≈ 2^-52.9 | ~53 | ~46M (needs T4 JL proj) |
  | 128 | (2/3)^128 ≈ 2^-75.2 | ~75 | ~65M (needs T4) |

  **Note**: For 128-bit security, the ternary scalar challenge requires ~90 rounds → ~132 rounds for margin. Without T4 JL projection, practical k is ≤ 10. With T4, k=128 yields ~1.2M constraints per step.

  **Cross-reference**: P1 soundness composes with P2 folding soundness (2^-160), SZ batch soundness (2^-135), and NIZK D2-binding. The dominant term is min(P1, P2, SZ, D2).

- [ ] 5.2 Update `SECURITY.md` lines 63–85: Replace the aspirational budget table with concrete computed values. Document that P1 is now `if SIGMA_REPETITIONS=1 { 2/3 error } else { (2/3)^k }`.

**Effort**: 0.5 day (documentation + analysis)
**Success**: Soundness budget is concretely documented with per-parameter error bounds.

---

### Task 6: Integration tests and backward compatibility

- [ ] 6.1 Run `cargo test -p pvthfhe-nizk`:
  - `sigma_completeness.rs` (1000 honest + 102 cheating) — ALL pass with k=1
  - New test: `test_sigma_repetition_accept` — k=10 honest proofs pass verification
  - New test: `test_sigma_repetition_reject_wrong_round` — tampered round in position 5 causes rejection
  - New test: `test_sigma_repetition_cross_round_replay` — proof from round 3 cannot be replayed in round 7 (different challenge due to round-index binding)

- [ ] 6.2 Run `cargo test -p pvthfhe-compressor`:
  - `nova_roundtrip.rs` — IVC prove/verify still ACCEPTS
  - `bfv_encryption_adversarial.rs` — adversarial ciphertext rejection works
  - `step_circuit_fold_relation.rs` — fold relation correct
  - `step_circuit_relation.rs` — sigma verification in-circuit correct

- [ ] 6.3 Run `cargo test -p pvthfhe-cli`:
  - Pipeline tests pass with default SIGMA_REPETITIONS=1

- [ ] 6.4 Run `just demo-e2e`:
  - ACCEPTS with SIGMA_REPETITIONS=1 (default, backward compat)
  - ACCEPTS with SIGMA_REPETITIONS=10 (higher soundness)

- [ ] 6.5 Run `just phase1-gate`:
  - NIZK gate passes (sigma completeness + soundness tests)

**Effort**: 1 day (testing + debugging)
**Success**: All gates pass, no backward compat breakage

---

### Task 7: Performance benchmarking

- [ ] 7.1 Benchmark sigma prove time vs k:
  - `k=1`: baseline (~3.5ms per proof at N=8192)
  - `k=10`: measure prove time, expect ~35ms (10× linear)
  - `k=90`: measure prove time, expect ~315ms
  - `k=128`: measure prove time, expect ~448ms

- [ ] 7.2 Benchmark compressor constraints vs k:
  - `k=1`: ~508K constraints baseline
  - `k=10`: ~5M constraints
  - `k=90`: ~46M constraints (too expensive without T4)
  - Document that practical k is 1–10 without T4; k≥90 requires T4 JL projection

- [ ] 7.3 Record results in `bench/results/sigma-repetition.json`

**Effort**: 0.5 day (benchmarking)
**Success**: Performance characterized; constraint budget documented

---

## Effort Summary

| Task | Description | Effort | Dependencies |
|------|-------------|--------|--------------|
| 1 | Add SIGMA_REPETITIONS constant | 0.25 day | — |
| 2 | Modify prove/verify for k rounds | 2 days | Task 1 |
| 3 | Update sigma_verify_step_bp for k rounds | 3 days | Tasks 1, 2 |
| 4 | Update CycloFoldStepCircuit counters | 0.5 day | Task 3 |
| 5 | Compute concrete soundness budget | 0.5 day | Task 2 |
| 6 | Integration tests + backward compat | 1 day | Tasks 2–4 |
| 7 | Performance benchmarking | 0.5 day | Task 6 |
| **Total** | | **~8 days** | |

## Execution Order

```
Task 1 (constant) → Task 2 (prove/verify) ─→ Task 3 (in-circuit gadgets)
                                             → Task 4 (counters) ─→ Task 5 (budget) ─→ Task 6 (tests) ─→ Task 7 (bench)
```

Tasks 3 and 4 can proceed in parallel once Task 2 is done. Task 5 is documentation-only and independent of Task 3.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| k=90 blows up constraint count (46M) | High | Medium | Document cap at k=10 without T4; defer k≥90 to T4 JL projection plan |
| FS round-index binding flaw | Low | High | Use canonical RO binding; crypto audit review |
| Sigma witness thread-local needs k-round widening | Low | Medium | SIGMA_DATA already uses Vec; just add k× entries |
| Backward compat break for existing proofs | Low | High | Default SIGMA_REPETITIONS=1 preserves exact byte-level compatibility |

## References

- `.sisyphus/plans/symphony-adoption.md` §T4 — JL random projection (enables cheap k-round norm enforcement)
- `crates/pvthfhe-nizk/src/sigma.rs` — Main sigma protocol (1024 lines): prove (line 236), verify (line 337), verify_scalar (line 352), derive_challenge_scalar (line 526)
- `crates/pvthfhe-compressor/src/nova/nova_gadgets.rs` — `sigma_verify_step_bp` (lines 10–185)
- `crates/pvthfhe-compressor/src/nova/mod.rs` — `sigma_verify_step` (lines 781–934), CycloFoldStepCircuit arcnova (lines 104–163), G.30 counter consistency (lines 2584–2661)
- `crates/pvthfhe-compressor/src/nova/cyclo_fold_circuit.rs` — arecibo CycloFoldStepCircuit (lines 54–142)
- `SECURITY.md` lines 63–85 — Current P1 soundness budget table
- `docs/security-proofs/p1/T1.md`, `T2.md` — Completeness and soundness formal proofs
