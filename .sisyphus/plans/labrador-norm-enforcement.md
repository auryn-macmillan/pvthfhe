# Plan: LaBRADOR-Style Norm Enforcement for CycloFoldStepCircuit

**Status**: RESEARCH — REVISED (parameter fix + cost model + phase reorder)  
**Reference**: Beullens & Seiler, "LaBRADOR: Compact Proofs for R1CS from Module-SIS", CRYPTO 2023 ([eprint 2022/1341](https://eprint.iacr.org/2022/1341))  
**Implementation Reference**: [github.com/lattirust/labrador](https://github.com/lattirust/labrador)  
**Estimate**: ~2-3 weeks  
**Depends on**: CycloFoldStepCircuit (built), G7b norm accumulation (built), B_Z_S/B_Z_E from sigma.rs

## Goal

Replace the current per-coefficient L∞ range check (31 bit-decompositions × 8,192 coefficients = ~254K constraints per step) with a LaBRADOR-style Johnson-Lindenstrauss projection that verifies norms in O(m) ≈ O(log N) constraints.

## How It Works

The LaBRADOR protocol verifies `‖w‖₂ ≤ β` by:
1. **Off-circuit**: Compute JL projection `p = Π·w` where Π is an m×N structured matrix (m≈64, N=8192). The prover computes p honestly.
2. **On-circuit**: Verify `‖p‖₂ ≤ √(m/2)·β`. The JL lemma guarantees this is equivalent to `‖w‖₂ ≤ β` with soundness error 2^{-m/2} ≈ 2^{-32}.
3. **Commitment binding**: The prover also proves that p was computed from the committed witness w via a separate lattice-native commitment opening. This is done outside R1CS (Cyclo/Ajtai native prover).

The R1CS circuit cost is therefore just the norm check of p (m=64 multiplications for p[i]²), NOT the projection computation itself.

## Correct Bound Parameters

From `sigma.rs:49-51`:
- `B_Z_S = B_Y + N = 2^30 + 8_192 ≈ 1,073,750,016` (infinity norm)
- `B_Z_E = B_Y + N · SIGMA_B_E = 2^30 + 8_192 · 16 ≈ 1,073,881,088` (infinity norm)
- L2 norm bound: `‖z_s‖₂ ≤ √8192 · B_Z_S ≈ 90 · 1.07e9 ≈ 9.7e10`
- L2 norm bound: `‖z_e‖₂ ≤ √8192 · B_Z_E ≈ 90 · 1.07e9 ≈ 9.7e10`

JL projection target: `‖p‖₂ ≤ √(m/2) · 9.7e10` with m=64.

## Architecture

```
Off-circuit (native, lattice prover):
  1. Compute JL projection p_s = Π·z_s, p_e = Π·z_e (structured JL matrix)
  2. Commit to p_s, p_e via Ajtai commitment (binding to witness)

On-circuit (R1CS, CycloFoldStepCircuit):
  3. Receive p_s, p_e as witness from SIGMA_RESPONSE_DATA
  4. Verify ‖p_s‖₂ ≤ √(m/2)·B_Z_S_L2  (m=64 squaring constraints)
  5. Verify ‖p_e‖₂ ≤ √(m/2)·B_Z_E_L2  (m=64 squaring constraints)
  6. Accumulate: state[5] += proj_norm_s, state[6] += proj_norm_e
```

## Implementation Phases

### Phase 1: Slack Factor Analysis (MUST COME FIRST) (~1 day)
*Anchor Phase 2 parameters on this analysis.*

- [ ] Derive JL projection soundness: with m=64, soundness error = 2^{-32} per step
- [ ] Derive slack factor from LaBRADOR §5.5: β_actual ≈ √(128/30) · β_claimed ≈ 2.07·β
- [ ] Verify: with 2.07× slack and B_Z_S ≈ 1.07e9, bounded prover norm ≤ 2.2e9 — acceptable for Cyclo fold security (still within SIS hardness range)
- [ ] Document: the slack factor means a malicious prover MAY submit a witness with ‖w‖ ≤ 2.07·B. For our parameters, this is still bounded by Module-SIS hardness at q ≈ 2^50, β ≈ 2.2e9.
- [ ] QA: `cargo test -p pvthfhe-compressor slack_analysis` — slack factor correctly derived

### Phase 2: In-Circuit Projection Verification (~3 days)
*Uses analysis from Phase 1.*

- [ ] `CycloFoldStepCircuit` state_len stays at 7; `z_s_proj_acc` and `z_e_proj_acc` replace `z_s_sq_acc`/`z_e_sq_acc`
- [ ] `SIGMA_RESPONSE_DATA` thread-local extended: each entry now carries `(z_s: Vec<i64>, z_e: Vec<i64>, p_s: Vec<i64>, p_e: Vec<i64>)` — proj vectors added
- [ ] `generate_step_constraints`: new section `G7b-laBRADOR`:
  - Read proj vectors p_s, p_e (m=64 each) from SIGMA_RESPONSE_DATA
  - Circuit provides `FpVar::constant` for each p_s[i] (proj values ARE constants from the prover — witness binding via Ajtai commitment, not R1CS)
  - Verify: `Σ p_s[i]² ≤ m/2 · B_Z_S_L2²` (1 accumulation + 1 comparison: ~2 constraints)
  - Verify: `Σ p_e[i]² ≤ m/2 · B_Z_E_L2²` (1 accumulation + 1 comparison: ~2 constraints)
  - Total per step: ~128 squaring multiplications + ~4 accumulation/comparison ≈ **132 constraints** (vs current 254K)
- [ ] Track A compatibility: when SIGMA_RESPONSE_DATA has no proj vectors, accumulate 0 (vacuous pass)
- [ ] QA: `cargo test -p pvthfhe-compressor cyclo_projection` — projection check correct

### Phase 3: Off-Circuit Projection Computation (~2 days)
- [ ] New function `compute_jl_projection(w: &[i64], seed: [u8; 32], m: usize) -> Vec<i64>` in `sigma.rs` or new `projection.rs`
- [ ] Generate deterministic JL matrix from session seed via Poseidon sponge (LaBRADOR-style structured matrix with `±1/√m` entries)
- [ ] Actually use a sparse JL construction: only ±1 entries at random positions (Achlioptas, 2003) — eliminates dense multiplication
- [ ] Unit test: `‖Π·w‖₂ ≈ ‖w‖₂` for random vectors (tolerance ±15%)
- [ ] Unit test: projection preserves norm ordering: `‖w₁‖₂ < ‖w₂‖₂ ⇒ ‖Π·w₁‖₂ < ‖Π·w₂‖₂` with high probability
- [ ] QA: `cargo test -p pvthfhe-nizk jl_projection` — all tests pass

### Phase 4: Integration and QA (~2 days)
- [ ] Wire `compute_jl_projection` into sigma verify flow: after z_s/z_e verified, compute projections, pass to SIGMA_RESPONSE_DATA
- [ ] Wire into demo-e2e, per-node, aggregator
- [ ] QA: `just demo-e2e 10 4 1` ACCEPTS
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS
- [ ] QA: `cargo test -p pvthfhe-compressor norm_projection` — projection correct, slack zone detected, Track A vacuous pass

## Constraint Budget

| Step | What | Constraints |
|------|------|------------|
| Projection computation | Off-circuit (native) | 0 R1CS |
| Squared norm accumulation (m=64) | Σ p[i]² in R1CS | 64 per vector |
| Bound comparison | ≤ check | 4 per step |
| **Total R1CS per step** | | **~132** (vs 254K current) |
| **Reduction** | | **1,920×** |
