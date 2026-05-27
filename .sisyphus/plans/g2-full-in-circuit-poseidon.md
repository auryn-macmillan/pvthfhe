# Plan: G2 Full — In-Circuit Commitment Opening + r-Power Correctness

**Plan**: `g2-full-in-circuit-poseidon`
**Status**: DONE
**Created**: 2026-05-17
**Depends on**: in-circuit-verification.md (G2 partial complete)
**Goal**: Close the three remaining G2 trust gaps: commitment opening, r-power correctness, and challenge derivation — all in R1CS constraints.

---

## Gap Inventory

| ID | Gap | Current State | Target |
|----|-----|--------------|--------|
| **G2a** | **Commitment opening not in circuit** | Off-circuit `verify_merkle_proofs()` checks only leaf_index=0. Circuit receives 8192 coefficient witnesses but never verifies they hash to `ext.2` (merkle_root). A malicious prover can supply arbitrary coefficients that don't match the committed root. | Circuit computes Poseidon sponge hash of all 8192 coefficient witnesses and enforces equality with `ext.2`. |
| **G2b** | **r-power correctness not verified** | `r_pow[j]` are witnesses. No constraint enforces `r_pow[0] == 1` or `r_pow[j+1] == r_pow[j] * r`. Malicious prover can supply arbitrary powers. | Constrain `r_pow[0] == 1` and `r_pow[j+1] == r_pow[j] * r` for all j in 0..N_COEFFS-2. |
| **G2c** | **Challenge point r derived natively** | `derive_challenge_point_r()` in full_pipeline.rs:1666 uses SHA-256 over coefficient bytes. Circuit trusts `r` without verifying derivation. | Derive `r` from Poseidon hash of the commitment (`ext.2`) + session identifier. Circuit receives `r` as public input and verifies `r == Poseidon::hash(ext.2 || session_tag)`. |

---

## Design

### Commitment Scheme Change: Merkle Tree → Poseidon Sponge

**Why change**: Reconstructing the 8-ary Merkle tree in R1CS requires ~1,171 `hash8` operations (~1,053,000 constraints per step). A direct Poseidon sponge hash of 8192 coefficients requires only ~614,700 constraints per step (~42% less) and is simpler to implement.

**New commitment**: `commitment = PoseidonSponge::absorb_all(coeffs[0..8191]).squeeze()`

The existing `PoseidonSpongeVar` (poseidon_gadget.rs) already supports absorbing arbitrary numbers of elements. Rate=4 means 8192/4 = 2048 permutation rounds, plus 1 squeeze. Each permutation costs ~300 constraints (only variable×variable multiplications; MDS mixing and ARK are constant×variable, free in R1CS).

**Impact on C7WitnessSet**: Replace `build_merkle_tree` + `prove_merkle_path` with `hash8_native` accumulated sponge hash. Remove `merkle_proof` field from `C7Witness`. Change `merkle_root` field name to `coeff_commitment`.

### r-Power Correctness

Add `r` as a public input to `ExternalInputs4` (replacing the currently-unused `dkg_root_hash` slot, or widening to `ExternalInputs5`). In `generate_step_constraints`:

```rust
// Constrain r-powers
enforce_equal(r_pow[0], FpVar::one())?;
for j in 0..N_COEFFS-1 {
    enforce_equal(r_pow[j+1], r_pow[j] * r_var)?;
}
```

This adds 8191 multiply-add constraints per step. Combined with the existing 8192 mul-adds for Horner evaluation: **~16,383 mul-adds + 614,700 sponge hashing = ~631,000 constraints per step**.

### Challenge Derivation

The circuit derives `r` from the commitment: `r = Poseidon::hash(coeff_commitment || session_epoch)`. The `session_epoch` is a public input. The circuit enforces: `computed_r == ext.r`. This prevents the prover from choosing a favorable challenge point.

---

## Implementation Plan

### Phase 1: Commitment Scheme Migration (Spine)

**Files affected**:
- `crates/pvthfhe-compressor/src/witness.rs` — C7WitnessSet, C7Witness
- `crates/pvthfhe-compressor/src/nova/c7_circuit.rs` — C7DecryptAggregationCircuit
- `crates/pvthfhe-compressor/src/nova/mod.rs` — ExternalInputs4 → ExternalInputs5
- `crates/pvthfhe-compressor/src/nova/poseidon_gadget.rs` — Expose `PoseidonSpongeVar` for direct use
- `crates/pvthfhe-cli/src/full_pipeline.rs` — Witness construction

### Task Breakdown

| ID | Task | File(s) | Effort | Depends |
|----|------|---------|--------|---------|
| **P1.1** | Add `hash_all_coeffs` function to witness.rs: computes Poseidon sponge hash of 8192 Fr values (native, matching circuit) | `witness.rs` | 0.5 day | — |
| **P1.2** | Update `C7Witness` struct: rename `merkle_root` → `coeff_commitment`, remove `merkle_proof`, add method to compute commitment from coeffs | `witness.rs` | 0.5 day | P1.1 |
| **P1.3** | Update `C7WitnessSet::new()`: use `hash_all_coeffs` instead of Merkle tree building and proof generation. Remove `verify_merkle_proofs()`. Add `verify_commitments()` that checks each participant's commitment matches its coefficients. | `witness.rs` | 0.5 day | P1.2 |
| **P1.4** | Expose `PoseidonSpongeVar` publicly from poseidon_gadget.rs. Add a method to absorb many elements and return a single hash. | `poseidon_gadget.rs`, `mod.rs` | 0.5 day | — |
| **P1.5** | Widen external inputs from `ExternalInputs4` to `ExternalInputs5`: add `r` (challenge point) as 5th field element. Update `ExternalInputs5`, `ExternalInputs5Var`, `AllocVar` impl, `encode_quad`→`encode_quint`. | `mod.rs` | 0.5 day | — |
| **P1.6** | Add in-circuit commitment verification to `C7DecryptAggregationCircuit::generate_step_constraints`: absorb 8192 coefficient witnesses into `PoseidonSpongeVar`, squeeze, enforce equality with `ext.2` (coeff_commitment). | `c7_circuit.rs` | 1 day | P1.4, P1.5 |
| **P1.7** | Add r-power correctness constraints: `r_pow[0]==1`, `r_pow[j+1]==r_pow[j]*r`. Also add `r` as witness (now an external input). | `c7_circuit.rs` | 0.5 day | P1.5 |
| **P1.8** | Add challenge derivation in circuit: `computed_r = Poseidon::hash(coeff_commitment || epoch)`, enforce `computed_r == ext.r`. | `c7_circuit.rs` | 0.5 day | P1.4, P1.5 |
| **P1.9** | Update `c7_fold_witnesses()`: pass `r` as external input. Remove off-circuit `verify_merkle_proofs()` call (replace with native commitment check). Update `set_c7_step_data` to pass `r` too. | `c7_circuit.rs` | 0.5 day | P1.3, P1.5 |
| **P1.10** | Update full_pipeline.rs: change `run_c7_verification` to use new `C7WitnessSet::new()` (no Merkle tree). Derive `r` from commitment hash. Pass `r` as external input. Update `ExternalInputs4` → `ExternalInputs5` in all call sites. | `full_pipeline.rs` | 0.5 day | P1.3, P1.5 |
| **P1.11** | Update per_aggregator.rs and per_node.rs binaries: `ExternalInputs4` → `ExternalInputs5`. | `per_aggregator.rs`, `per_node.rs` | 0.25 day | P1.5 |

### Phase 2: RED Tests

| ID | Test | What it proves | Files | Effort |
|----|------|---------------|-------|--------|
| **P2.1** | `test_c7_commitment_honest_passes` | Valid coefficients pass commitment check | `tests/c7_step_circuit.rs` | 0.25 day |
| **P2.2** | `test_c7_tampered_coeffs_fail` | Changed coefficient→commitment mismatch→constraint violation | `tests/c7_step_circuit.rs` | 0.25 day |
| **P2.3** | `test_c7_wrong_commitment_fail` | Wrong ext.2→constraint violation | `tests/c7_step_circuit.rs` | 0.25 day |
| **P2.4** | `test_c7_r_power_honest_passes` | Correct r-powers pass constraints | `tests/c7_step_circuit.rs` | 0.25 day |
| **P2.5** | `test_c7_r_power_wrong_fails` | Arbitrary r-powers→constraint violation | `tests/c7_step_circuit.rs` | 0.25 day |
| **P2.6** | `test_c7_challenge_derivation` | r derived from commitment in-circuit, wrong r→violation | `tests/c7_step_circuit.rs` | 0.25 day |
| **P2.7** | `test_c7_full_nova_roundtrip` | Full Nova IVC roundtrip with commitment+r-power+r-derivation | `tests/c7_step_circuit.rs` | 0.5 day |
| **P2.8** | `test_c7_witness_set_commitment_match` | C7WitnessSet native commitment matches circuit | `tests/c7_phase2_n8192.rs` | 0.25 day |

### Phase 3: Integration Verification

| ID | Check | Command | Effort |
|----|-------|---------|--------|
| **P3.1** | All existing C7 tests pass | `cargo test -p pvthfhe-compressor` | 0.25 day |
| **P3.2** | Demo-e2e ACCEPT | `just demo-e2e` | 0.25 day |
| **P3.3** | Per-aggregator benchmark produces output | `cargo run --bin per-aggregator -- --n 16 --threshold 4` | 0.25 day |
| **P3.4** | LSP diagnostics clean | `lsp_diagnostics` on changed files | 0.1 day |

---

## Constraint Budget

| Component | Constraints per step | Type |
|-----------|---------------------|------|
| Horner evaluation (8192 coeffs) | 8,192 | `witness × witness + witness` |
| r-power correctness (8191 steps) | 8,191 | `witness × witness` |
| Poseidon sponge hash (2048 perms) | ~614,400 | `variable × variable` (3 per sbox, 5 sboxes per perm = 15 per perm) |
| Challenge derivation (1 perm) | ~300 | `variable × variable` |
| **Total per step** | **~631,000** | |

At t=63: ~39.8M constraints. At t=127: ~80.1M constraints. Both within Nova's practical range (tested up to ~100M).

**Per-step overhead**: ~2.3× over current G2 partial (~270K for Horner eval only). At t=63, per-aggregator C7 time estimated at ~28s (was ~12s post-G2 partial, +133%). This is the security-vs-performance tradeoff.

---

## Acceptance Criteria

- [ ] All 8192 coefficient witnesses bound to in-circuit commitment hash (`ext.2`)
- [ ] r-power sequence constrained: `r_pow[0]==1`, `r_pow[j+1]==r_pow[j]*r`
- [ ] Challenge point `r` derived from commitment in R1CS (not trusted from natively-derived value)
- [ ] `C7WitnessSet` uses Poseidon sponge hash, not Merkle tree (native matches circuit)
- [ ] `c7_fold_witnesses` no longer calls off-circuit `verify_merkle_proofs`
- [ ] All 8 RED tests pass
- [ ] All existing C7 tests pass (no regressions)
- [ ] `just demo-e2e` ACCEPT
- [ ] Per-aggregator binary produces correct output
- [ ] LSP diagnostics clean on all changed files

---

## Estimated Total Effort

**~5 days** (implementation: 3.5 days, tests: 2 days, integration: 0.5 days)

Matches the ~1 week estimate from `in-circuit-verification/decisions.md`.
