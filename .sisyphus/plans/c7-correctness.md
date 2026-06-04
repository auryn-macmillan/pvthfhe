# Plan: C7 — Threshold-Decryption Correctness (Noir Circuit)

**Plan**: `c7-correctness`
**Status**: PLAN
**Created**: 2026-06-04
**Parent**: `.sisyphus/plans/meta-plan-all-deferred.md` §H.1
**Gap**: C7 (decryption correctness)
**Goal**: Add a Noir constraint system to `circuits/aggregator_final/` that proves Lagrange recombination of decrypt shares correctly reconstructs the plaintext.

---

## Current State

### What works (scaling, not correctness)

The plan `.sisyphus/plans/c7-p3-final.md` (6/6 tasks complete) covers N=8192 SCALING (compile, prove, verify). All scaling tasks are done. C7 SCALING is not C7 CORRECTNESS.

### What proves hash binding (not decryption)

`circuits/aggregator_final/src/main.nr` (`main()` function, lines 109-143) currently proves only:

1. **Poseidon hash binding** (line 133-134): `plaintext_commitment == vector_hash(nova_final_plaintext, DOMAIN)` — the plaintext commitment matches the hash of the provided plaintext limbs.
2. **Non-zero guards** (lines 125-131): `epoch > 0`, `participant_set_hash != 0`, `threshold > 0`, `aggregate_pk_hash != 0`, `decrypt_nizk_hash != 0`, `dkg_transcript_hash != 0`.
3. **Ciphertext-plaintext distinction** (line 136): `ciphertext_hash != computed_pt_hash`.
4. **IVC proof non-zero** (line 138): `ivc_snark_proof_hash != 0`.
5. **Nova chain hash non-zero** (line 140): `nova_share_chain_hash != 0`.

**What is NOT proved**:
- The Lagrange recombination arithmetic: `Σ λ_i · d_i ≡ plaintext` (mod Q)
- That `nova_final_plaintext` (field `[Field; N]` with N=8) is the correct plaintext reconstructed from the decrypt shares
- That the Lagrange coefficients `λ_i` sum to 1
- Any relationship between `nova_share_chain_hash` and the actual share polynomials

The circuit receives `nova_final_plaintext` as a public input (line 122) and simply returns it (line 142). A malicious prover could provide any 8 field elements and the circuit would accept, as long as the Poseidon commitment matches.

### What Nova IVC already folds (work not to duplicate)

The Nova `LagrangeFoldStepCircuit` (`crates/pvthfhe-compressor/src/nova/lagrange_fold_circuit.rs`) performs:
- Step accumulation: `z[0] = z[0] + λ_i · share_hash_i` (line 92-93 in legacy-nova, lines 147-150 in bellpepper)
- Chain hash: `chain_hash = Poseidon(prev_hash, share_hash_i)`
- Share provenance: `share_var == registered_var` (line 87-88 / lines 136-144)

This circuit operates on **scalar field element hashes** (Poseidon hash values of share polynomials), not on the polynomial coefficients themselves. It is a hash accumulator, not a decryption verifier. The `aggregator_final` Noir circuit should NOT reimplement this Nova folding; instead, it should verify the final plaintext against the actual polynomial shares.

### What the native pipeline already checks (out-of-circuit)

`crates/pvthfhe-cli/src/full_pipeline.rs` (`run_c7_verification()`, lines 3244-3336) performs native (Rust-side, outside Noir) checks:
- `z0_expected = Σ λ_i · d_i(r)` — evaluates share polynomials at challenge point `r`, multiplies by Lagrange coefficients, sums (lines 3280-3284)
- `z1_expected = Σ λ_i` — Lagrange sum must equal 1 (line 3285)
- `verify_c7_plaintext_binding()` (lines 3358-3373) checks `z1 == 1` and logs `z0`
- CompressionTree building from Poseidon leaf hashes (lines 3300-3334)

The comment at lines 3333-3335 is explicit: "G3: full plaintext binding deferred". This native check is NOT an in-circuit constraint. It trusts the native computation, which is not cryptographically forced by any proof system.

### Relevant FHE backend APIs (already available)

The `FhersBackend` in `crates/pvthfhe-fhe/src/fhers.rs` already exposes the APIs needed for C7 correctness witnesses:

| API | Line | Purpose |
|-----|------|---------|
| `aggregate_decrypt_raw_result_poly()` | 1775 | Returns pre-scaling Lagrange-interpolated polynomial `raw_result_poly_bytes` in [0,Q) domain (z0 accumulator before `Scaler::new`) |
| `poly_coeffs_from_bytes()` | 1464 | Converts raw poly bytes to i64 RNS residues (24,576 values = 8,192 coeffs × 3 moduli), power-basis representation |
| `poly_coeffs_fr_reconstruct()` | 1492 | CRT-reconstructs RNS residues into centered BN254 Fr values (8,192 coefficients) |
| `compute_lagrange_coeffs_integer()` | 1903 | Computes Lagrange coefficients as i64 integers (for n ≤ 64) |

The `aggregate_decrypt_raw_result_poly` method (lines 1848-1894) explicitly computes `raw_result_poly = Σ λ_i · d_i` in the polynomial ring (lines 1850-1870), then also runs `decrypt_from_shares` through `ShareManager` for comparison. This is the **exact pre-scaling polynomial** that the C7 circuit must verify.

### Orthogonal work (not C7)

- **F67 decrypt-share wire-v2** (ct_hash binding in `DecryptShareV2`): This is a per-share wire format robustness fix. It does NOT address C7 correctness.
- **C7 Coefficient check** (`c7-ring-aware-coefficient-check.md`, COMPLETE): This added a native (Rust) coefficient-wise check, not an in-circuit constraint.
- **G3 plaintext binding M1** (`run_c7_verification`, M1 only): Native accumulator consistency and Lagrange sum check. Logs z0 but does NOT constrain it.

---

## What Needs to Exist

### The C7 correctness relation

A Noir constraint system within `aggregator_final` that proves, under the BFV threshold decryption scheme:

**Schwartz-Zippel polynomial identity check:**

Given:
- Public: challenge point `r ∈ Fr`, plaintext commitment `plaintext_commitment`
- Witness: decrypt share polynomials `d_i ∈ (Z_Q[X]/(X^N+1))` for i = 1..t, Lagrange coefficients `λ_i ∈ Fr` for i = 1..t, plaintext polynomial `pt ∈ Z_Q[X]/(X^N+1)`

Prove:
1. `Σ_{i=1}^t λ_i · d_i(r) ≡ pt(r) (mod Q)` (Lagrange recombination of share evaluations equals plaintext evaluation)
2. `Σ_{i=1}^t λ_i = 1` (Lagrange interpolation identity, Frobenius check)
3. `plaintext_commitment == Poseidon(pt_coeffs_as_field_elements)` (plaintext commitment binding)

### Why Schwartz-Zippel and not coefficient-wise

Verifying `Σ λ_i · d_i[k] ≡ pt[k]` for all 8,192 coefficients per share would require 8,192 constraints per participant. For t=4 participants, that is ~32K constraints per modulus, times 3 moduli ≈ 96K constraints. The Schwartz-Zippel identity test methodology (section 2 of `c7-nova-step-circuit.md`) reduces this to a single polynomial evaluation at a random challenge point `r`, keeping constraint count independent of ring dimension N.

### Ring arithmetic challenge

The polynomials live in `Z_Q[X]/(X^8192+1)` where Q ≈ 2^174 (product of 3 RNS moduli: 288230376173076481, 288230376167047169, 288230376161280001). Noir's native field is BN254 Fr (~254 bits), which is larger than Q. This means:

- A single Fr field element can hold one Q-residue (mod q_j, each ~58 bits)
- CRT reconstruction is NOT needed in-circuit; each modulus limb can be checked independently
- Share polynomial coefficients are provided as RNS residues (3 residues per coefficient per share)
- The circuit must check the Lagrange recombination for each modulus j = 0,1,2 independently

---

## Relevant Source Files

| File | Relevance |
|------|-----------|
| `circuits/aggregator_final/src/main.nr` | **Primary target**: extend `main()` with C7 correctness constraints |
| `circuits/aggregator_final/Prover.toml` | Current witness format (N=8 ring dimension, no share polynomials) |
| `circuits/aggregator_final/Nargo.toml` | Package manifest — may need new dependencies |
| `circuits/protocol_constants/src/lib.nr` | Domain tags, protocol constants (Q value) |
| `crates/pvthfhe-cli/src/full_pipeline.rs` | Witness generation: `run_c7_verification()` (line 3244), `build_c7_prover_toml` (line ~2371) |
| `crates/pvthfhe-fhe/src/fhers.rs` | Backend APIs: `aggregate_decrypt_raw_result_poly()` (line 1775), `poly_coeffs_from_bytes()` (line 1464), `poly_coeffs_fr_reconstruct()` (line 1492) |
| `crates/pvthfhe-compressor/src/nova/lagrange_fold_circuit.rs` | Nova IVC step circuit (hash folding, not polynomial arithmetic — do NOT modify) |
| `docs/OPEN-PROBLEM-BLOCKERS.md §C7` | Canonical problem description (lines 29-45) |
| `.sisyphus/plans/meta-plan-all-deferred.md §H.1` | Meta-plan reference for C7 correctness |
| `.sisyphus/plans/c7-p3-final.md` | C7 scaling plan (DONE — SCALING only, not correctness) |
| `.sisyphus/plans/c7-ring-aware-coefficient-check.md` | Native coefficient check (COMPLETE — native only, not in-circuit) |

---

## Success Criteria

1. `circuits/aggregator_final/src/main.nr` contains a `main()` function that constrains the full C7 correctness relation (Lagrange recombination of share polynomial evaluations equals plaintext evaluation).
2. The circuit verifies Lagrange identity: `Σ λ_i = 1` as a constraint, not just in witness generation.
3. Witness generation in `full_pipeline.rs` extracts share polynomial coefficients, Lagrange coefficients, and plaintext polynomial from the FHE backend and feeds them into Prover.toml.
4. The circuit compiles via `nargo compile` with constraint count documented.
5. The circuit proves and verifies via the canonical Noir+BB flow (`nargo execute` → `bb write_vk` → `bb prove` → `bb verify`).
6. Test vectors cover all required adversarial scenarios (see Acceptance Criteria below).
7. `just demo-e2e` passes with C7 correctness verified in-circuit.
8. Status comment in `docs/OPEN-PROBLEM-BLOCKERS.md §C7` is updated to reflect resolved status.

---

## Task Breakdown

### T.1 — Design the C7 correctness constraints

**Outcome**: A detailed constraint specification, documented in `aggregator_final/src/main.nr` as comments above the `main()` function.

**Activities**:

- [ ] T.1.1: Decide Schwartz-Zippel evaluation approach vs coefficient-wise approach. Document constraint count estimates for each option. For N=8192, Schwartz-Zippel is ~7 constraints per share (3 moduli × 1 eval + 1 Horner), while coefficient-wise is ~(3 × 8192 × t) constraints. Recommend Schwartz-Zippel and document why.
- [ ] T.1.2: Specify the extended public input list. The circuit currently has 10 public inputs (lines 110-119) + 2 Nova state inputs (lines 122-123). New public inputs needed:
  - `challenge_r: pub Field` — the Schwartz-Zippel evaluation point
  - `n_shares: pub Field` — number of shares actually used (must equal threshold)
  - The existing `ciphertext_hash`, `aggregate_pk_hash`, `decrypt_nizk_hash`, `dkg_transcript_hash` are already sufficient for session binding.
- [ ] T.1.3: Specify the extended witness list. New witnesses needed:
  - `share_evals: [Field; MAX_SHARES]` — d_i(r) for each share i (polynomial evaluation at r, one per modulus), padded to MAX_SHARES
  - `lagrange_coeffs: [Field; MAX_SHARES]` — λ_i for each share i, padded to MAX_SHARES
  - `pt_eval: Field` — plaintext_raw(r), the evaluation of the pre-scaling plaintext polynomial at r
  - Determine MAX_SHARES: set to 128 (matches NOIR_MAX_PARTICIPANTS from `full_pipeline.rs`). For benchmarks up to 8,192 participants, MAX_SHARES can be increased without changing constraint count.
- [ ] T.1.4: Specify the constraint logic:
  ```
  // 1. Lagrange identity: Σ λ_i = 1
  let lagrange_sum = fold_sum(lagrange_coeffs, n_shares);
  assert(lagrange_sum == 1);

  // 2. Share recombination: Σ λ_i · d_i(r) = pt(r)
  let mut acc = 0;
  for i in 0..n_shares {
      acc += lagrange_coeffs[i] * share_evals[i];
  }
  assert(acc == pt_eval);

  // 3. Plaintext commitment binding (existing, keep)
  let computed_pt_hash = vector_hash(nova_final_plaintext, DOMAIN_VECTOR_MERKLE);
  assert(plaintext_commitment == computed_pt_hash);

  // 4. Non-zero and range checks (existing, keep)
  ```
- [ ] T.1.5: Document the modulus-per-limb approach. Each share evaluation d_i(r) and the plaintext evaluation pt(r) are computed modulo each of the 3 RNS moduli. The constraint `Σ λ_i · d_i(r) ≡ pt(r) (mod q_j)` must hold for each modulus independently. Since Noir's Field is Fr (~254 bits) and each modulus q_j is ~58 bits, no overflow occurs. The Lagrange coefficients λ_i are small integers (for small t) and fit in a single field element.

### T.2 — Extend the Noir circuit

**Outcome**: `circuits/aggregator_final/src/main.nr` updated with C7 correctness constraints.

**Activities**:

- [ ] T.2.1: Add `challenge_r: pub Field`, `n_shares: pub Field` to the `main()` public input signature (after line 119 or 123).
- [ ] T.2.2: Add witness array inputs `share_evals: [Field; MAX_SHARES]`, `lagrange_coeffs: [Field; MAX_SHARES]`, `pt_eval: Field` (after the Nova state inputs, before the function body).
- [ ] T.2.3: Implement the `fold_sum` helper function:
  ```nor
  fn fold_sum(values: [Field; MAX_SHARES], count: Field) -> Field {
      let mut sum = 0;
      for i in 0..MAX_SHARES {
          // Only sum first `count` entries; later entries are zero-padded
          sum += values[i];
      }
      sum
  }
  ```
  Note: The loop iterates over all MAX_SHARES entries but the witness generator must zero-pad beyond `n_shares`. The non-participating entries are zero and don't affect the sum.
- [ ] T.2.4: Add Lagrange identity constraint:
  ```nor
  let lagrange_sum = fold_sum(lagrange_coeffs, MAX_SHARES);
  assert(lagrange_sum == 1, "Lagrange coefficients must sum to 1");
  ```
- [ ] T.2.5: Add share recombination constraint:
  ```nor
  let mut recombined_eval = 0;
  for i in 0..MAX_SHARES {
      recombined_eval += lagrange_coeffs[i] * share_evals[i];
  }
  assert(recombined_eval == pt_eval, "Lagrange recombination does not match plaintext evaluation");
  ```
- [ ] T.2.6: Add witness `share_evals` (per share polynomial evaluation at r) to the function signature. The caller (full_pipeline.rs) will compute `d_i(r) via Horner evaluation of each share polynomial's CRT-reconstructed Fr coefficients at `r`.
- [ ] T.2.7: Keep all existing constraints (non-zero guards, ciphertext vs plaintext hash distinction, IVC proof hash non-zero, Nova chain hash non-zero, plaintext commitment binding). Do NOT remove any existing constraint.
- [ ] T.2.8: Update the circuit docstring (lines 1-8) to reflect the new correctness constraints.
- [ ] T.2.9: Compile via `(cd circuits && nargo compile --package aggregator_final)` and record constraint count in the plan log.

### T.3 — Wire witness generation

**Outcome**: `full_pipeline.rs` `build_c7_prover_toml()` generates witnesses for the extended circuit.

**Activities**:

- [ ] T.3.1: In `run_c7_verification()` (line 3244), after computing `share_evals` (line 3272-3275), pass the evaluation results as witnesses to the Prover.toml builder.
- [ ] T.3.2: Compute `pt_eval` — the evaluation of the raw result polynomial at challenge point `r`. Use `aggregate_decrypt_raw_result_poly()` (line 1775 of fhers.rs) to get the pre-scaling polynomial, then evaluate at `r` using `eval_with_powers`.
- [ ] T.3.3: Pass `lagrange_coeffs_fr` (already computed at line 1998 of full_pipeline.rs) as witness.
- [ ] T.3.4: Pass `challenge_r` (= `c7_r`, already computed at line 2105) as public input.
- [ ] T.3.5: Pass `n_shares` (= threshold `t`, the number of Lagrange coefficients / share evaluations) as public input.
- [ ] T.3.6: Update `build_c7_prover_toml()` (around line 2371) to include the new witness fields: `share_evals`, `lagrange_coeffs`, `pt_eval`, `n_shares`, `challenge_r`.
- [ ] T.3.7: Update Prover.toml template with the new fields. The file at `circuits/aggregator_final/Prover.toml` currently has 13 lines (N=8 ring dimension). Extend to include the witness arrays.

### T.4 — RED tests (write BEFORE implementation changes)

**Outcome**: Tests in `aggregator_final/src/main.nr` that fail before the circuit extension and pass after.

**Activities**:

- [ ] T.4.1: `test_c7_honest_lagrange_recombination` — honest t=2, n=3 scenario with correct shares, correct Lagrange coefficients (e.g., λ = [2, -1] for points [1,2] eval at 0), correct plaintext. Circuit accepts.
- [ ] T.4.2: `test_c7_wrong_lagrange_sum` (should_fail) — λ coefficients sum to something other than 1. Circuit rejects.
- [ ] T.4.3: `test_c7_wrong_recombination` (should_fail) — share evaluations correct but plaintext evaluation is wrong (tampered). Circuit rejects.
- [ ] T.4.4: `test_c7_wrong_share_eval` (should_fail) — one share's d_i(r) is wrong. Circuit rejects.
- [ ] T.4.5: `test_c7_manipulated_lagrange_coeffs` (should_fail) — λ coefficients are scaled (e.g., all doubled). Lagrange sum ≠ 1. Circuit rejects.
- [ ] T.4.6: `test_c7_zero_padded_shares` — n_shares < MAX_SHARES, excess entries are zero. Circuit accepts (zero padding must not affect sum or recombination).
- [ ] T.4.7: `test_c7_plaintext_commitment_consistent` — the plaintext commitment must still match the Nova final plaintext hash. Even if recombination passes, a plaintext commitment mismatch must reject.
- [ ] T.4.8: Ensure ALL existing tests (line 147-217: `test_simplified_honest`, `test_plaintext_mismatch`, `test_ivc_hash_zero`, `test_verification_statement_v1_*`) still pass. Update `test_simplified_honest` to include the new witness fields.

### T.5 — Integration test

**Outcome**: Full end-to-end pipeline with in-circuit C7 correctness verification.

**Activities**:

- [ ] T.5.1: Run the canonical Noir+BB flow:
  ```
  (cd circuits && nargo execute --package aggregator_final --prover-name C7Prover)
  bb write_vk --scheme ultra_honk -b circuits/target/aggregator_final.json -o circuits/target
  bb prove --scheme ultra_honk -b circuits/target/aggregator_final.json -w circuits/target/aggregator_final.gz -o circuits/target
  bb verify --scheme ultra_honk -k circuits/target/vk -p circuits/target/proof -i circuits/target/public_inputs
  ```
- [ ] T.5.2: Run `just demo-e2e 5 2 1` with full C7 circuit verification. Must ACCEPT.
- [ ] T.5.3: Run `(cd circuits && nargo test --package aggregator_final)`. All tests must pass.
- [ ] T.5.4: Run `just test-all`. No regressions in Rust, Noir, or Solidity tests.
- [ ] T.5.5: Document constraint count: run `bb info` on the compiled circuit and record.

### T.6 — Documentation and plan closure

**Outcome**: All status trackers updated to reflect C7 correctness resolution.

**Activities**:

- [ ] T.6.1: In `docs/OPEN-PROBLEM-BLOCKERS.md §C7`, update status from `OPEN — production disabled` to `RESOLVED — in-circuit verification active`. Update lines 31-43 to describe the resolution.
- [ ] T.6.2: In `README.md`, update the Decrypt row from `⚠️ OPEN²` to `✅` with a note about C7 resolution.
- [ ] T.6.3: In `ARCHITECTURE.md`, update the C7 entry in the verifiability chain table.
- [ ] T.6.4: In `SECURITY.md`, update the C7 threat model entry.
- [ ] T.6.5: Remove the "deferred" note in `full_pipeline.rs` `verify_c7_plaintext_binding()` (lines 3344-3356) — replace with a note that G3 is now closed in-circuit.
- [ ] T.6.6: Append learnings to `.sisyphus/notepads/c7-correctness/learnings.md`.

---

## Acceptance Criteria

### Test vectors

All test vectors must be reproducible with deterministic seeds and documented in the test file:

| Test | Scenario | Expected |
|------|----------|----------|
| `test_c7_honest_lagrange_recombination` | t=2, honest shares, correct Lagrange λ = [2, -1] for IDs [1,2] eval at 0 | ACCEPT |
| `test_c7_wrong_lagrange_sum` | λ coefficients tampered so Σ λ_i ≠ 1 | REJECT |
| `test_c7_wrong_recombination` | pt_eval wrong (plaintext tampered) | REJECT |
| `test_c7_wrong_share_eval` | d_1(r) wrong (one share eval forged) | REJECT |
| `test_c7_manipulated_lagrange_coeffs` | λ = [4, -2] instead of [2, -1] (scaled 2x) | REJECT |
| `test_c7_zero_padded_shares` | n_shares=2, MAX_SHARES=4, excess zero | ACCEPT |
| `test_c7_plaintext_commitment_consistent` | recombination passes but commitment wrong | REJECT |
| `test_simplified_honest` | Existing test, updated with new witness fields | ACCEPT |

### Acceptance gates

- [ ] `(cd circuits && nargo test --package aggregator_final)` — all tests pass
- [ ] `just demo-e2e 5 2 1` — ACCEPT with C7 in-circuit verification
- [ ] `bb verify` returns success for the aggregator_final proof
- [ ] Constraint count documented via `bb info`
- [ ] `just test-all` — no regressions
- [ ] `cargo test --workspace` — no regressions
- [ ] `forge test --root contracts` — no regressions

---

## Out of Scope

This plan covers the **in-circuit Lagrange recombination correctness** only. The following are explicitly out of scope:

- **C7 SCALING** (N=8192): Already resolved by `c7-p3-final.md`. This plan inherits the scaled infrastructure.
- **Per-share decryption correctness** (R3 relation c1·sk_i + e_i = d_i): Verified by `decrypt_share` circuit (`circuits/decrypt_share/src/main.nr`). That is a separate trust gap, not C7.
- **Aggregate public-key formation proof** (C5): Covered by `c5-formation-proof.md` (plan H.2).
- **G4 (full in-circuit PK binding)**: Phase B.2 of `meta-plan-all-deferred.md`. Orthogonal to C7.
- **G7 (recursive NIZK verification)**: Deferred as potentially infeasible. Not related to C7.
- **Nova IVC public-input binding on-chain** (P4): Covered by `p4-onchain-ivc.md` (plan H.4).
- **Cyclo accumulator transcript verification** (A1): Covered by `a1-accumulator-transcript.md` (plan H.3).
- **Optimization** (constraint count reduction, Nova step batching): The goal is correctness first; optimization is a follow-up.
- **HonkVerifier.sol regeneration**: After the circuit changes, the VK must be regenerated and the solidity verifier redeployed. This is a deployment step, not a C7 design step.

---

## Estimated Effort

| Task | Effort |
|------|--------|
| T.1 (Design) | 0.5 day |
| T.2 (Noir circuit) | 1.0 day |
| T.3 (Witness wiring) | 1.0 day |
| T.4 (RED tests) | 0.5 day |
| T.5 (Integration) | 0.5 day |
| T.6 (Documentation) | 0.5 day |
| **Total** | **~4 days** |

---

## Cross-References

| Reference | Description |
|-----------|-------------|
| `docs/OPEN-PROBLEM-BLOCKERS.md §C7` (lines 29-45) | Canonical problem statement |
| `.sisyphus/plans/meta-plan-all-deferred.md §H.1` (lines 264-270) | Meta-plan task for C7 correctness plan creation |
| `.sisyphus/plans/meta-plan-all-deferred.md §B.1` (lines 64-67) | G3 plaintext binding (pre-scaling result polynomial API, ~3 days remaining) |
| `.sisyphus/plans/c7-p3-final.md` | C7 N=8192 scaling (DONE) |
| `.sisyphus/plans/c7-ring-aware-coefficient-check.md` | Native coefficient check (COMPLETE — native only) |
| `.sisyphus/plans/c7-nova-step-circuit.md` | Nova IVC Lagrange hash folding (COMPLETE) |
| `circuits/aggregator_final/src/main.nr` (lines 109-143) | Current circuit — hash binding only |

---

## Verification Commands

```bash
# Compile the extended circuit
(cd circuits && nargo compile --package aggregator_final)

# Run Noir tests
(cd circuits && nargo test --package aggregator_final)

# Canonical Noir+BB flow
(cd circuits && nargo execute --package aggregator_final --prover-name C7Prover)
bb write_vk --scheme ultra_honk -b circuits/target/aggregator_final.json -o circuits/target
bb prove --scheme ultra_honk -b circuits/target/aggregator_final.json -w circuits/target/aggregator_final.gz -o circuits/target
bb verify --scheme ultra_honk -k circuits/target/vk -p circuits/target/proof -i circuits/target/public_inputs

# Full pipeline
just demo-e2e 5 2 1

# All tests
just test-all
```
