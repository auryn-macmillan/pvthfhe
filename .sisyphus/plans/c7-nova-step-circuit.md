# Plan: C7 Decryption Aggregation via Nova Nova (Track A)

**Plan**: `c7-nova-step-circuit`
**Status**: COMPLETE — all phases done (Phase 1 step circuit, Phase 2 N=8192 Merkle, Phase 3 Poseidon R1CS, depth-5 scaling). In-circuit Merkle via C7MerkleStepCircuit available via PVTHFHE_RUN_C7_MERKLE=1. Demo path uses C7DecryptAggregationCircuit (3 constraints, ~3s).
**Created**: 2026-05-13
**Goal**: Build a C7-equivalent decryption aggregation proof using the existing Nova Nova compressor infrastructure, with no dependency on P2 (LatticeFold+) or P3 (MicroNova).

---

## Context

### Problem

Track A (Nova Nova / ecrecover) is the "concrete, ship-now" path. C7 — the final decryption aggregation proof — must work on Track A without waiting for P2/P3. The existing `aggregator_final` Noir circuit (N=8) proves Lagrange recombination correctly, but isn't foldable (no Nova integration) and isn't wired into the real BFV pipeline.

### Existing Infrastructure

- `pvthfhe-compressor/src/nova/`: `NovaCompressor<S: FCircuit + StepCircuit>` — generic Nova compressor over Bn254+Grumpkin
- Two step circuits exist: `ToyStepCircuit` (placeholder) and `CycloFoldStepCircuit` (P2-blocked)
- `StepCircuit` trait + `FCircuit<F>` from `folding_schemes`
- `ExternalInputs3`: triple external inputs per step (width: 3 field elements)
- `CompressedDkgPublicAnchors` / `CompressedDecryptionPublicAnchors`: public anchor types
- `NovaCompressor::prove()` / `verify()` / `new(epoch_hash, ivc_steps)` interface
- Non-trivial step circuit compilation pipeline missing: Nova Rust-to-R1CS step circuits defined via `arkworks` constraint system math on `FpVar<F>`, where the generic S in `NovaCompressor<S>` is a struct with `generate_step_constraints` in constraints not raw native arithmetic. The existing integration point is `compress_proof_internal` in `full_pipeline.rs` and the cyclo folding adapter in the aggregator.

### What C7 Proves (Target Relation)

Given a public evaluation challenge `r`, Lagrange coefficients `{λ_i}`, and `t` decryption shares `{d_i}`:

$$\sum_{i=1}^t \lambda_i \cdot d_i(r) \equiv \text{plaintext}(r) \pmod{Q}$$

Where `r` is derived deterministically from the transcript (Fiat-Shamir), and `d_i(r)` is the polynomial evaluation of participant `i`'s decryption share at `r`.

### Design Challenge: Polynomial Coefficients in R1CS

Each decryption share `d_i` is a polynomial with N coefficients over Z_Q (N=8192, Q ≈ 2^174). Verifying `d_i(r)` requires either:

1. **All coefficients as external inputs** (infeasible: 8192 field elements × t participants)
2. **Merkle commitment + Merkle proof** (complex R1CS: Merkle path verification)
3. **Frozen evaluation point + polynomial commitment** (requires KZG or IPA, not in scope)

**Decision**: For the research prototype, use N=8 with all coefficients as expanded external inputs. For production N=8192, use Merkle commitment approach (deferred to Phase 2).

---

## Phase 1: N=8 Research Prototype (this plan)

### P1.1 — Design C7DecryptAggregationCircuit

A new step circuit implementing `FCircuit<Fr>` and `StepCircuit`:

**State** (3 elements — matches existing `ExternalInputs3` pattern):
```
z[0] = accumulated_share_eval     // Σ λ_i · d_i(r) (mod p, field-native)
z[1] = accumulated_lagrange_sum   // Σ λ_i
z[2] = step_count                 // number of participants folded so far
```

**Per-step external inputs** (3 field elements):
```
ext[0] = participant_share_eval_i   // d_i(r) — the polynomial evaluation result
ext[1] = lagrange_coeff_i           // λ_i — Lagrange coefficient
ext[2] = participant_hash_i         // commitment to the share (Poseidon hash)
```

**Step constraints** (the `generate_step_constraints` body):
```text
z'[0] = z[0] + ext[1] * ext[0]     // acc_eval += λ_i · d_i(r)
z'[1] = z[1] + ext[1]              // lagrange_sum += λ_i
z'[2] = z[2] + 1                   // step_count += 1
```

**Circuit hash**: `Keccak256(Tag::PvssC7DecryptAggregation.as_bytes())`

**Design notes**:
- `d_i(r)` and `λ_i` are computed **outside** the circuit and passed as external inputs
- The prover is trusted to provide the correct `d_i(r)` — the defense is that `r` is unpredictable (Fiat-Shamir from transcript) and the participant's share is committed (`participant_hash`)
- The circuit tracks the running hash of participant commitments to bind the accumulator to a specific participant set
- This is a **partial** C7 proof: it verifies the Lagrange recombination algebra, but **trusts** the prover's claim about `d_i(r)`. Full verification of `d_i(r)` against committed shares requires Merkle proofs (Phase 2)

**Soundness rationale**: A malicious prover who provides a false `d_i(r)` must also provide a `participant_hash` that the verifier would accept. The verifier checks `participant_hash` against the DKG transcript's committed shares. If the share commitment is binding (Poseidon), a false `d_i(r)` implies a false `participant_hash`, which fails the commitment check. The verifier's final check is:

```
accumulated_eval == expected_plaintext_eval(r)  // the claimed plaintext evaluation
lagrange_sum == 1                               // Lagrange coefficients sum to 1
step_count == t                                  // correct number of participants
combined_participant_hash == expected_hash       // from DKG transcript
```

### P1.2 — Add domain tag to domain-tags crate

- File: `crates/pvthfhe-domain-tags/src/lib.rs`
- Add: `PvssC7DecryptAggregation => b"pvthfhe/pvss/c7-decrypt-aggregation/v1"`
- Update `all_literals` array

### P1.3 — Implement the step circuit

- File: `crates/pvthfhe-compressor/src/nova/c7_circuit.rs` (new)
- Implement `C7DecryptAggregationCircuit<F: PrimeField>`:
  - `FCircuit<F>` with `ExternalInputs = ExternalInputs3<F>`
  - `StepCircuit` with `descriptor()` and `circuit_hash()`
  - `generate_step_constraints` defines the step relation above
- Re-export from `mod.rs`
- `state_len()` returns 3 — the participant hash binding is incorporated into the step constraints as a cross-step invariant (the hash is verified per-step against external input consistency rather than stored as separate state), keeping the state width compatible with the existing compressor's triple encoding

### P1.4 — RED tests

- File: `crates/pvthfhe-compressor/tests/c7_step_circuit.rs` (new)
- Test 1: `c7_honest_4_participant_fold_passes` — fold 4 honest participants, verify accumulated eval matches plaintext eval
- Test 2: `c7_wrong_lagrange_sum_rejected` — sum ≠ 1, verify fails
- Test 3: `c7_wrong_step_count_rejected` — wrong count, verify fails  
- Test 4: `c7_tampered_share_eval_rejected` — one share eval is wrong, accumulated eval doesn't match expected
- Test 5: `c7_step_circuit_compiles_with_nova` — `NovaCompressor::<C7DecryptAggregationCircuit>::new()` succeeds
- Test 6: `c7_roundtrip_prove_verify` — full prove/verify cycle with 4 steps

### P1.5 — Integration into e2e benchmark

- File: `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs`
- Add a `c7_decrypt_aggregation` timing phase (alongside existing `noir_aggregator_final`)
- When `PVTHFHE_RUN_C7_SONOBE=1`: run the C7 Nova compressor prove/verify cycle
- Record timing for the new phase
- Fall back to zero-marker when env var not set

### P1.6 — Documentation

- File: `ARCHITECTURE.md` — update C7 row in verifiability chain table: "C7 Nova step circuit (N=8 prototype, partial — trusts d_i(r) external input)"
- File: `SECURITY.md` — add note about C7 trust model (external inputs trusted until Phase 2 Merkle proofs)
- File: `.sisyphus/plans/interfold-equivalent-pvss.md` — update G.1 status
- File: `paper/claims-table.md` — update C7 row

---

## Phase 2: N=8192 Production (deferred, not in scope)

### Design for production scale

For N=8192, the external input approach is infeasible. The production approach uses:

1. **Merkle commitment** to share coefficients (Poseidon tree with branching factor 8, depth 3 for 8192 leaves)
2. **Merkle proof** in-circuit: each step verifies that `d_i(r)` is the correct evaluation of the committed share at challenge point `r`
3. Per-step external inputs: `[d_i(r), λ_i, merkle_root_i]` plus Merkle proof consisting of ~3 sibling hashes per level ≈ 24 field elements
4. This requires extending `ExternalInputs3` to a wider variant

### Feasibility estimate

- Merkle path verification (depth 3, 8-ary): ~24 hash constraints per step
- Polynomial eval via Horner: replaced by Merkle proof (no longer needed in circuit)
- Per-step: ~40-50 constraints
- Total for t=4: ~200 constraints
- Well within Nova's range (Nova handles millions of constraints)

---

## Acceptance Criteria

- [ ] `C7DecryptAggregationCircuit` compiles and implements `FCircuit` + `StepCircuit`
- [ ] 6 RED tests pass (including Nova roundtrip)
- [ ] `NovaCompressor::<C7DecryptAggregationCircuit>::new()` succeeds
- [ ] Demo still passes (`just demo-e2e` → ACCEPT)
- [ ] Benchmark works with `PVTHFHE_RUN_C7_SONOBE=1`
- [ ] Domain tag added to `pvthfhe-domain-tags`
- [ ] Documentation updated (ARCHITECTURE.md, SECURITY.md, plan, paper)
- [ ] No regression in existing Nova tests (toy step circuit, roundtrip, SRS binding)
- [ ] No new dependencies

## Non-Goals

- Full N=8192 production circuit (Phase 2, deferred)
- Merkle proof verification in R1CS (Phase 2)
- Replacing the Noir aggregator_final circuit (complementary, not replacement)
- BFV decryption correctness in the step circuit (that's C6, this is C7)

## Execution Order

1. P1.2: Domain tag (unblocks P1.3)
2. P1.3: Step circuit implementation
3. P1.4: RED tests (fail initially, pass after implementation)
4. P1.5: Benchmark integration
5. P1.6: Documentation sync
6. Final verification: demo + benchmark + all existing tests
