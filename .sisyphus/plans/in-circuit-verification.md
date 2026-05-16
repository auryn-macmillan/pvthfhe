# Plan: Comprehensive In-Circuit Verification — Close All Trust Gaps

**Plan**: `in-circuit-verification`
**Status**: DRAFT
**Created**: 2026-05-16
**Goal**: Move ALL verification into R1CS constraints. No trusted external inputs. The Nova proof itself proves every claim.

---

## Trust Gap Inventory

| ID | Gap | What's trusted | Where | Impact |
|----|-----|---------------|-------|--------|
| **G1** | Ring equation not in circuit | `ext.2` (ring result) — prover can set to 1 even when equation fails | `CycloFoldStepCircuit::generate_step_constraints` | Critical |
| **G2** | C7 share evaluation not in circuit | `ext.0 = d_i(r)` — prover can claim any evaluation | `C7DecryptAggregationCircuit::generate_step_constraints` | Critical |
| **G3** | Plaintext not bound to C7 accumulator | No check that `Σ λ_i·d_i(r) = plaintext(r)` | Post-Nova verification | High |
| **G4** | Aggregate PK not bound in C7 | `agg_pk_hash` is external input, circuit doesn't verify derivation | C7 external inputs | High |
| **G5** | Merkle leaf_index constrained to 0 | Position-aware Merkle verification missing | `C7MerkleStepCircuit` | Medium |
| **G6** | Compressor hash only | Nova proves hash consistency, not lattice relation | `CycloFoldStepCircuit` | Medium |

---

## Fix Strategy

### G1: Ring equation in circuit (~3 days)

Ternary challenge c ∈ {-1,0,1} means ZERO R1CS multiplications. At N=256 ring dimension, each step needs 256 `enforce_equal` calls. The fix: widen external inputs to carry ring coefficients (or their Poseidon hashes) and verify the ring equation directly.

| Task | Files | Effort |
|------|-------|--------|
| G1.1 | Widen `ExternalInputs3` to carry 4 Poseidon hashes (z_s, z_e, t, d) + challenge = 5 Fr values. The hashes bind the ring coefficients but don't verify the equation. Need actual coefficients in circuit. | `mod.rs:62-77` | 1 day |
| G1.2 | Add ring coefficients as **private witnesses** (not external inputs). The prover provides the coefficients; the circuit hashes them and verifies against the public hashes, then verifies the ring equation. | `mod.rs:191-204` | 1 day |
| G1.3 | 4 RED tests: honest equation passes, wrong z_s fails, wrong challenge fails, tampered hash fails | Tests | 1 day |

**Design**: External inputs carry 4 Poseidon hashes + 1 challenge. The circuit receives 1024 private witnesses (4 ring elements × 256 coefficients). For each ring element, the circuit hashes the 256 private witnesses with `PoseidonSpongeVar::hash256` and enforces equality with the public hash. Then: if c=1, enforce `zs[k]+ze[k] == t[k]+d[k]` for all k. If c=-1, enforce `d[k]+ze[k] == t[k]+zs[k]`. If c=0, enforce `ze[k] == t[k]`.

### G2: Share evaluation in C7 circuit (~5 days)

Each share has 8192 coefficients. Verifying `d_i(r) = Σ coeff[j] × r^j` in R1CS requires either:
- All 8192 coefficients as private witnesses (heavy but doable)
- Merkle commitment + Merkle opening at position r (efficient but complex)

**Design**: Encode each share as a Merkle tree of 8192 leaves (already built in Phase 2). Pass the Merkle root + leaf index as external inputs. The prover provides the 8192 coefficients as private witnesses. The circuit verifies: `evaluation = Σ coeff[j] × r^j` AND `Merkle root of coeffs == share_commitment`.

Actually simpler: since the evaluation is done with Horner's method, we need all 8192 coefficients in the circuit. Each step folds one share. With 8192 coefficients × t steps = 933K constraints at t=114 — well within Nova's range.

| Task | Files | Effort |
|------|-------|--------|
| G2.1 | Pass share coefficients as private witnesses to `C7DecryptAggregationCircuit` — 8192 Fr per step | `c7_circuit.rs:53-69` | 1 day |
| G2.2 | Add Horner evaluation in R1CS: `eval = Σ coeff[j] × r^j` using precomputed r^j powers | `c7_circuit.rs` | 1 day |
| G2.3 | Verify that `ext.0 == computed_eval` — close the gap between claimed evaluation and actual share coefficients | `c7_circuit.rs` | 0.5 day |
| G2.4 | 4 RED tests: honest eval matches, wrong coeffs fail, wrong eval fails, batch works | Tests | 2 days |
| G2.5 | Performance benchmark: t=114 with 8192 coeffs per step, measure Nova prove time | Manual | 0.5 day |

### G3: Plaintext binding in C7 (~1 day)

After all t Nova steps, the accumulator `z[0]` contains `Σ λ_i × d_i(r)`. The verifier needs `z[0] == plaintext(r)` where `plaintext(r)` is also evaluated in R1CS.

| Task | Files | Effort |
|------|-------|--------|
| G3.1 | Add plaintext coefficients (8192) as private witnesses to C7 after folding completes | `c7_circuit.rs` | 0.5 day |
| G3.2 | Compute `plaintext(r)` in R1CS and enforce equality with final accumulator `z[0]` | `c7_circuit.rs` | 0.5 day |

### G4: Aggregate PK binding (~0.5 day)

Pass the DKG root hash as an external input. The circuit verifies it matches the expected value from the state statement.

| Task | Files | Effort |
|------|-------|--------|
| G4.1 | Add `dkg_root_hash` to C7 external inputs (4th element, widen to ExternalInputs4) | `c7_circuit.rs`, `mod.rs` | 0.5 day |
| G4.2 | Verify `dkg_root_hash == expected_dkg_root` via enforce_equal | `c7_circuit.rs` | 0.25 day |

### G5: Position-aware Merkle (~2 days)

The `C7MerkleStepCircuit` currently constrains `leaf_index == 0`. Full position-aware Merkle requires walking the index through tree levels.

| Task | Files | Effort |
|------|-------|--------|
| G5.1 | In `verify_merkle_path`, use `leaf_index % arity` to correctly place the leaf value among siblings | `c7_merkle_circuit.rs:129-162` | 1 day |
| G5.2 | Propagate `leaf_index = leaf_index / arity` through each tree level | `c7_merkle_circuit.rs` | 0.5 day |
| G5.3 | 2 RED tests: non-zero leaf_index passes, wrong leaf_index fails | Tests | 0.5 day |

---

## Acceptance Criteria

- [ ] Ring equation verified in Nova circuit (not just counter)
- [ ] C7 share evaluation computed in R1CS from coefficients
- [ ] Plaintext evaluation matches C7 accumulator in R1CS
- [ ] Aggregate PK bound to DKG root in C7 circuit
- [ ] Merkle verification supports arbitrary leaf_index
- [ ] All 14 RED tests pass
- [ ] Demo ACCEPT
- [ ] Per-node + per-aggregator produce output

## Execution Order

G1 (foundation) → G2+G3 (C7) → G4 (binding) → G5 (Merkle)

G1 and G4+G5 can run in parallel. G2+G3 require G1 (ring element private witness pattern established).

## Estimated Total Effort

~2-3 weeks. G1: 3 days. G2+G3: 6 days. G4: 0.5 days. G5: 2 days. Tests + integration: 3 days.
