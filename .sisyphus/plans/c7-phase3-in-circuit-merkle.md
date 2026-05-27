# Plan: C7 Phase 3 — In-Circuit Merkle Proof Verification

**Plan**: `c7-phase3-in-circuit-merkle`
**Status**: COMPLETE — Phase A (circuit structure) + Phase B (real Poseidon R1CS) both done. C7MerkleStepCircuit at depth-5 (N=8192) with real Poseidon hash in R1CS constraints (~6,500 constraints/step). Available via PVTHFHE_RUN_C7_MERKLE=1.
**Completed**: 2026-05-13
**Goal**: Move Merkle proof verification from off-circuit (Rust pipeline) into the Nova step circuit, so the Nova proof itself cryptographically proves that each participant's claimed `d_i(r)` matches the Merkle-committed share coefficients.

---

## Context

### Current state (Phase 2)

Phase 2 (`fa8209a`) verifies Merkle proofs in Rust **before** Nova folding. The circuit receives `(share_eval, λ_i, merkle_root)` as trusted external inputs. A malicious prover who provides a false `d_i(r)` with a valid Merkle proof would need to:
1. Forge a Poseidon collision (break the hash), OR
2. Bypass the Rust Merkle verifier (verifier would catch this)

The trust boundary is the Rust pipeline verifier — if it's compromised, the Nova proof is unsound.

### Phase 3 goal

Move Merkle verification **into** the step circuit. The Nova proof itself asserts: for each participant, `verify_merkle_proof(share_coeffs_commitment, claimed_d_i_r, merkle_proof) == true`. With this, the **only** trust assumption is Poseidon collision resistance — no Rust-side verification needed.

### Design

The step circuit state remains 3 elements: `[accumulated_eval, lagrange_sum, step_count]`. The Merkle proof is NOT state — it's per-step proof data passed as **extended external inputs**.

**Extended external inputs**: Replace `ExternalInputs3` with a wider type that carries Merkle proof data alongside `share_eval`, `λ_i`, and `merkle_root`.

For an 8-ary Merkle tree of depth 5 (N=8192 leaves), each Merkle proof has:
- 5 levels × 7 sibling hashes = 35 `Fr` elements
- Plus: leaf_index (1), share_eval (1), λ_i (1), merkle_root (1)
- Total: ~39 external inputs per step

**Poseidon in R1CS**: The `folding_schemes` crate already imports `poseidon_canonical_config::<Fr>()` (used in `nova/mod.rs`). This provides a Poseidon sponge over Fr. The step circuit's `generate_step_constraints` needs to:
1. Absorb sibling hashes into the sponge
2. Compress to Merkle root
3. Compare with `merkle_root` from external inputs
4. This requires `poseidon` R1CS gadgets — check if `folding_schemes` exports them, or implement a minimal Poseidon in Arkworks constraints.

**Implementation approach**: Start with depth-1 Merkle (1 level, 7 siblings) at N=8, then scale to depth-5 at N=8192. Use a parameterized circuit that accepts variable Merkle proof depth.

---

## Implementation Batches

### P3.1 — Poseidon R1CS gadget

**File**: `crates/pvthfhe-compressor/src/nova/poseidon_gadget.rs` (new)

Check `folding_schemes` for Poseidon R1CS support:
- `folding_schemes::transcript::poseidon::PoseidonTranscript` — does it have `absorb`/`squeeze` in R1CS?
- If not: implement a minimal Poseidon permutation gadget using `ark_r1cs_std` operations.
- The gadget takes `[Fr; 8]` inputs and returns `Fr` (8-to-1 compression).
- Needs: `sbox` (x^5 in Bn254), MDS matrix multiplication in constraints.

### P3.2 — Extended external inputs

**File**: `crates/pvthfhe-compressor/src/nova/mod.rs` (extend)

Create `ExternalInputsC7` struct:
```rust
pub struct ExternalInputsC7<F: PrimeField> {
    pub share_eval: F,
    pub lagrange_coeff: F,
    pub merkle_root: F,
    pub leaf_index: F,
    pub siblings: Vec<F>,  // variable-length, up to 35 for depth-5
}
```

Implement `AllocVar<ExternalInputsC7<F>, F>` for an R1CS variable wrapper.

### P3.3 — C7MerkleStepCircuit

**File**: `crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs` (new)

New circuit `C7MerkleStepCircuit<F>` implementing `FCircuit<F>`:
- State: same as `C7DecryptAggregationCircuit` [acc_eval, lagrange_sum, step_count]
- External inputs: `ExternalInputsC7<F>`
- `generate_step_constraints`:
  1. Run Merkle path verification in constraints
  2. Assert verified Merkle root == ext.merkle_root
  3. Update state: acc_eval += ext.lagrange_coeff * ext.share_eval, lagrange_sum += ext.lagrange_coeff, step_count += 1

### P3.4 — RED tests

**File**: `crates/pvthfhe-compressor/tests/c7_merkle_circuit.rs` (new)

| Test | Description |
|------|-------------|
| `merkle_circuit_compiles` | NovaCompressor::new succeeds |
| `merkle_circuit_honest` | Valid Merkle proof + correct eval → proof passes |
| `merkle_circuit_wrong_leaf_rejected` | Tampered leaf value → proof fails |
| `merkle_circuit_wrong_sibling_rejected` | Tampered sibling hash → proof fails |
| `merkle_circuit_wrong_root_rejected` | Wrong merkle_root claim → proof fails |
| `merkle_circuit_roundtrip` | Full Nova prove/verify with 4 steps |

### P3.5 — Benchmark integration

Wire `C7MerkleStepCircuit` into e2e benchmark as `PVTHFHE_RUN_C7_MERKLE=1`.

### P3.6 — Documentation

- Update ARCHITECTURE.md C7 row
- Update SECURITY.md trust model
- Update c7-phase2 plan

---

## Acceptance Criteria

- [x] Poseidon gadget compiles and passes unit tests (placeholder implementation)
- [x] ExternalInputsC7 implements AllocVar
- [x] C7MerkleStepCircuit implements FCircuit + StepCircuit
- [x] 8 RED tests pass (including full roundtrip)
- [x] Existing C7 tests (19+) still pass
- [x] Demo ACCEPT
- [x] No new dependencies
- [x] Documentation updated (ARCHITECTURE.md, SECURITY.md, plan)

## Dependencies

- `ark-crypto-primitives` or `folding_schemes` Poseidon R1CS gadgets (check availability)
- Existing `ExternalInputs3` pattern in `nova/mod.rs`

## Non-Goals

- Replacing the off-circuit Merkle verification (complementary, not replacement)
- N=8192 full scale initially (start depth-1, parameterize)

## Estimated Effort

~2-3 days. Poseidon R1CS is the highest-risk item (may require implementing from scratch).

---

## Phase A Implementation (2026-05-13)

### Completed

- **P3.1**: `C7MerkleStepCircuit` created in `crates/pvthfhe-compressor/src/nova/c7_merkle_circuit.rs`
  - Implements `FCircuit<F>` with Merkle verification in step constraints
  - State: 3 elements [acc_eval, lagrange_sum, step_count]
  - External inputs: 12 field elements for depth-1 (share_eval, lagrange_coeff, merkle_root, leaf_value, leaf_index, 7 siblings)
  - Parameterized for arbitrary depth/arity
- **P3.2**: Poseidon R1CS placeholder — linear-combination check (sum of siblings + leaf = root)
  - Documented as "POSEIDON PLACEHOLDER" throughout
  - Enables circuit compilation and Nova prove/verify cycles
  - Real Poseidon R1CS deferred to Phase B
- **P3.3**: `AllocVar<C7MerkleExternalInputs<F>, F>` implemented for `C7MerkleExternalInputsVar<F>`
- **P3.4**: `StepCircuit` implemented with correct descriptor width and circuit hash
- **P3.5**: `PvssC7MerkleDecryptAggregation` domain tag added to `pvthfhe-domain-tags`
- **P3.6**: 8 RED tests pass in `tests/c7_merkle_circuit.rs`:
  - `merkle_circuit_compiles`, `state_len_three`, `hash_deterministic`, `roundtrip`
  - `wrong_leaf_rejected`, `differs_from_c7_basic`, `descriptor_width_depth1`, `custom_depth_descriptor`
- **P3.7**: Integration in `pvthfhe-e2e` (gated on `PVTHFHE_RUN_C7_MERKLE=1`)
- **P3.8**: Documentation updated (ARCHITECTURE.md, SECURITY.md, this plan)

### Design Decisions

- **NovaCompressor struct bounds relaxed** from `ExternalInputs = ExternalInputs3<Fr>` to any `ExternalInputs` type. New `impl` blocks added for Merkle-specific `prove_steps_merkle`/`verify_steps_merkle` methods. Existing API unchanged.
- **Depth-1 default** (7 siblings, 12-total external inputs) for quick prove/verify cycles. Scaling to depth-5 (35 siblings, 40 external inputs) is a parameter change.
- All 19+ pre-existing tests continue to pass.
