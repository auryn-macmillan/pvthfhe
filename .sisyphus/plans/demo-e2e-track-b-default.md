# Plan: E2E Demo — Track B Default with Track A Flag

**Plan**: `demo-e2e-track-b-default`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-14
**Goal**: Default `demo-e2e` to Track B (LatticeFold+ / MicroNova) while retaining Track A (Sonobe Nova / hash-then-fold) behind `--track A` flag. No regression in Track A behavior.

---

## Design

### Flag mechanism

- Default: Track B (`just demo-e2e` → Track B)
- Track A: `PVTHFHE_TRACK=A just demo-e2e` or `cargo run -- demo --track A`
- Track B explicit: `PVTHFHE_TRACK=B` (same as default)
- Feature-gated: Track B components only compile with `pipeline-extra-checks` (already enabled in demo-e2e)
- The flag is an env var `PVTHFHE_TRACK` (default `B`), checked at runtime

### What changes per track

| Component | Track A (current) | Track B (new default) |
|-----------|-------------------|----------------------|
| DKG folding | `CycloFoldStepCircuit` (hash-then-fold) | R1CS ring equation verifier in `generate_step_constraints` |
| Ajtai commitment | `pvthfhe-cyclo::ajtai` | `AjtaiMatrix` from `pvthfhe-aggregator::folding` |
| C7 aggregation | `C7DecryptAggregationCircuit` | `C7DecryptAggregationCircuit` (unchanged) |
| C7 in-circuit Merkle | `C7MerkleStepCircuit` (opt-in) | Available via `PVTHFHE_RUN_C7_MERKLE=1` |

---

## Implementation

### D.1 — Track flag plumbing

**File**: `crates/pvthfhe-cli/src/full_pipeline.rs`

- Read `PVTHFHE_TRACK` env var, default `B`
- Thread `track: Track` through pipeline context
- `Track::A` → existing code paths
- `Track::B` → new code paths (feature-gated)

### D.2 — Track B: R1CS compressor step

**File**: `crates/pvthfhe-compressor/src/sonobe/mod.rs` (CycloFoldStepCircuit)

Replace the placeholder comment with actual R1CS ring equation verification in `generate_step_constraints` for Track B. Key design:

- The step circuit state grows from 4 to 5: `[hash, norm, fold_count, ring_passed, challenge]`
- External inputs carry ring-encoded data (z_s, z_e, t, d as Fr vectors), plus challenge
- For N=256 ring elements: each external input needs 256 Fr elements → too wide for ExternalInputs3
- **Solution**: Encode ring elements as Merkle-tree-hashed digests (32 bytes each), passed as 4 external inputs + challenge through ExternalInputs3 (3 Fr elements) plus an encoded state slot
- OR: Use a wider external input type (ExternalInputsN for N=4+256=260 → not practical)
- OR: Use hashed ring elements (Poseidon hash of coefficients) as external inputs, verify ring equation off-circuit before hashing — **this is the hash-and-verify approach**: hash the ring elements first (like Track A), but also verify the native ring equation before entering the hash

**Recommended for M6**: Hash-and-verify approach. The ring equation IS verified natively (off-circuit) before hashing. The Nova circuit folds the hashes. This is: Track A's hashing + Track B's ring verification as a pre-step. The hashing makes the circuit feasible (3 inputs), the native verification adds the ring equation check.

```rust
fn generate_step_constraints(..., track: Track) -> Vec<FpVar<F>> {
    match track {
        Track::A => { /* existing hash-accumulate */ }
        Track::B => {
            // Ring equation verified natively before entering constraints
            // (via verify_ring_equation_native called in prove_step)
            // Circuit folds the hash of the verified state
            hash_accumulate(cs, i, z_i, external_inputs)
        }
    }
}
```

### D.3 — Track B: Ajtai commitment switch

**File**: `crates/pvthfhe-cli/src/full_pipeline.rs`

Replace `pvthfhe-cyclo::ajtai::commit` with `pvthfhe-aggregator::folding::ajtai::AjtaiMatrix::commit` for Track B. The AjtaiMatrix is deterministic from epoch, so the commitment is reproducible.

### D.4 — Track B: Norm enforcement in DKG

**File**: `crates/pvthfhe-cli/src/full_pipeline.rs`

In the DKG step, for Track B: call `validate_folding_witness` on each party's witness before folding. This enforces coefficient norm bounds.

### D.5 — Feature toggle in Justfile

**File**: `Justfile`

- `demo-e2e` recipe: add `PVTHFHE_TRACK=B` env var (or default via code)
- Add `demo-e2e-track-a` recipe: `PVTHFHE_TRACK=A just demo-e2e`
- Track B already requires `pipeline-extra-checks` feature

### D.6 — Tests

| Test | Description |
|------|-------------|
| `demo_track_a_produces_same_output` | Track A with flag → identical to current demo |
| `demo_track_b_completes_successfully` | Track B → ACCEPT |
| `track_b_norm_enforcement_rejects_large_witness` | Large witness in B → rejected |
| `track_b_ajtai_differs_from_track_a` | Ajtai commitment B ≠ A (different matrices) |

### D.7 — Documentation

- Update `ARCHITECTURE.md`: Track A/B flag documentation
- Update `paper/main.tex`: Track B default status
- Update `SECURITY.md`: Track B assumptions

---

## Acceptance Criteria

- [ ] `just demo-e2e` defaults to Track B
- [ ] `PVTHFHE_TRACK=A just demo-e2e` runs Track A (identical to current)
- [ ] Track B ACCEPT
- [ ] Track A ACCEPT (no regression)
- [ ] 4 tests pass
- [ ] Norm enforcement active in Track B

## Non-Goals

- Replacing the entire DKG pipeline with Track B (AjaiMatrix substitution only)
- On-chain UltraHonk verification (P3-M3, deferred)
- Full R1CS ring equation in constraints (hybrid hash-and-verify for M6)

## Estimated Effort

~1-2 weeks. The flag plumbing and Ajtai substitution are straightforward. The R1CS compressor step design (hash-and-verify) avoids the complexity of full ring-element circuit integration.
