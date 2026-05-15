# Plan: Heterogeneous IVC (MicroNova) in Sonobe Fork

**Plan**: `micronova-heterogeneous-ivc`
**Status**: COMPLETE
**Created**: 2026-05-14
**Goal**: Implement heterogeneous incremental verifiable computation in our sonobe fork, enabling MicroNova-style folding where each step can use a different circuit from a circuit family.

---

## Design

### Key insight: FCircuit already has `i: usize`

The existing `FCircuit::generate_step_constraints` receives the step index `i`. Each step CAN already have different constraints — the method just needs to dispatch on `i`. The only missing piece: the verifier must know which circuit variant was used at each step.

### Circuit family

For the LatticeFold+ tree with depth `d`:

```
Level 0 (leaves):     P1VerifierCircuit    — verify ring equation c·z_s + z_e - t - c·d ≡ 0
Levels 1..d-1 (internal): FoldVerifierCircuit   — verify two children fold correctly
Level d (root):      TerminalVerifierCircuit — verify final accumulator
```

All circuits share:
- `state_len = 3` ([hash, norm, fold_count])
- External inputs width = 3 (encoded as `ExternalInputs3<Fr>`)
- Same BN254/Grumpkin curve cycle

### Heterogeneous FCircuit trait

Extend the existing `FCircuit` with a `circuit_index_for_step` method:

```rust
pub trait HeterogeneousCircuitFamily<F: PrimeField>: Debug {
    /// Number of distinct circuits in the family.
    fn num_circuits(&self) -> usize;
    
    /// Which circuit handles step `i`.
    fn circuit_index_for_step(&self, i: usize) -> usize;
    
    /// Circuit hash for circuit `idx` (for verifier key).
    fn circuit_hash(&self, idx: usize) -> [u8; 32];
    
    /// Generate constraints for step `i` using circuit `circuit_index_for_step(i)`.
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        circuit_idx: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: ExternalInputs3Var<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}
```

For backward compatibility, a single-circuit wrapper implements `FCircuit` by delegating to `generate_step_constraints` with `circuit_idx = 0`.

### MicroNovaCompressor

Wraps multiple `SonobeCompressor` instances, one per circuit in the family:

```rust
pub struct MicroNovaCompressor<F: PrimeField, CF: HeterogeneousCircuitFamily<F>> {
    pub circuit_family: CF,
    pub compressors: Vec<SonobeCompressor<SingleCircuitWrapper<F, CF>>>,
    pub depth: usize,
    pub leaf_count: usize,
}
```

Prover: folds bottom-up through the tree, dispatching each step to the correct compressor.
Verifier: checks each step against the correct verifier key.

---

## Implementation Batches

### MN.1 — HeterogeneousCircuitFamily trait

**File**: `crates/pvthfhe-compressor/src/sonobe/heterogeneous.rs` (new)

Define the trait and a single-circuit adapter that implements the existing `FCircuit`.

### MN.2 — LatticeFoldTreeCircuitFamily

**File**: `crates/pvthfhe-compressor/src/sonobe/latticefold_circuit_family.rs` (new)

Implement `HeterogeneousCircuitFamily` for the 3-level LatticeFold+ tree:

```rust
pub struct LatticeFoldTreeCircuitFamily {
    pub depth: usize,
}

impl<F: PrimeField> HeterogeneousCircuitFamily<F> for LatticeFoldTreeCircuitFamily {
    fn num_circuits(&self) -> usize { 2.min(self.depth) }
    
    fn circuit_index_for_step(&self, i: usize) -> usize {
        // Leaves use circuit 0, internal + root use circuit 1
        if i < self.leaf_count() { 0 } else { 1 }
    }
    
    fn generate_step_constraints(...) -> Vec<FpVar<F>> {
        match circuit_idx {
            0 => P1VerifierCircuit::generate(...),  // ring equation
            _ => FoldVerifierCircuit::generate(...),  // fold verify
        }
    }
}
```

### MN.3 — MicroNovaCompressor

**File**: `crates/pvthfhe-compressor/src/micronova/compressor.rs` (extend existing `micronova/` module)

Replace the stub `CompressionTree` with real MicroNova folding:

```rust
impl MicroNovaCompressor {
    pub fn new(circuit_family: impl HeterogeneousCircuitFamily<Fr>, depth: usize) -> Self;
    
    /// Fold a full tree from leaves to root.
    pub fn prove_tree(&self, leaf_data: &[ExternalInputs3<Fr>]) -> Result<CompressedProof>;
    
    /// Verify a folded tree proof.
    pub fn verify_tree(&self, proof: &CompressedProof, leaf_data: &[ExternalInputs3<Fr>]) -> Result<bool>;
}
```

### MN.4 — Tests

**File**: `crates/pvthfhe-compressor/tests/micronova_heterogeneous.rs` (new)

| Test | Description |
|------|-------------|
| `heterogeneous_circuit_family_count` | num_circuits matches depth |
| `heterogeneous_2_level_tree_folds` | 4 leaves → 2 parents → 1 root (3 levels, 2 circuits) |
| `heterogeneous_leaf_vs_internal_differ` | Leaf constraints ≠ internal constraints |
| `heterogeneous_folds_verify_with_nova` | Full prove/verify cycle |
| `heterogeneous_depth_4_tree` | 16 leaves → 8 → 4 → 2 → 1 (5 levels) |

### MN.5 — Integration with demo-e2e ✅ DONE

**File**: `crates/pvthfhe-cli/src/full_pipeline.rs`

Enable MicroNova via `PVTHFHE_COMPRESSOR=micronova` env var:

```rust
match std::env::var("PVTHFHE_COMPRESSOR").as_deref() {
    Ok("micronova") => {
        // Use MicroNovaCompressor with LatticeFoldTreeCircuitFamily
    }
    _ => {
        // Use existing SonobeCompressor with CycloFoldStepCircuit (Track A/B)
    }
}
```

### MN.6 — Documentation ✅ DONE

- [x] Update `ARCHITECTURE.md`: MicroNova compressor status
- [x] Add `docs/security-proofs/p3/heterogeneous-ivc.md`: soundness argument
- [ ] Update `p3-micronova-target.md`: mark MN.1-MN.5 complete

---

## Acceptance Criteria

- [ ] `HeterogeneousCircuitFamily` trait defined and documented
- [ ] `LatticeFoldTreeCircuitFamily` implements the trait for 2+ circuit levels
- [ ] `MicroNovaCompressor` folds heterogeneous trees
- [ ] 5 RED tests pass (including depth-4 tree)
- [ ] Existing homogeneous Nova tests still pass
- [ ] Demo ACCEPT with `PVTHFHE_COMPRESSOR=micronova`
- [ ] Demo ACCEPT with default compressor (no regression)

## Non-Goals

- Replacing the `folding-schemes` crate (we extend, don't replace)
- Full on-chain verification (deferred to P3-M3)
- Spartan SNARK compression (deferred to future plan)
- Changing existing `FCircuit` trait (backward compatible)

## Estimated Effort

~2-4 weeks. The trait design and compressor are ~1 week. The tree circuit family is ~1 week. Tests and integration ~1 week.

## Dependencies

- Existing `SonobeCompressor`, `FCircuit`, `ExternalInputs3` in our sonobe fork
- `FoldVerifierCircuit` (P3-M1, already implemented)
- `CycloVerifierCCS` (P2-M1, already implemented)
- Lemma 9 (accepted as documented assumption)
