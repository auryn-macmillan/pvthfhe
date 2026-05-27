# Plan: P3 M1 — MicroNova Step Circuit for LatticeFold+ Terminal Verifier

**Plan**: `p3-m1-micronova-step-circuit`
**Status**: DRAFT — pending Momus review
**Created**: 2026-05-14
**Goal**: Design the MicroNova step circuit that encodes the LatticeFold+ terminal verifier relation over BN254/Grumpkin, enabling recursive compression of the P2 folding tree into a constant-size UltraHonk proof.

---

## Context

### Current state: Nova Nova IVC (Track A surrogate)

The Track A pipeline uses `NovaCompressor` with `CycloFoldStepCircuit` (hash-then-fold) to compress DKG accumulator state. This produces a Nova IVC proof that is then UltraHonk-wrapped. The proof is verified off-chain.

### Target state: MicroNova + UltraHonk on-chain

Track B replaces the hash-then-fold with real LatticeFold+ (P2), then uses MicroNova to compress the LatticeFold+ terminal verifier into a single UltraHonk proof suitable for on-chain verification via `HonkVerifier.sol`.

The MicroNova step circuit encodes: given two LatticeFold+ accumulator states (left, right) and a claim about their folded child, verify that the LatticeFold+ folding step is correct.

### MicroNova vs Nova

| | Nova | MicroNova |
|---|---|---|
| Steps | Homogeneous (same circuit per step) | Heterogeneous (multiple circuits) |
| Use case | Folding many instances of the same relation | Compressing different proof layers |
| P3 role | Would work but wastes constraints | Enables efficient compressor with per-layer optimization |

For P3 M1, MicroNova is the right target because:
1. The LatticeFold+ tree has nodes at different depths with different constraint systems
2. The compression pipeline needs to handle multiple circuit types (CCS verifier, recursion verifier, encoding bridge)
3. MicroNova enables per-layer optimization

However, for the M1 implementation, a simplified Nova approach (treating all verification layers as the same step circuit) is acceptable as a first iteration. The plan documents the MicroNova target but implements Nova for M1.

---

## Implementation

### P3-M1.1 — Define the terminal verifier relation

**File**: `.sisyphus/research/p3/terminal-verifier.md` (new design doc)

The LatticeFold+ terminal verifier checks:
1. The root accumulator `Acc_root` is consistent with the leaf accumulators `{Acc_i}`
2. Each folding step from leaf to root satisfies the CCS relation
3. The Merkle tree of accumulator states is well-formed
4. The public statement matches the expected values

For M1, simplify to: verify that two accumulator states (left, right) correctly fold into a parent accumulator under the Cyclo CCS relation from P2-M1.

### P3-M1.2 — Implement FoldVerifierStepCircuit

**File**: `crates/pvthfhe-compressor/src/nova/fold_verifier_circuit.rs` (new)

A Nova step circuit that verifies one LatticeFold+ folding step:

```rust
pub struct FoldVerifierStepCircuit<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for FoldVerifierStepCircuit<F> {
    type Params = ();
    type ExternalInputs = ExternalInputs3<F>; // (acc_left_hash, acc_right_hash, expected_parent_hash)
    
    fn state_len(&self) -> usize { 2 } // [verified_count, root_hash]
    
    fn generate_step_constraints(...) -> Vec<FpVar<F>> {
        // 1. Verify that acc_left and acc_right are consistent
        // 2. Verify that folding left + right produces expected_parent
        // 3. Update verified_count, update running root_hash
    }
}
```

The 3 external inputs carry the hash commitments of the accumulator states. The step circuit verifies the folding equation in R1CS constraints, using the CCS adapter from P2-M1.

### P3-M1.3 — Build recursive compression pipeline

**File**: `crates/pvthfhe-compressor/src/micronova/mod.rs` (new)

Wrap the `FoldVerifierStepCircuit` in a recursive compression loop:

```rust
pub fn compress_latticefold_tree(
    leaf_accumulators: &[AccumulatorState],
    ccs_adapter: &CycloVerifierCCS,
) -> Result<CompressedProof, CompressorError> {
    // 1. Build Merkle tree of accumulator hashes
    // 2. For each level from bottom to top:
    //    a. Fold pairs of sibling leaves using FoldVerifierStepCircuit
    //    b. Use MicroNova to handle heterogeneous layer types (optional for M1)
    // 3. UltraHonk-wrap the root verifier proof
}
```

### P3-M1.4 — Tests

**File**: `crates/pvthfhe-compressor/tests/fold_verifier_step.rs` (new)

| Test | Description |
|------|-------------|
| `fold_verifier_compiles` | NovaCompressor::new with FoldVerifier succeeds |
| `fold_verifier_state_len_two` | state_len() == 2 |
| `fold_verifier_accepts_honest_fold` | Two valid accumulators fold correctly |
| `fold_verifier_rejects_inconsistent_fold` | Mismatched accumulators → verification fails |
| `fold_verifier_roundtrip` | Full prove/verify cycle |
| `recursive_4_leaf_tree_compresses` | 4 leaves → 2 parents → 1 root: 3 fold steps |

### P3-M1.5 — Documentation

- Update `docs/security-proofs/p3/proof-skeletons.md` — note M1 implementation
- Update `p3-micronova-target.md` — mark M1 complete
- Cross-reference P2-M1 CycloCCSAdapter

---

## Acceptance Criteria

- [ ] FoldVerifierStepCircuit implements FCircuit + StepCircuit
- [ ] 6 RED tests pass (including recursive tree compression)
- [ ] Existing Nova tests pass
- [ ] Demo ACCEPT (Track A unchanged)
- [ ] Plan notes that full MicroNova (heterogeneous circuits) is deferred to M2

## Non-Goals

- Full MicroNova heterogeneous circuit support (deferred to M2)
- On-chain UltraHonk verifier deployment (M3)
- Gas optimization (M4)
- Full security proofs (M5)

## Estimated Effort

~1-2 weeks. The FoldVerifierStepCircuit is a 3-external-input Nova circuit following the established pattern (ToyStepCircuit, C7DecryptAggregationCircuit). The recursive compression pipeline wraps the existing Nova infrastructure.

## Dependencies

- P2-M1 CycloCCSAdapter (for the CCS verifier equation)
- Lemmma 9 (accepted as documented assumption)
- Existing Nova Nova infrastructure (`NovaCompressor`, `FCircuit`, `StepCircuit`)
