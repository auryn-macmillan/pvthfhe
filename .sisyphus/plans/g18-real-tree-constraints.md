# G.18 — Real LatticeFoldTreeCircuitFamily Constraints

**Status**: READY  
**Blocks**: C7 tree path verification  
**Estimate**: ~1-2 days

## Background

The tree C7 path uses `CompressionTree::build` → `MicroNovaCompressor::prove_tree` → folds `LatticeFoldTreeCircuitFamily`. Currently both leaf and internal variants produce identical degenerate constraints (pure state accumulation, 0 R1CS multiplication gates). This is the placeholder documented as deferred in G.18.

## Goal

Add real R1CS constraints to `LatticeFoldTreeCircuitFamily` so the tree path verifies C7 decryption aggregation with cryptographic soundness.

## Circuit Architecture

```
LatticeFoldTreeCircuitFamily:
  ├── Leaf variant: verifies share evaluation + Lagrange coefficient
  │     Input: (share_eval, lagrange_coeff, agg_pk_hash)
  │     Constraint: incorporates eval + coeff into state accumulator
  │
  └── Internal variant: verifies hash consistency
        Input: (left_child_hash, right_child_hash)
        Constraint: parent_hash = Poseidon(left, right)
```

## Tasks

### Task 1: Implement leaf verifier constraints
- [ ] Read share evaluation data from thread-local (same pattern as C7DecryptAggregationCircuit)
- [ ] `state[0] += share_eval * lagrange_coeff` — accumulate plaintext evaluation
- [ ] `state[1] += lagrange_coeff` — accumulate Lagrange sum (must sum to 1)
- [ ] `state[2] += 1` — step counter
- [ ] Verify: leaf_fold_roundtrip test passes

### Task 2: Implement internal node constraints
- [ ] `hash = Poseidon(left_hash, right_hash)` — verify parent = hash of children
- [ ] `state[0] += hash` — accumulate in state
- [ ] `state[1] += 1` — step counter
- [ ] Verify: internal_fold_roundtrip test passes

### Task 3: Update CompressionTree to pass real data
- [ ] `CompressionTree::build` currently hashes leaf data via SHA-256
- [ ] Change to use thread-local data for share evaluations
- [ ] Pass `share_evals` and `lagrange_coeffs` through tree

### Task 4: Wire into demo-e2e
- [ ] Remove tree path grace period (it's now the primary)
- [ ] Remove flat Nova path (broken)
- [ ] Verify: `just demo-e2e 16 7` ACCEPTS

## Constraint Budget
- Leaf: 3 constraints (1 mul for eval*coeff, 2 adds for accumulators)
- Internal: ~8K constraints (Poseidon hash of 2 fields)
- Tree depth for n=16: ceil(log2(8)) = 3, total nodes = 2n-1 = 15
- Total tree constraints: 8 leaves × 3 + 7 internal × 8K ≈ 56K
