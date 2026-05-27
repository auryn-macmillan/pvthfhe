# Plan: C7 Phase 2 — N=8192 Production Scale via Off-Circuit Merkle Proofs

**Plan**: `c7-phase2-n8192-merkle`
**Status**: COMPLETE
**Created**: 2026-05-13
**Goal**: Scale C7 decryption aggregation to N=8192 production parameters using off-circuit Poseidon Merkle proofs for share coefficient verification, with no changes to the existing `C7DecryptAggregationCircuit` step circuit.

---

## Design

### Why off-circuit Merkle

In-circuit Merkle proof verification requires implementing Poseidon hash in Arkworks R1CS constraints and designing a wide `ExternalInputsN` type for the 30+ sibling hashes per Merkle path. This is deferred to Phase 3.

Off-circuit Merkle achieves the same security guarantee: the verifier checks Merkle proofs before accepting Nova external inputs. The circuit stays 3 inputs wide, 3 constraints per step, and all 6 existing tests continue to pass.

### Security model

The Nova circuit trusts `(d_i(r), λ_i, merkle_root)` as external inputs. A malicious prover who provides a false `d_i(r)` must either:

1. **Forge a Merkle proof** for a wrong value against `merkle_root` — breaks Poseidon collision resistance.
2. **Skip Merkle verification** — verifier rejects because it runs Merkle verification before accepting the Nova proof.
3. **Use a different merkle_root** — the verifier checks `merkle_root` against the DKG transcript's committed share, which is binding.

The trust boundary is at the pipeline level: the verifier function runs `verify_merkle_proof()` before `compressor.verify()`. If the Merkle verifier is honest, the Nova proof is sound.

### Merkle tree design

- **Hash**: Poseidon over Bn254 scalar field (reuse existing `poseidon` dependency from compressor)
- **Arity**: 8-ary (depth 4 for N=8192: 8^4 = 4096 < 8192 < 8^5, needs depth 5)
- **Leaves**: Each leaf is a single share coefficient (8192 leaves per participant)
- **Root**: `merkle_root_i` — the commitment to participant i's share coefficients
- **Proof path**: 5 levels × 7 sibling hashes = 35 sibling hashes per proof

Data layout:
```
leaf_index   = participant_id (0..8191)
leaf_value   = H(coefficient_value || position_tag)
proof_path   = [sibling_level_0, ..., sibling_level_4]  // each level: 7 siblings
merkle_root  = final hash
```

### Protocol flow

```
1. DKG produces share coefficients [c_0, ..., c_8191] for each participant
2. Build Merkle tree: Poseidon 8-ary tree over coefficients
3. Compute challenge r = Fiat-Shamir(transcript)
4. For each participant i:
   a. d_i(r) = eval_poly(share_i, r)  // Horner's method, O(N)
   b. merkle_proof_i = prove_path(tree_i, leaf_index=0, r)
   c. verify: verify_merkle_proof(merkle_root_i, d_i(r), merkle_proof_i)
5. Nova folding: fold (d_i(r), λ_i, merkle_root_i) into C7 accumulator
6. Check accumulator == plaintext(r), lagrange_sum == 1
```

---

## Implementation Batches

### Batch M1 — Merkle tree types and Poseidon hash

**File**: `crates/pvthfhe-compressor/src/merkle.rs` (new)

Types:
```rust
pub struct MerkleTree {
    pub nodes: Vec<Vec<ark_bn254::Fr>>, // [level][node_index]
    pub depth: usize,                     // 5 for N=8192 with 8-ary
    pub arity: usize,                     // 8
}

pub struct MerkleProof {
    pub leaf_value: ark_bn254::Fr,
    pub leaf_index: usize,
    pub siblings: Vec<Vec<ark_bn254::Fr>>, // [level][7 siblings]
    pub root: ark_bn254::Fr,
}
```

Functions:
- `MerkleTree::from_coefficients(coeffs: &[Fr]) -> MerkleTree` — build 8-ary tree
- `MerkleTree::root(&self) -> Fr`
- `MerkleTree::prove(&self, coefficient_index: usize) -> MerkleProof` — generate proof path
- `verify_merkle_proof(proof: &MerkleProof) -> bool` — verify path to root
- `verify_merkle_proof_with_evaluation(proof: &MerkleProof, claimed_value: Fr, position_tag: Fr) -> bool` — verify leaf value matches

### Batch M2 — Polynomial evaluation at N=8192

**File**: `crates/pvthfhe-compressor/src/poly_eval.rs` (new)

Function:
```rust
pub fn eval_poly_bn254(coeffs: &[ark_bn254::Fr], r: ark_bn254::Fr) -> ark_bn254::Fr
```

Horner's method: `result = Σ coeffs[i] * r^(N-1-i)`. O(N) = 8192 iterations. Pure field arithmetic, no constraints.

### Batch M3 — Witness generation pipeline

**File**: `crates/pvthfhe-compressor/src/witness.rs` (new)

Structure:
```rust
pub struct C7Witness {
    pub merkle_root: ark_bn254::Fr,
    pub share_eval: ark_bn254::Fr,
    pub merkle_proof: MerkleProof,
    pub lagrange_coeff: ark_bn254::Fr,
}

pub struct C7WitnessSet {
    pub participants: Vec<C7Witness>,
    pub plaintext_eval: ark_bn254::Fr,
    pub expected_lagrange_sum: ark_bn254::Fr,  // should be Fr::from(1u64)
}
```

Factory:
- `C7WitnessSet::from_shares(shares: &[Vec<Fr>], lagrange_coeffs: &[Fr], challenge_r: Fr) -> C7WitnessSet`
- For each participant: build Merkle tree, compute eval, generate Merkle proof

Verification:
- `C7WitnessSet::verify_all_merkle_proofs(&self) -> Result<(), Error>`
- Runs `verify_merkle_proof_with_evaluation()` for every participant
- Must pass BEFORE Nova folding

### Batch M4 — Nova folding with N=8192 witnesses

**File**: `crates/pvthfhe-compressor/src/nova/c7_circuit.rs` (extend)

Add:
```rust
impl C7DecryptAggregationCircuit<Fr> {
    pub fn fold_witnesses(
        compressor: &NovaCompressor<Self>,
        witnesses: &C7WitnessSet,
    ) -> Result<(Vec<u8>, Vec<u8>), CompressorError> {
        // Verify all Merkle proofs first (security check!)
        witnesses.verify_all_merkle_proofs()?;
        
        // Build initial Nova state
        let initial_state = encode_triple((Fr::zero(), Fr::zero(), Fr::zero()));
        
        // Fold each participant
        let mut acc = initial_state;
        for witness in &witnesses.participants {
            let public_inputs = encode_triple((
                witness.share_eval,
                witness.lagrange_coeff,
                witness.merkle_root,
            ));
            acc = compressor.prove_step(&acc, &public_inputs)?;
        }
        
        Ok((acc, /* final public inputs */))
    }
}
```

### Batch M5 — RED tests at N=8192

**File**: `crates/pvthfhe-compressor/tests/c7_phase2_n8192.rs` (new)

| Test | Description |
|------|-------------|
| `merkle_tree_8192_coefficients_correct_root` | Build tree, verify root matches expected |
| `merkle_proof_8192_verifies` | Generate proof for coefficient 0, verify |
| `merkle_proof_rejects_wrong_leaf` | Tamper leaf value, verify fails |
| `merkle_proof_rejects_wrong_root` | Wrong root, verify fails |
| `merkle_proof_rejects_out_of_range_index` | Index ≥ 8192, verify fails |
| `poly_eval_bn254_matches_horner` | Manual sum vs Horner result |
| `c7_witness_set_generates_n_merkle_proofs` | N participants, all proofs verify |
| `c7_witness_set_rejects_one_bad_proof` | One tampered eval, verify_all fails |
| `c7_nova_fold_n8192_4_participants` | Full pipeline: build witnesses, verify Merkle, fold Nova, verify proof |

### Batch M6 — Integration + documentation

- Wire `C7WitnessSet` into `full_pipeline.rs` behind `pipeline-extra-checks`
- Update ARCHITECTURE.md C7 row: "N=8192 off-circuit Merkle verification"
- Update SECURITY.md: trust model documentation
- Update plan files

---

## Dependencies

- `ark-bn254 = { workspace = true }` — already in compressor Cargo.toml
- `ark-ff = { workspace = true }` — already available
- `poseidon` / `ark-crypto-primitives` — check if already in dependency tree

---

## Acceptance Criteria

- [ ] Merkle tree construction for N=8192 coefficients
- [ ] Merkle proof generation and verification
- [ ] N=8192 polynomial evaluation
- [ ] Witness generation pipeline
- [ ] Nova folding with N=8192 witnesses
- [ ] 9 RED tests pass (including full Nova prove/verify at N=8192)
- [ ] Existing C7 tests (6) still pass
- [ ] Demo still passes
- [ ] Documentation updated

## Non-Goals

- In-circuit Merkle proof verification (Phase 3 — see `c7-phase3-in-circuit-merkle.md`)
- Ring-aware C7 coefficient check (see `c7-ring-aware-coefficient-check.md`)
- Replacing the Noir aggregator_final circuit

## Execution Order

M1 → M2 → M3 (M2 and M3 can overlap) → M4 → M5 → M6
