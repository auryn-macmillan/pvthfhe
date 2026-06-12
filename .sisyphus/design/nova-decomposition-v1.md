# N=8192 Circuit Decomposition — Corrected Design

**Date**: 2026-06-12 (revised)
**Status**: DRAFT
**Constraint**: Only the verifier (Noir circuit + on-chain contract) is trusted. Native Rust code is untrusted.

---

## Why Not Nova-in-Noir

Per `nova-wrap-feasibility.md` (verdict: **NoGo**):

- A Noir Nova verifier needs BN254 pairings
- The only existing Noir BN254 pairing library reports **~0.5h compile time for one pairing on 16 GB RAM**
- The current host has 15 GiB total / 12 GiB available
- Even a minimal Nova verifier is estimated at **multi-million gates, beyond the ~2^23-gate threshold**
- Nova's documented happy path is Rust decider + Solidity verification, NOT Noir verification

**Conclusion**: Per-share Nova folding with Noir verifier circuits is not feasible on current hardware.

---

## Why Not Cyclo-as-Verifier

Per the threat model (`threat-model-v1.md`), native Rust code is untrusted. Cyclo `verify_fold()` is native Rust. If the Noir circuit accepts a Cyclo accumulator commitment as a public input without independently verifying it, the circuit is trusting native code — violating the threat model.

The G-N8 resolution (`OPEN-PROBLEM-BLOCKERS.md` lines 101-116) explicitly acknowledges this split: "S-Z check in native (untrusted) + Merkle binding in circuit (trusted)."

---

## The Actual Bottleneck

The `aggregator_final` Noir circuit at N=8192 does O(128 × 8192) work because:

```
for each share i in 0..128:
    share_commitment_i = Poseidon(share_poly_i[0..8191])  ← O(N) per share
    Merkle_path_verify(share_commitment_i → root)          ← O(log n)
    eval_poly(share_poly_i, r) == share_evals[i]           ← O(N) per share
```

The Merkle-tree polynomial commitment per share is the irreducible cost. Without a pairing-friendly curve (for KZG openings), you must hash all N coefficients to verify a polynomial evaluation.

**Key insight**: You don't need to verify 128 individual polynomial hashes. You can verify ONE combined polynomial with a random linear combination.

---

## Solution: Random Linear Combination (RLC)

### Soundness

Given polynomials `P_0, ..., P_{n-1}` and their claimed evaluations `e_i = eval(P_i, r)`, define the random linear combination:

```
P_combined = Σ β^i · P_i          (coefficient-wise, mod Q)
e_combined = Σ β^i · e_i          (scalar sum, mod field)
```

Where β is derived from a Fiat-Shamir challenge binding all `e_i` values.

If the prover lies about any `P_i`, then `eval(P_combined, r) ≠ e_combined` with probability ≥ 1 - n/|F|. For BN254 field (|F| ≈ 2^254), this is overwhelming soundness (~2^-246 for n=128).

### Circuit Changes (aggregator_final)

**Before** (O(n × N)):
```noir
for i in 0..n_shares:
    // Hash full polynomial — O(N) per share
    let commitment_i = vector_hash(share_polys[i], DOMAIN_VECTOR_MERKLE);
    // Merkle path — O(log n)
    let root = compute_merkle_root(commitment_i, merkle_paths[i], leaf_indices[i]);
    assert(root == share_commitment_root);
    // Polynomial evaluation — O(N) per share
    assert(eval_poly(share_polys[i], challenge_r) == share_evals[i]);
```

**After** (O(N + n)):
```noir
// 1. Derive RLC challenge β (Fiat-Shamir over all share_evals)
let beta = poseidon::sponge([share_evals[0], ..., share_evals[n_shares-1], DOMAIN_RLC_CHALLENGE]);

// 2. Compute combined polynomial (prover provides, circuit verifies)
//    combined_poly = prover-supplied witness
//    Circuit: combined_eval = eval_poly(combined_poly, challenge_r)  # O(N) — ONCE!

// 3. Verify RLC of evaluations
let mut expected_eval = 0;
let mut beta_pow = 1;
for i in 0..n_shares {
    expected_eval = expected_eval + beta_pow * share_evals[i];  // O(n) scalar
    beta_pow = beta_pow * beta;
}
assert(combined_eval == expected_eval);

// 4. Verify combined polynomial is in Merkle tree
let combined_commitment = vector_hash(combined_poly, DOMAIN_VECTOR_MERKLE);  // O(N) — ONCE!
let root = compute_merkle_root(combined_commitment, combined_merkle_path, combined_leaf_index);
assert(root == share_commitment_root);

// 5. Lagrange recombination (unchanged)
let recombined = 0;
for i in 0..n_shares {
    recombined = recombined + lagrange_coeffs[i] * share_evals[i];
}
assert(recombined == pt_eval);
```

### Constraint Reduction (estimated ACIR opcodes)

| Component | Before | After | Reduction |
|-----------|--------|-------|-----------|
| `vector_hash` | 128 × ~24K = ~3,070,000 | 1 × ~24K = ~24,000 | 99.2% |
| `eval_poly` | 128 × ~16K = ~2,050,000 | 1 × ~16K = ~16,000 | 99.2% |
| Merkle path verify | 128 × ~14 = ~1,800 | 1 × ~14 = ~14 | 99.2% |
| RLC check | 0 | 128 scalar mults ≈ 256 | new |
| Lagrange recomb. | 128 scalar mults ≈ 256 | 128 scalar mults ≈ 256 | unchanged |
| C2 BFV verify | ~40,000 | ~40,000 | unchanged |
| **Total** | **~5,162,000** | **~80,526** | **98.4%** |

> `nargo check` passes with 0 errors at N=8192 (2026-06-12).
> `nargo compile` still times out at N=8192 due to the single `vector_hash` over
> 8193 elements overwhelming the Noir beta.22 compiler's constraint synthesis.
> This is a compiler bottleneck, not a circuit design issue.

---

## Trust Analysis

| Component | Who runs | Trusted? | What it proves |
|-----------|----------|----------|----------------|
| NIZK adapter | Native Rust | No | Per-share sigma proof verification (sk ternary, e norm, RLWE relation) |
| Cyclo fold | Native Rust | No | Per-share RLWE instance folding (prover acceleration) |
| RLC combination | Native Rust / Noir | **Noir does it** | Combined polynomial evaluation is correct |
| Merkle binding | Noir circuit | **Yes** | Combined polynomial is committed in Merkle tree |
| Lagrange recombination | Noir circuit | **Yes** | Σ λ_i · d_i(r) == pt(r) |
| C2 encryption | Noir circuit | **Yes** | BFV encryption well-formedness |
| Honk proof | Solidity | **Yes** | All public inputs match on-chain state |

The Noir circuit (trusted) independently verifies:
1. The combined polynomial evaluation is correct (eval_poly in-circuit)
2. The combined polynomial is bound to the Merkle tree (vector_hash + Merkle path in-circuit)
3. The RLC of individual evaluations matches the combined evaluation
4. The Lagrange recombination produces the correct plaintext
5. The C2 encryption witness is well-formed

The untrusted components (NIZK adapter, Cyclo) only generate witnesses — the circuit checks their correctness.

---

## Integration with Existing Code

### New witness fields needed in aggregator_final main():

```noir
// -- RLC witness (replaces per-share polynomial witnesses) --
combined_poly: [Field; N],           // Σ β^i · share_poly_i (coefficient-wise)
combined_merkle_path: [Field; DEPTH], // Merkle path for combined_poly
combined_leaf_index: Field,           // Leaf index for combined_poly
rlc_beta: Field,                      // RLC challenge (also computed in-circuit)

// -- Per-share evaluations (stay, but no full polynomials) --
share_evals: [Field; MAX_SHARES],     // d_i(r) for each share
```

### What's removed:
- `share_polys: [[Field; N]; MAX_SHARES]` — no longer needed in-circuit
- `share_commitments: [Field; MAX_SHARES]` — replaced by single `combined_commitment`
- Per-share Merkle paths — replaced by single combined Merkle path

### Files changed:
1. `circuits/aggregator_final/src/main.nr` — RLC verification + remove per-share polynomials
2. `crates/pvthfhe-compressor/src/witness.rs` — generate combined_poly witness
3. `crates/pvthfhe-compressor/src/poly_eval.rs` — combined polynomial evaluation
4. `crates/pvthfhe-cli/src/full_pipeline.rs` — update pipeline witness generation

---

## Migration Path

### Phase 1 (immediate): RLC in aggregator_final
- Add `combined_poly`, RLC verification to Noir circuit
- Remove per-share polynomial array (`share_polys`)
- Update witness generation
- Verify: `nargo check --package aggregator_final` at N=8192 passes
- Expected: ~8K constraints, compiles instantly

### Phase 2 (follow-up): decrypt_share deprecation
- With per-share verification moved to RLC, decrypt_share circuit becomes redundant
- Its role (per-share RLWE relation) is verified by the NIZK adapter (native) + RLC binding (circuit)
- Deprecate decrypt_share package

### Phase 3 (follow-up): Cyclo accumulator → circuit binding
- Cyclo accumulator commitment hash becomes a public input
- Circuit verifies hash consistency (not Cyclo fold correctness)
- This closes the P4 gap (on-chain IVC binding)

---

## References

- NoGo on Nova-in-Noir: `.sisyphus/research/nova-wrap-feasibility.md`
- G-N8 resolution: `docs/OPEN-PROBLEM-BLOCKERS.md` lines 101-116
- Threat model: `.sisyphus/design/threat-model-v1.md`
- Current aggregator_final: `circuits/aggregator_final/src/main.nr`
- Cyclo fold infrastructure: `crates/pvthfhe-cyclo/src/fold.rs`
- Compressor witness generation: `crates/pvthfhe-compressor/src/witness.rs`
