# Design: C1 + C5 — PK Contribution and Aggregation Proofs

**Status**: DESIGN (Phase 5)
**Depends on**: Phase 1-4 completion

## C1 — Individual PK Contribution

### Relation

Each party `i` publishes a BFV public key `pk_i = (pk_0_i, pk_1_i)` where
`pk_1_i = a` is the common CRS polynomial. The party must prove:

```
pk_0_i = a · sk_i + e_i   (mod Q)
```

where `sk_i` is ternary, `e_i` is short Gaussian error.

### Circuit Design

- Re-use the existing `sigma.rs` infrastructure: the relation is identical to
  `d_i = c · s_i + e_i` with `c := a`, `d_i := pk_0_i`, `s_i := sk_i`.
- Create `KeyContributionStepCircuit` (Nova FCircuit) using `sigma_verify_step`
  with `c_rns = pk_1_rns`, `d_rns = pk_0_rns`.
- Thread-local: `KEY_CONTRIB_DATA` storing per-party `(pk_0_rns, pk_1_rns, sk_coeffs, e_coeffs)`.
- State: `(contribution_hash_accumulator, step_count)`.
- Wire into `full_pipeline.rs` after keygen phase.

### Public Inputs

Expose `pk_contribution_hash` (Poseidon accumulator of all C1 proofs) in
`PipelineReport`. Add as public input to `aggregator_final` Noir circuit.

## C5 — PK Aggregation Proof

### Relation

Given committee `{i_1, ..., i_t}` and individual public keys `pk_1, ..., pk_t`,
prove that `aggregate_pk = Σ pk_j` (additive homomorphism of BFV public keys).

### Circuit Design

- Re-use Cyclo's `CycloFoldStepCircuit` with a `pk_aggregation` verification
  mode that sums all `pk_j` field elements in R1CS.
- The aggregate sum is committed via Poseidon and bound to `aggregate_pk_hash`
  in `aggregator_final`.

## Integration Into aggregator_final

The Noir circuit should check:
```
assert(pk_contribution_hash != 0, "C1 PK contribution proofs missing");
assert(aggregate_pk == pk_sum, "C5 aggregate PK mismatch");
```

## Implementation Plan (Phase 5)

1. Wire `sigma_verify_step` into `KeyContributionStepCircuit`
2. Create `PkAggregationStepCircuit` for C5 sum verification
3. Add `pk_contribution_hash` and `aggregate_pk` as public inputs to `aggregator_final`
4. Wire into `full_pipeline.rs` after keygen and after aggregate key computation
5. Add adversarial tests: tamper `pk_i` → C1 proof fails; tamper `aggregate_pk` → C5 proof fails
6. Demo-e2e verification with C1+C5 proofs

## Dependencies
- `sigma_verify_step` (exists, proven in CycloFoldStepCircuit — Phase 2)
- `aggregator_final` Noir circuit (exists, N=8 prototype — Phase B / G6)
- KZG commitment scheme (switched in Phase 4)
