# Decisions — in-circuit-verification (G4 + G5)

## G4: ExternalInputs3 kept as-is

**Decision**: Did NOT change ExternalInputs3 to ExternalInputs4. The circuit keeps 3 external inputs:
- ext.0 = share_eval
- ext.1 = lagrange_coeff
- ext.2 = merkle_root (participant hash)

The dkg_root_hash → agg_pk_hash binding is deferred to off-circuit verification. Rationale:
- Changing ExternalInputs3 → ExternalInputs4 would break all existing code using C7DecryptAggregationCircuit
- The merkle_root already binds shares to the committed tree
- Off-circuit SHA-256(DKG transcript) verification suffices for M1

## G5: Position-aware Merkle deferred, RED test added

**Decision**: Circuit logic NOT changed. The `leaf_index == 0` constraint remains. Full position-aware Merkle (idx % arity propagation) is deferred. A RED test was added to prove the constraint is active.
