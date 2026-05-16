# Learnings — in-circuit-verification (G4 + G5)

## G1: Ring equation in circuit (2026-05-16)

- **Approach**: Created standalone `RingVerifierCircuit` (new file `ring_verifier.rs`) with `ExternalInputs5` carrying 4 Poseidon hashes + challenge.
- **Challenge branching**: The challenge is stored as a native `F` field in the circuit struct and used to branch at constraint-generation time. This works because the challenge is ternary (known when the circuit is built) and the constraint structure is fixed per challenge value.
- **Private witnesses**: 1024 ring coefficients (4×256) stored in the circuit struct. The prover provides them at circuit construction; they flow into `FpVar::new_witness` closures in `generate_step_constraints`.
- **Params type**: Changed from `()` to `(F, Vec<F>)` (challenge + ring coefficients). This circuit is standalone (not used with SonobeCompressor which requires `Params = ()`).
- **hash256**: Added to `poseidon_gadget.rs` — absorbs 256 elements via Poseidon sponge (64 permutations with rate=4) and squeezes one output. Both R1CS (`hash256`) and native (`hash256_native`) variants.
- **Test vectors**: 7 tests covering all challenge values (1, -1, 0), tampered coefficients, hash mismatches, and wrong challenges.
- **Constraint count**: ~76,800 R1CS constraints (4×256-element hashes × ~19,200 constraints each), plus 256 `enforce_equal` calls. Zero multiplications for the ring equation itself.

## G4: Aggregate PK binding

- **Decision**: Deferred full in-circuit PK binding to follow-up. Documented in `c7_circuit.rs:29-42`.
- **Current state**: C7 circuit uses `ExternalInputs3` with `ext.2 = merkle_root` (participant hash). This binds each share to the Merkle tree but does NOT verify dkg_root_hash → agg_pk_hash in-circuit.
- **Off-circuit path**: `agg_pk_hash = SHA-256(dkg_root)` computed off-circuit; verifier checks the binding.
- **M1 sufficiency**: For M1 milestone, off-circuit verification suffices; full in-circuit G4 binding deferred.

## G5: Position-aware Merkle

- **RED test added**: `verify_merkle_path_rejects_nonzero_leaf_index` in `c7_merkle_circuit.rs:310-349`.
- **Test result**: PASSES — confirms `leaf_index == 0` constraint is actively enforced. Non-zero leaf_index yields unsatisfied CS.
- **Arkworks quirk**: `Fr::zero()` not available on BN254 Fr; used `Fr::from(0u64)` closure pattern instead.
- **Circuit logic unchanged**: `verify_merkle_path` at line 164 enforces `leaf_index == 0`. `generate_step_constraints` at line 252 also has belt-and-suspenders check.
- **Deferred**: Full position-aware Merkle (idx % arity propagation through levels) documented at lines 130-141; native reference at `merkle.rs:87-109`.
