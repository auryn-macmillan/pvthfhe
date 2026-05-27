# Learnings — P2-M6 R1CS Cyclo Ring Equation Verifier

## Module structure
- `ark_relations::gr1cs` (not `r1cs`) is the constraint system module used by Nova
- `ark_r1cs_std::eq::EqGadget` must be imported for `enforce_equal` on `FpVar`
- `ark_r1cs_std::fields::FieldVar` must be imported for `FpVar::constant()`
- The existing codebase uses `ConstraintSystemRef` via `ConstraintSystem::new_ref()`

## Ternary challenge branching (key insight)
- c ∈ {-1, 0, 1} needs ZERO R1CS multiplications
- c=1:  lhs = z_s + z_e, rhs = t + d
- c=-1: lhs = z_e + d, rhs = t + z_s
- c=0:  z_e = t
- All branch paths use only addition/negation (free in R1CS)

## FpVar negation
- `FpVar::constant(F::zero()) - a` is the canonical way to negate an FpVar
- Requires `FieldVar` trait to be in scope

## Test pattern for R1CS constraint verification
- `verify_ring_equation_r1cs()` adds constraints, returns `Ok(())` even if unsatisfiable
- To detect constraint violations: check `cs.is_satisfied().unwrap()` after calling the function
- Wrong witness: function returns Ok, but `cs.is_satisfied()` returns false

## Cyclic dependency awareness
- `cyclo_verifier.rs` in compressor imports from `pvthfhe-aggregator` (RingElement, CycloVerifierCCS)
- `ring_element_var.rs` has no external dependency — pure arkworks R1CS types

## M6 Verification Counter Implementation (2026-05-16)

### State extension
- CycloFoldStepCircuit widened from state_len=3 to state_len=4
- New 4th state element: `ring_verification_count`
- ext.2 repurposed from `fold_count_delta` to `ring_verification_result` (Fr::ONE=passed, Fr::ZERO=failed)
- fold_count now hardcoded as `z_i[2] + FpVar::one()` in generate_step_constraints

### Verifier move semantics
- `NovaNova::verify()` moves `ivc_proof`, so ring check values must be captured BEFORE the verify call
- Pattern: `let ring_check = if self.state_len >= 4 { Some((z_i[2], z_i[3])) } else { None };`
- Guard: only check `fold_count == verification_count` for state_len >= 4 circuits
- State_len=3 circuits (ToyStepCircuit, HeterogeneousStepCircuit) skip the ring check

### compressor_inputs semantics
- 3rd element of `encode_triple` was `Fr::from(1u64)` (count_delta), now represents ring_result
- Pipeline checks ring equation natively BEFORE compressor.prove(), so ext.2=1 by construction
- No per-step granularity needed for M6 — the pipeline guarantees all-or-nothing ring check

### Test patterns
- `prove` + `verify`: single ext.2 for all steps (all-pass or all-fail with ext.2=0)
- `prove_steps` + `verify_steps`: per-step ext.2 for mixed pass/fail scenarios
- RED test `multi_input_step_circuit` was pre-written with 4-element expectations
