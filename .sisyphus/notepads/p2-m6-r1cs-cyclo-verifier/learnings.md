# Learnings — P2-M6 R1CS Cyclo Ring Equation Verifier

## Module structure
- `ark_relations::gr1cs` (not `r1cs`) is the constraint system module used by Sonobe
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
