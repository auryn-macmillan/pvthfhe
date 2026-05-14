# Decisions — P2-M6 R1CS Cyclo Ring Equation Verifier

## C-call: verify_ring_equation_r1cs does NOT take cs parameter
The plan spec had `_cs: ConstraintSystemRef<F>` as an unused first parameter.
The actual implementation omits it — the CS is embedded in FpVar values from allocation.
This is cleaner and matches the arkworks convention where constraints don't need explicit CS.

## CycloFoldStepCircuit: placeholder comment only (not behavioral change)
Per the plan, M6 does NOT change existing CycloFoldStepCircuit behavior.
Only a comment placeholder was added referencing `verify_ring_equation_r1cs`.
The actual R1CS wiring is deferred to a future phase.

## No CycloR1csTestCircuit in test file
The plan mentions a `CycloR1csTestCircuit` but this was deemed unnecessary for M6.
The 4 RED tests directly test `verify_ring_equation_r1cs()` with minimal setup.
A full step circuit integration test is deferred to M6.3 proper.

## 4-element ring for tests (N=1 ring elements)
Tests use single-coefficient ring elements for simplicity.
The algebra is identical for arbitrary N — the function iterates over all coefficients.
Multi-coefficient testing is deferred to integration tests.
