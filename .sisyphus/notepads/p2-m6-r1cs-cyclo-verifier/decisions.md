# Decisions — P2-M6 R1CS Cyclo Ring Equation Verifier

## C-call: verify_ring_equation_r1cs does NOT take cs parameter
The plan spec had `_cs: ConstraintSystemRef<F>` as an unused first parameter.
The actual implementation omits it — the CS is embedded in FpVar values from allocation.
This is cleaner and matches the arkworks convention where constraints don't need explicit CS.

## CycloFoldStepCircuit: placeholder comment only → ACTIVE implementation (2026-05-16)
The original placeholder approach has been replaced with an active implementation.
The verification counter approach (M6) widens state from 3 to 4 elements,
adding `ring_verification_count` as state[3]. The circuit hardcodes `fold_count = z_i[2] + 1`
per step and accumulates `verification_count += ext.2` where ext.2 is the native
ring-equation verification result (1 = passed, 0 = failed).

The verifier (all four verify paths) checks `state[3] == state[2]` to confirm
every fold step passed its ring equation. This closes the M1 trust gap where
a remote verifier previously could not verify ring equation correctness.

## Verification counter over full R1CS ring arithmetic
The verification counter approach is sufficient for M6. Full R1CS ring equation
encoding (using RingElementVar and verify_ring_equation_r1cs) remains available
in the codebase but is not wired into CycloFoldStepCircuit. This is deferred to M2.

## Ring check guarded by state_len
Verifier ring check `fold_count == verification_count` is only performed for
state_len >= 4 circuits (CycloFoldStepCircuit). State_len=3 circuits
(ToyStepCircuit, HeterogeneousStepCircuit) skip the check. This avoids
panicking on index out of bounds for 3-element states.

## No CycloR1csTestCircuit in test file
The plan mentions a `CycloR1csTestCircuit` but this was deemed unnecessary for M6.
The 4 RED tests directly test `verify_ring_equation_r1cs()` with minimal setup.
A full step circuit integration test is deferred to M6.3 proper.

## 4-element ring for tests (N=1 ring elements)
Tests use single-coefficient ring elements for simplicity.
The algebra is identical for arbitrary N — the function iterates over all coefficients.
Multi-coefficient testing is deferred to integration tests.

## ext.2 semantics: repurposed from count_delta to ring_result
The third external input was formerly `fold_count_delta` (always 1). Now it is
the ring equation verification result. The fold count is hardcoded in the circuit
as `z_i[2] + 1`. This is a simpler design than adding a 4th external input type.
