# P3-M1 Learnings

## SonobeCompressor state_len constraint
- `SonobeCompressor::prove()` and `prove_steps()` hard-code pushing 3 initial state elements from decoded triple, requiring `state_len >= 3`.
- FoldVerifierStepCircuit originally planned for `state_len=2` was adjusted to `state_len=3` to match this constraint.
- The third state element `step_index` serves as padding/consistency with existing C7/Toy circuits.
- This is a design limitation of the current SonobeCompressor — noted for future refactoring.

## Pattern consistency
- All step circuits (Toy, C7, CycloFold, FoldVerifier) follow identical patterns: PhantomData, FCircuit impl, StepCircuit impl, Keccak256 domain tag hashing.
- Adding a new step circuit requires: domain tag, circuit file, mod.rs exposure, tests.

## Domain tags
- `Tag::PvssFoldVerifier` maps to `pvthfhe/p3/fold-verifier/v1`.
- Required updates: enum variant, as_bytes() match arm, all_literals() array count + entry.
