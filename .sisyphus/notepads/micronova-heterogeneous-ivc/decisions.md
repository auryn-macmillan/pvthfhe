# Decisions — MicroNova Heterogeneous IVC

## D1: HeterogeneousStepCircuit params strategy (2026-05-14)

**Context**: SonobeCompressor hardcodes `FCircuit<Fr, Params = ()>` and calls `S::new(())`.

**Decision**: Use `thread_local!` registry for the circuit family instead of passing
it through `Params`. `HeterogeneousStepCircuit::set_family()` must be called before
`SonobeCompressor::new()`.

**Rationale**: Cannot modify SonobeCompressor (per MUST NOT constraint). thread_local
provides test isolation for parallel test execution.

## D2: State length = 3 (2026-05-14)

**Context**: Task description says state_len=2, but existing infrastructure assumes 3.

**Decision**: Use state_len=3 ([hash, norm, count]) matching existing circuits.

**Rationale**: SonobeCompressor initializes state as a triple; all existing circuits
use 3-element state. Using 2 would break serialization boundaries.

## D3: HeterogeneousCircuitFamily<F> generic parameter (2026-05-14)

**Context**: Trait is generic over F: PrimeField, but many methods don't use F in their
signatures, causing type inference failures.

**Decision**: Keep the generic parameter (needed by generate_step_constraints) and use
UFCS in test code to disambiguate.

**Rationale**: generate_step_constraints must work with FpVar<F> which requires F.
Removing F from the trait would require boxing/dyn dispatch, adding complexity.

## D4: Per-variant verifier limitation documented (2026-05-15)

**Context**: Batch A — document the known limitation that SonobeNova uses a single
verifier key for all circuit variants, making per-variant enforcement architecturally
impossible.

**Decision**: Added documentation in three locations:
- `crates/pvthfhe-compressor/src/micronova/compressor.rs:127-132` — R9 KNOWN LIMITATION comment
- `docs/security-proofs/p3/heterogeneous-ivc.md:94-101` — replaced open questions with formal limitation
- `SECURITY.md:51-53` — P3 section addendum

**Rationale**: The per-step variant hash computation in `verify_tree` is diagnostic-only.
Security relies on structural equivalence of constraints across variants
(state_len=2, identical ExternalInputs3 width per LatticeFoldTreeCircuitFamily).
