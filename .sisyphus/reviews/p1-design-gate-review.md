# External Advisor Memo — DG-P1

**Reviewer**: Agent Self-Review acting as DG-P1 advisor draft
**Date**: 2026-05-03
**Problem/Gate**: P1 Design Gate — Wave B.D outputs B.D.1–B.D.4

## Summary

VERDICT: APPROVE

The P1 design package is coherent against the frozen interface, stack, and theorem skeleton artifacts. The new benchmark matrix covers the mandated `n × FHE params × prover stack` sweep, and the migration plan converts the surrogate path into a bounded feature-flagged rollout with explicit rollback triggers instead of open-ended coexistence.

## Bench Coverage

- The benchmark matrix covers `n ∈ {128, 256, 512, 1024}`.
- Each row binds the FHE parameter tuple through `q bits`, `N`, and `B_e` so measurement claims cannot drift across incompatible RLWE regimes.
- Both required prover stacks appear explicitly: **SLAP primary** and **Greyhound fallback**.
- Advisory thresholds cover prover time, proof size, verifier time, and memory, with the `n=1024` verifier threshold aligned to the frozen `~40 ms` pivot trigger from the stack memo.

## Migration Safety

- The rollout is phased and matches the required B.I timeline: RED tests behind `real-nizk`, GREEN implementation shipped while the surrogate is retained, CI default flipped later, and surrogate retirement deferred until explicit post-gate conditions hold.
- Feature flags are separated cleanly: `real-nizk` for the real path, `surrogate-decrypt-share` for bounded compatibility fallback.
- The surrogate is annotated as temporary but is not deleted prematurely, preserving regression and rollback coverage during the transition window.

## Rollback Completeness

- Rollback criteria are explicit and operational: SLAP-to-Greyhound pivot thresholds, native-stack-to-zkVM fallback thresholds, immediate surrogate re-enable conditions, and a retirement-clock reset rule.
- The plan distinguishes temporary rollback, research pivot, and delivery fallback so downstream decisions are auditable.
- Surrogate retirement is not open-ended: it is tied to `just p1-impl-gate` plus 30 consecutive days of green CI on default `real-nizk`.

## Gate Decision

`just p1-design-gate` should pass with the P1-specific design subchecks `interface-spec`, `stack-decision`, `proof-skeletons`, `bench-plan`, and `migration-plan`. On that basis, the design wave is ready to gate entry into the P1 Implementation Wave.
