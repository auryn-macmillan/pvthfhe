# P2 Migration Plan

This plan stages the P2 adapter migration from the checked-in surrogate folding path to the real LatticeFold+ implementation while preserving the frozen `FoldingScheme` boundary in `.sisyphus/design/p2/interface-spec.md`. The rollout assumes the semantic trait remains stable and only backend wiring, feature defaults, and retirement criteria change across phases.

## Adapter Rollout

### Phase 1 — Surrogate retained, real adapter shim added

- Keep the current surrogate implementation as the default path behind the existing semantic `FoldingScheme` boundary.
- Add the real-adapter wiring under feature flag `folding-real`, disabled by default in this phase.
- The Phase 1 shim is allowed to be structurally incomplete, but it must consume the frozen `FoldStatement`, `FoldWitness`, `FoldAccumulator`, and `FinalProof` types so downstream code stops depending on surrogate-only shapes.
- `folding-surrogate` remains enabled by default so CI and local happy-path flows still exercise the surrogate until the real adapter is ready.

### Phase 2 — Real LatticeFold+ implementation replaces the shim

- Replace the Phase 1 shim with the first real LatticeFold+ adapter implementation under the same `FoldingScheme` trait.
- Invert the operational default: `folding-real` becomes enabled for the main path, while `folding-surrogate` changes from default-on compatibility flag to explicit opt-out/rollback flag.
- The surrogate remains in tree for regression comparison, but all new acceptance and integration evidence should run against the real adapter unless a rollback trigger fires.

### Phase 3 — Surrogate removed

- Delete the surrogate implementation after the retirement criteria below are satisfied.
- Remove both the surrogate code path and the transitional feature-flag inversion logic.
- End state: the real LatticeFold+ adapter is the only production path and the `FoldingScheme` surface remains unchanged for downstream consumers.

## Feature-Flag Strategy

The Cargo feature schedule should be tracked in `crates/pvthfhe-aggregator/Cargo.toml` once the implementation-wave wiring lands.

- `folding-real`: disabled by default in Phase 1, enabled in Phase 2 and retained in Phase 2+ only as the real implementation selector until the migration stabilizes.
- `folding-surrogate`: enabled by default until Phase 3, then removed entirely in Phase 3 once the surrogate path is retired.
- Phase 1 target behavior: default build uses surrogate; explicit `--features folding-real` enables the adapter shim for RED tests and early integration.
- Phase 2 target behavior: default build exercises the real adapter; explicit `--features folding-surrogate` keeps the old path available for regression and rollback.
- Phase 3 target behavior: no dual-path default remains, and consumers no longer see any surrogate-specific feature surface.

## Surrogate Retirement Schedule

The surrogate can be retired only when all of the following explicit conditions hold:

1. GREEN on all C.I.* RED tests that were introduced to protect the real adapter rollout.
2. `just p2-impl-gate` exits `0` with the real LatticeFold+ path as the default execution path.
3. External reviewer `APPROVE` is present for C.I.4 proof obligations.

Retirement sequence:

- First, complete a stabilization window where default CI runs the real adapter and the surrogate is exercised only in explicit regression jobs.
- Next, freeze benchmark evidence for the decisive `n=1024`, `fold-depth=10` row so rollback can compare against a fixed projected baseline.
- Finally, remove the surrogate implementation, delete `folding-surrogate`, and collapse any conditional code that only existed to preserve the transition period.

## Rollback Criteria

Rollback to the surrogate path is mandatory if any of the following occurs after the real LatticeFold+ implementation becomes active:

1. Fold test failure in CI.
2. Proof-sketch inconsistency flagged by reviewer.
3. Prover time exceeds `3×` the projected value at `t=513`, `n=1024`.

Operationally, rollback means re-enabling the surrogate as the default path with `folding-surrogate`, capturing evidence for the failing benchmark or review finding, and reopening the real adapter behind `folding-real` only after the failure has been explained. A rollback does not change the frozen interface spec; it only resets which backend satisfies that interface by default.
