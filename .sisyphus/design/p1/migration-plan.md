# P1 Migration Plan

## Rollout Phases

### Phase 1 — RED tests behind `real-nizk`

- Add RED protocol and adapter tests for the real decrypt-share relation under the `real-nizk` Cargo feature as required by **B.I.1**.
- Keep the production default on the surrogate path; test fixtures must exercise the frozen `NizkStatement` / `NizkWitness` / `NizkProof` interface rather than backend-specific circuit objects.
- The existing surrogate remains the only default proving backend while RED evidence is collected.

### Phase 2 — GREEN implementation shipped, surrogate annotated but retained

- Ship the first GREEN implementation for the SLAP-backed adapter in **B.I.2** behind `real-nizk`.
- Annotate the surrogate path as temporary compatibility code and route it through the same semantic adapter boundary.
- The surrogate is **not deleted** in this phase; it remains available for regression comparison and emergency rollback.

### Phase 3 — CI default flips to `real-nizk`

- After GREEN tests, adversarial tests, and proof updates pass, flip CI default to `real-nizk`.
- Keep the old path behind the explicit `surrogate-decrypt-share` feature so regressions can still be reproduced intentionally.
- All new P1 acceptance and downstream P2-facing checks must exercise the real backend by default from this point onward.

### Phase 4 — Surrogate retirement milestone

- Retire the surrogate path only after **both** conditions hold: (1) `just p1-impl-gate` is green with the real backend as default, and (2) there are **30 consecutive calendar days** of green CI on the default `real-nizk` path with no rollback-trigger incident.
- If either condition is unmet, surrogate retirement is deferred; if both are met, the surrogate can be removed in the next scoped cleanup task.

## Feature Flag Schedule

| Milestone | `real-nizk` | `surrogate-decrypt-share` | Default behavior |
| --- | --- | --- | --- |
| Before B.I.1 | absent or off | on / available | surrogate remains default |
| B.I.1 RED | on for targeted RED tests only | on | surrogate default, real path test-only |
| B.I.2 GREEN | on for implementation and targeted integration tests | on | surrogate default until CI flip |
| B.I.3/B.I.4 stabilization | on | on | dual-path regression period |
| Phase 3 CI flip | on | on but non-default | real backend default in CI and local happy path |
| Phase 4 retirement trigger met | on | off by default; scheduled for removal | real backend only for production path |

Scheduling rules:

- No task may enable `real-nizk` by default before the B.I.2 GREEN implementation and adversarial coverage are both green.
- No task may remove `surrogate-decrypt-share` before the explicit retirement condition in this document is satisfied.
- Every flag transition must be paired with a matching evidence log so regressions are attributable to a specific flip.

## Surrogate Retirement

The surrogate is a bounded compatibility layer, not a permanent second implementation.

- **Retirement trigger:** first commit after `just p1-impl-gate` passes and 30 consecutive calendar days of green CI on default `real-nizk` complete.
- **Retirement scope:** remove surrogate-only production wiring, delete the `surrogate-decrypt-share` implementation path, and keep only historical benchmark/evidence artifacts.
- **Retirement prerequisite review:** confirm that downstream P2 consumers depend only on the frozen semantic interface, not surrogate-specific verifier metadata.
- **Retirement guard:** if any rollback criterion fires during the 30-day window, reset the retirement clock to zero.

## Rollback Criteria

Rollback is mandatory, not discretionary, when any of the following exact conditions occurs:

1. **Pivot to Greyhound** if the SLAP real implementation exceeds any primary advisory threshold at `n=1024` by more than **25%** *and* Greyhound stays within verifier-time and proof-size thresholds on the same statement family.
2. **Pivot to Greyhound** if SLAP verifier time exceeds **40 ms** at `n=1024`, because that violates the recursion-shape budget frozen in `.sisyphus/design/p1/stack-decision.md`.
3. **Pivot to Rust-in-zkVM fallback** if both SLAP and Greyhound exceed the `n=1024` prover-time threshold by more than **2×**, or if either native stack cannot produce a stable deterministic proof object compatible with the frozen `NizkProof` contract.
4. **Immediate surrogate re-enable** if the default `real-nizk` path causes two consecutive CI failures on the same regression class, any soundness/adversarial test failure, or any mismatch between real-backend proofs and the frozen public-input encoding.
5. **Retirement freeze** if a downstream P2 integration test requires surrogate-specific metadata or if a reviewer memo records `REQUEST_CHANGES`/`REJECT` against rollback completeness.

These criteria intentionally separate three actions:

- **temporary rollback** to `surrogate-decrypt-share` for service continuity,
- **research pivot** from SLAP to Greyhound,
- **delivery fallback** from native lattice stacks to Rust-in-zkVM.
