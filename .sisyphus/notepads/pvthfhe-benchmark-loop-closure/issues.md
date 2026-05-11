# Issues — pvthfhe-benchmark-loop-closure

## 2026-05-06 Session bootstrap

- `parameters.toml` doesn't exist yet — X1 needs to create it with the canonical parameter table
- `tests/integration/` directory doesn't exist — X2 creates it
- No Justfile gate recipes yet — all must be added as tasks progress

- E1 baseline provenance initially used `source_commit: "HEAD"`; replaced with the fetched upstream SHA `c7e98029193f548ac4575fd05d007b034b75385c` to satisfy the provenance requirement more concretely.

## 2026-05-06 F2 BLOCKER

- **F2 is a human gate** (plan line ~751): "user runs `just bench-comparison` on their machine, reviews the output, and signs off."
- All implementation tasks X1–X3, W1–W6, S0–S5, N0–N6, P0a–P6, E1–E5, F1 are ✅ DONE.
- `bench/results/comparison-5d7853a.md` exists and is valid (no surrogate rows, honest n/a disclosure).
- `just bench-comparison` times out in the orchestrator VM (>2 min); must be run by the user.
- **No autonomous action remains. Plan is BLOCKED pending user sign-off on F2.**
