# Decisions — p2-m4-lattice-commitment

## 2026-05-16: AjtaiMatrix integration approach

### Decision: Env-var gating over feature flag
**Chose** `PVTHFHE_USE_AJTAI_MATRIX` env var over a Cargo feature flag.
**Rationale**: Enables runtime toggling without recompilation. The AjtaiMatrix is experimental;
the Cyclo path remains default and stable.

### Decision: epoch_hash derivation from seed
**Chose** to derive `epoch_hash = SHA256(seed.to_be_bytes())` inside the function
rather than threading it as a parameter.
**Rationale**: Matches the existing derivation at line 442; avoids signature changes to
`build_fold_instances` and `compute_ajtai_commitment_for_track`.

### Decision: Track A untouched
The AjtaiMatrix path only activates for Track B. Track A always uses Cyclo Ajtai.
Matches the plan's intent: "Do NOT change the default commitment path. Do NOT break Track A."
