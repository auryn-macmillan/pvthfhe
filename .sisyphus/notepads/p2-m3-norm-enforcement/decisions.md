# P2-M3 Norm Enforcement - Decisions

## Test Registration

Added `[[test]]` entry in `Cargo.toml` for `cyclo_norm_enforcement` test target. No required-features since the norm module has no feature gating.

## Norm Bounds

Per plan:
- `B = 1024` (witness bound)
- `B_e = 16` (error bound)
- `B_z = 2049` (response bound = 2*B + 1)
