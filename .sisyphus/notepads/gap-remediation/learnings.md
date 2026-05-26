# Learnings — Finding 5 (Parameter Presets)

## Pattern: const → OnceLock global state

- `pub const RLWE_N: usize = 8192` was replaced with `pub fn rlwe_n() -> usize { pvthfhe_types::rlwe_n() }`
- `OnceLock<BfvParameterPreset>` holds the active preset; default is Production8192
- `set_active_preset(...)` must be called before any NIZK/FHE operations
- Callers use `pvthfhe_nizk::sigma::rlwe_n()` instead of `pvthfhe_nizk::sigma::RLWE_N`

## Files changed

- `pvthfhe-types/src/lib.rs`: Added `BfvParameterPreset` struct, `OnceLock`, preset constructors
- `pvthfhe-nizk/src/sigma.rs`: Removed `const RLWE_N`, added `rlwe_n()` + `num_rns_limbs()` delegating to types
- `pvthfhe-nizk/src/bfv_sigma.rs`: Changed to dynamic `rlwe_n()`, removed hardcoded moduli
- `pvthfhe-nizk/src/adapter.rs`: Dynamic N, dynamic moduli in `expand_c_rns`
- `pvthfhe-cli/src/bin/pvthfhe_e2e.rs`: Added `--params` flag, calls `set_active_preset`
- `pvthfhe-cli/src/main.rs`: Added `--params` to `Demo` subcommand
- `pvthfhe-cli/src/full_pipeline.rs`: Replaced 2x `const RLWE_N` blocks with dynamic calls
- All test files updated to import `rlwe_n` instead of `RLWE_N`

## Presets

- `Insecure512`: N=512, 1 modulus (549755903489 ≈ 2^39), plaintext=100, bound=16
- `Production8192`: N=8192, 3 production moduli, plaintext=65536, bound=16

## Verification

- All pvthfhe-nizk tests pass (42 tests, 0 failures)
- `cargo build --lib` for pvthfhe-types, pvthfhe-nizk, pvthfhe-pvss, pvthfhe-fhe, pvthfhe-aggregator all pass
- `pvthfhe-cli` builds with all features
- Demo starts with `--params production8192` (default) and shows "active parameter preset set"
