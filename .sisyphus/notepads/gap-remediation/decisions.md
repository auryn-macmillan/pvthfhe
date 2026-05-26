# Decisions — Finding 5 (Parameter Presets)

## OnceLock pattern

Used `std::sync::OnceLock` instead of `once_cell::Lazy` or `lazy_static`. Rust stable (1.70+) provides `OnceLock` natively. The `set` method is first-write-wins, matching the semantic that the preset is set once at startup.

## Constructor functions instead of const

Presets use `pub fn production8192() -> Self` rather than `pub const PRODUCTION8192: Self = ...` because `vec![]` is not const-stable. This is fine since `set_active_preset` happens at runtime.

## Dynamic moduli vs hardcoded 3 limbs

Functions that previously assumed 3 RNS limbs now use `num_rns_limbs()` (delegates to `pvthfhe_types::rlwe_moduli().len()`). This enables the insecure512 preset with 1 limb to function correctly.

## Module headers updated

sigma.rs module header changed from specific values (N=8192, Q=3 limbs, 174 bits) to generic parameterized description. The specific production values are preserved in `BfvParameterPreset::production8192()`.

## Single mutable global state

The `OnceLock<BfvParameterPreset>` is declared in `pvthfhe-types` and accessed through functions (`rlwe_n()`, `rlwe_moduli()`, etc.). All crates query through `pvthfhe_types::rlwe_n()` (or `pvthfhe_nizk::sigma::rlwe_n()` which delegates). Only one global preset is active at a time.
