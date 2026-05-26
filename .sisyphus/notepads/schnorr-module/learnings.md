# Learnings - Schnorr Module

## Successful patterns
- `light-poseidon` 0.4 with `Poseidon::new_circom(n).hash()` is the established pattern for Poseidon hashing in pvthfhe-nizk (used by sigma.rs)
- arkworks 0.5 `CurveGroup::into_affine()` and `AffineRepr::into_group()` provide ergonomic conversions
- `Fr::from_le_bytes_mod_order` is the canonical way to derive scalar field elements from byte randomness
- Use `#[cfg(test)] mod tests` with `use rand_core::SeedableRng;` for test imports

## Conventions
- Module doc comments use `//!` for crate-level, `///` for items
- Public API functions must have doc comments (enforced by `#![deny(missing_docs)]` in lib.rs)
- Domain separator for Schnorr: `0x7363686e6f7272` ("schnorr" in ASCII)
