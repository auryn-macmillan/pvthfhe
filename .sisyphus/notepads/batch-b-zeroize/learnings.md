# Batch B — Zeroize on NizkWitness structs

## Changes Made

### pvthfhe-fhe (real_nizk.rs)
- Added `use zeroize::{Zeroize, ZeroizeOnDrop};` (line 8)
- Changed `NizkWitness` derive from `#[derive(Clone, Debug, PartialEq, Eq)]` to `#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]` (line 30)
- `pvthfhe-fhe` already had `zeroize = { version = "1", features = ["zeroize_derive"] }` in Cargo.toml

### pvthfhe-nizk (lib.rs + Cargo.toml)
- Added `use zeroize::{Zeroize, ZeroizeOnDrop};` (line 25)
- Changed `NizkWitness` derive from `#[derive(Clone, Debug, PartialEq, Eq)]` to `#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]` (line 58)
- Added `zeroize = { version = "1", features = ["zeroize_derive"] }` to Cargo.toml dependencies

## Verification
- `cargo build -p pvthfhe-fhe -p pvthfhe-nizk` — passed, no new errors
