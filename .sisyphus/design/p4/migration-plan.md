# P4 Migration Plan: Surrogate → Hermine-Adapted PVSS

## Goal

Replace the surrogate coordinator in `crates/pvthfhe-aggregator/src/keygen/protocol.rs` with the real Hermine-adapted PVSS implementation without ever breaking CI. The migration is gated behind a Cargo feature flag so the surrogate remains the active code path until each piece of the real implementation is proven correct.

## Adapter Architecture

```
┌─────────────────────────────────────────────────────────┐
│  crates/pvthfhe-aggregator  (unchanged coordinator)      │
│  src/keygen/protocol.rs     (surrogate — read-only now)  │
└────────────────────┬────────────────────────────────────┘
                     │  calls via KeygenAdapter trait
                     ▼
┌─────────────────────────────────────────────────────────┐
│  crates/pvthfhe-keygen                                   │
│  src/lib.rs — KeygenAdapter trait                        │
│                                                          │
│  #[cfg(feature = "migration-stub")]                      │
│  src/adapter/stub.rs — SurrogateAdapter (delegates back) │
│                                                          │
│  #[cfg(not(feature = "migration-stub"))]  (T4+)          │
│  src/adapter/hermine.rs — HermineAdapter                 │
└─────────────────────────────────────────────────────────┘
```

### `KeygenAdapter` trait

The trait exposes the same protocol-semantic objects frozen in `.sisyphus/design/p4/interface-spec.md`:

```rust
pub trait KeygenAdapter: Send + Sync {
    fn generate_session(&self, participants: &[Participant], threshold: u16)
        -> Result<KeygenSession, KeygenError>;

    fn generate_shares(&self, session: &KeygenSession, dealer_id: u16)
        -> Result<(Vec<Share>, PublicVerificationArtifact), KeygenError>;

    fn verify_transcript(&self, artifact: &PublicVerificationArtifact)
        -> Result<bool, KeygenError>;

    fn reconstruct_bfv_key(&self, shares: &[Share])
        -> Result<BFVPublicKey, KeygenError>;
}
```

### Stub adapter (`migration-stub` feature)

- Implements `KeygenAdapter` by returning `Ok(unimplemented-placeholder)` values.
- Compiles without any dependency on the real PVSS crates.
- Allows `pvthfhe-aggregator` to depend on `pvthfhe-keygen/migration-stub` immediately.
- CI remains green because the surrogate coordinator still controls the live code path.

### Hermine adapter (real implementation, T4+)

- Will be gated behind `#[cfg(not(feature = "migration-stub"))]`.
- Depends on `fhe.rs` from `gnosisguild/fhe.rs` (chosen backend, deferred to T4).
- Must pass all existing integration tests in `pvthfhe-aggregator` before the feature flag is flipped.

## Migration Steps

| Step | Description                                              | CI Invariant                        |
|------|----------------------------------------------------------|-------------------------------------|
| M0   | Land `crates/pvthfhe-keygen` with `migration-stub` only  | `cargo check` green (this task)     |
| M1   | Add `KeygenAdapter` trait + `SurrogateAdapter` impl       | All tests green                     |
| M2   | Wire aggregator to use `KeygenAdapter` (via feature flag) | Tests green with `migration-stub`   |
| M3   | Implement `HermineAdapter` (T4)                           | Tests green with/without flag       |
| M4   | Remove surrogate protocol.rs, flip default feature        | Tests green, surrogate deleted      |

## CI-Green Guarantee

- The `migration-stub` feature is **always-on** in CI until Step M4.
- The surrogate `protocol.rs` is **never modified** before Step M4.
- Each step is merged as a separate PR with explicit `cargo test --workspace` verification.
- The `pvthfhe-keygen` crate does **not** appear in `pvthfhe-aggregator`'s dependencies until Step M2.

## Dependency Graph

```toml
# crates/pvthfhe-keygen/Cargo.toml (this task)
[features]
migration-stub = []  # no extra deps; stub returns placeholder values

# crates/pvthfhe-aggregator/Cargo.toml (added in M2, not this task)
[dependencies]
pvthfhe-keygen = { path = "../pvthfhe-keygen", features = ["migration-stub"] }
```

## Risk Register

| Risk                                   | Mitigation                                              |
|----------------------------------------|---------------------------------------------------------|
| HermineAdapter not ready at T4         | `migration-stub` can stay on; blocks only M4 not M3     |
| Trait surface change after M1          | Interface spec is frozen; any change requires a new ADR |
| BFV key reconstruction semantics differ| M3 includes dedicated integration tests before any flip |

## References

- Interface spec: `.sisyphus/design/p4/interface-spec.md`
- Stack decision: `.sisyphus/design/p4/stack-decision.md`
- Surrogate: `crates/pvthfhe-aggregator/src/keygen/protocol.rs`
