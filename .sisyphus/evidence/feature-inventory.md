# PVTHFHE Feature Inventory

Generated: 2026-05-04  
Task: redteam-stage0-killswitch — gate mock backends behind opt-in env var

## Summary of Changes

Mock backends were previously activated via `features = ["mock"]` in the `pvthfhe-fhe`
dependency declaration across multiple crates, which caused mock code to run silently
as part of the default build. This has been corrected:

- All `features = ["mock"]` have been removed from dependency declarations.
- A `mock` Cargo feature now exists in crates that need it, but is **never in `default`**.
- `MockBackend::load_params` and every method panics unless
  `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` is set in the process environment.
- `KeygenSimulator::new` also panics unless the env var is set.
- `FhersBackend` (the default backend) now returns `FheError::Backend` sentinel errors
  for all cryptographic primitives instead of silently delegating to mock.

---

## Crate-by-Crate Inventory

### `pvthfhe-fhe`

| Feature                  | Mock/Surrogate? | In `default` Before | In `default` After |
|--------------------------|-----------------|---------------------|--------------------|
| `real-nizk`              | No              | ✅ Yes              | ✅ Yes             |
| `mock`                   | **Yes**         | ❌ No               | ❌ No              |
| `surrogate-decrypt-share`| **Yes**         | ❌ No               | ❌ No              |

Notes:
- `mock` was never in `pvthfhe-fhe`'s own `default`, but was force-activated by
  dependent crates via `features = ["mock"]` in their dep declarations.
- Runtime guard added to `MockBackend`: all methods panic unless env var is set.
- `FhersBackend` no longer delegates to `MockBackendInner`; it now returns
  `FheError::Backend` sentinel for all crypto operations until T33.

---

### `pvthfhe-aggregator`

| Feature        | Mock/Surrogate? | In `default` Before | In `default` After |
|----------------|-----------------|---------------------|--------------------|
| `real-folding` | No              | ❌ No               | ❌ No              |
| `real-verifier`| No              | ❌ No               | ❌ No              |
| `real-pvss`    | No              | ❌ No               | ❌ No              |
| `real-nizk`    | No              | ❌ No               | ❌ No              |
| `mock`         | **Yes**         | Implicit (force-on) | ❌ No              |

Changes:
- Removed `features = ["mock"]` from `pvthfhe-fhe` dep (was implicitly enabling mock).
- Added `mock = ["pvthfhe-fhe/mock"]` feature (opt-in only, not in default).
- `keygen::simulator` module gated behind `#[cfg(feature = "mock")]`.
- `KeygenSimulator::new` panics unless env var is set.

---

### `pvthfhe-cli`

| Feature | Mock/Surrogate? | In `default` Before | In `default` After |
|---------|-----------------|---------------------|--------------------|
| `mock`  | **Yes**         | Implicit (force-on) | ❌ No              |

Changes:
- Removed `features = ["mock"]` from `pvthfhe-fhe` dep.
- Added `mock = ["pvthfhe-fhe/mock", "pvthfhe-aggregator/mock"]` (opt-in only).
- `run_demo` function and related imports gated behind `#[cfg(feature = "mock")]`.
- `Commands::Demo` handler returns `anyhow::bail!` sentinel when `mock` not enabled.

---

### `pvthfhe-core`

| Feature | Mock/Surrogate? | In `default` Before | In `default` After |
|---------|-----------------|---------------------|--------------------|
| (none)  | —               | —                   | —                  |

Changes:
- Removed `features = ["mock"]` from `pvthfhe-fhe` **dev-dependency** declaration.
- No production code in this crate uses MockBackend.

---

### `pvthfhe-enclave-adapter`

| Feature | Mock/Surrogate? | In `default` Before | In `default` After |
|---------|-----------------|---------------------|--------------------|
| `stub`  | No              | ❌ No               | ❌ No              |

Changes:
- Removed `features = ["mock"]` from `pvthfhe-fhe` dep declaration.
- Source code does not directly import MockBackend (no further gating needed).

---

### `pvthfhe-bench`

| Feature          | Mock/Surrogate? | In `default` Before | In `default` After |
|------------------|-----------------|---------------------|--------------------|
| `backend-fhe-rs` | No              | ❌ No               | ❌ No              |
| `backend-poulpy` | No              | ❌ No               | ❌ No              |

Changes:
- Removed `mock` from `pvthfhe-fhe` dep feature list; `real-nizk` retained.

---

### Remaining Crates (no mock features)

| Crate                    | Features                    | Mock? |
|--------------------------|-----------------------------|-------|
| `pvthfhe-api`            | (none)                      | No    |
| `pvthfhe-circuits`       | (none)                      | No    |
| `pvthfhe-cyclo`          | (none)                      | No    |
| `pvthfhe-keygen`         | (none)                      | No    |
| `pvthfhe-keygen-spec`    | (none)                      | No    |
| `pvthfhe-micronova`      | (none)                      | No    |
| `pvthfhe-nizk`           | (none)                      | No    |

---

## Activation Protocol (Post-Change)

To use the mock backend (e.g. in CI or integration tests):

```bash
PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 cargo test -p pvthfhe-fhe --features mock
PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 cargo run -p pvthfhe-cli --features mock -- demo --n 4
```

Without the env var, any mock code path will **panic** immediately.  
Without the `mock` feature, `Commands::Demo` returns a sentinel error.  
Without the `mock` feature, `FhersBackend` primitives return `FheError::Backend` sentinel.
