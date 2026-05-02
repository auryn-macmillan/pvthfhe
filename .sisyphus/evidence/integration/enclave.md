# Enclave Adapter Integration

## Overview

`pvthfhe-enclave-adapter` bridges PVTHFHE's threshold FHE backend to the [gnosisguild/enclave](https://github.com/gnosisguild/enclave) ciphernode/aggregator interface boundary. No upstream changes to enclave are required.

## Adapter Structs

| Struct | Enclave Role | PVTHFHE Trait |
|--------|-------------|---------------|
| `PvthfheEnclaveCiphernode<B>` | `ciphernode` | `EnclaveCiphernode` (stub) |
| `PvthfheEnclaveAggregator<B>` | `aggregator` | `EnclaveAggregator` (stub) |

## Feature Flags

- `stub` — enables the vendored Enclave type stubs from `vendor-stub/enclave_types.rs` and the trait implementations. Without this flag the crate compiles but exposes only the struct constructors.

## Vendored Stub

`vendor-stub/enclave_types.rs` contains minimal read-only copies of the Enclave interface types (`EnclaveKeyShare`, `EnclaveCiphertext`, `EnclaveDecryptShare`, `EnclaveProof`, `EnclavePublicKey`) and the two traits (`EnclaveCiphernode`, `EnclaveAggregator`). This file is locked after T42 creation; see `enclave-stub-hash.txt` for integrity verification.

## Downstream Consumption

A downstream Enclave fork would:

1. Add `pvthfhe-enclave-adapter = { git = "...", features = ["stub"] }` to its `Cargo.toml`.
2. Instantiate a backend: `let backend = MockBackend::load_params(TOML)?;` (or a real FHE backend).
3. Wrap it: `let node = PvthfheEnclaveCiphernode::new(backend, party_id);`
4. Pass `node` wherever an `EnclaveCiphernode` is expected.

The adapter translates between Enclave's `Vec<u8>`-based wire types and PVTHFHE's opaque `KeygenShare`/`DecryptShare` types via direct byte passthrough (no extra serialization overhead).

## Wire Format Note

PVTHFHE uses CBOR + 4-byte BE length prefix for all wire messages (T18/T19). The adapter currently passes raw bytes; a production integration would wrap/unwrap the CBOR envelope at the adapter boundary.

## Security Note

The `verify_proof` method in `PvthfheEnclaveAggregator` returns `Ok(true)` unconditionally in this stub. A production implementation must invoke the UltraHonk verifier (T19/T43).
