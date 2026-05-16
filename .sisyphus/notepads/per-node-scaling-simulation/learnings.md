# Learnings: per-node-scaling-simulation

## Implementation Notes (2026-05-16)

### Binary Architecture

**per_node.rs**: Measures wall time for ONE party at arbitrary n and t.
- Keygen: one call to `FhersBackend::keygen_share_with_session()` — creates one BFV key pair
- Shamir split: uses `fhe::trbfv::ShareManager::generate_secret_shares_from_poly()` — full split of one party's key into n-1 shares (measured directly, not extrapolated)
- Encrypt: one BFV encryption under aggregated public key, multiplied by (n-1) for extrapolation
- NIZK prove: one `RealNizkAdapter::prove()` call, multiplied by (n-1)
- NIZK verify: `RealNizkAdapter::verify()` called (t-1) times, measured directly
- All operations use real cryptographic functions (not mocks or fake timing)

**per_aggregator.rs**: Measures wall time for the aggregator at arbitrary n and t.
- Setup: Runs full KeygenSimulator at given n (expensive but needed for valid data)
- Compressor: `SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new()` with ceil(n/10) steps, then `prove_steps()` with synthetic inputs
- Aggregate decrypt: `backend.aggregate_decrypt()` with t shares
- C7: `SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new()` with t steps, then `prove_steps()`

### Dependency additions

- Added `fhe` (gnosisguild/fhe.rs) as optional dependency to pvthfhe-cli (needed for `ShareManager` in per_node.rs)
- Added to `with-fhe` feature

### Format string issue

- Rust 2021 edition: cannot mix named and positional format arguments in `format!()` macros
- Fix: use all positional `{}` or all named `{var}`

### CompressorError and anyhow

- `CompressorError` does not implement `StdError`, so `.context()` cannot be used on `Result<T, CompressorError>`
- Workaround: use `.map_err(|e| anyhow::anyhow!("...: {e:?}"))` instead

### Public key encoding

- `KeygenShare::bytes` is NOT a valid public key for encryption
- Must use `backend.aggregate_keygen(&[keygen_share])` to derive a proper `PublicKey`

### P3: Justfile recipes (2026-05-16)

- Added `just per-node n t seed` and `just aggregator n t seed` recipes to Justfile
- Both use `cargo run --release --bin <name>` with `--n`, `--threshold`, `--seed` args
- No explicit `--features` flag needed since `with-fhe` and `sonobe-compressor` are both in default features
- Cargo.toml already had `[[bin]]` entries for both binaries with correct `required-features`
- Commit: 82045fd — 7 files, single commit as per task instructions
