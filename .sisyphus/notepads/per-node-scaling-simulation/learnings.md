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
- C7: Tree path: per-leaf `SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new(epoch_hash, 1)` + `prove_steps_c7()` (1 step each), then `CompressionTree::build(leaf_hashes)`. Falls back to flat Nova IVC (t steps) on any leaf failure or tree build failure.

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

## C7 Tree Path Fix (2026-05-18)

### Problem
The per_aggregator C7 tree path was a surrogate — it only hashed dummy field elements 
and built a CompressionTree from those hashes. No actual Nova proving happened in the 
tree path. The flat Nova fallback (lines 207-233) DID prove, but the tree path was fake.

### Fix
Replaced the dummy-hash tree path with per-leaf C7 Nova proving:
1. For each leaf `i` in `0..args.threshold`:
   - Create `SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new(epoch_hash, 1)` (leaf_count=1)
   - Create 1 `ExternalInputs5` step with dummy [42+i, 1, coeff_commitment, 0, derived_r]
   - Call `compressor.prove_steps_c7(&acc, &[step])` — actual Nova proving
   - Hash proof bytes via SHA-256 for leaf hash
2. Pad leaf_hashes to power of 2
3. Build `CompressionTree::build(&leaf_hashes)`
4. On any failure: depth=0 → flat Nova fallback preserved

### Verified
`cargo run -p pvthfhe-cli --release --bin per-aggregator -- --n 16 --threshold 7 --seed 1`
Output: `c7: 327.1s (tree depth=3, 8 leaves)` — tree path active, real proving cost.

### Key insight
`CompressedProof` is `pub struct CompressedProof(pub Vec<u8>)` (tuple struct). 
Access proof bytes via `proof.0` (not `.proof_bytes()` — that method is on the 
`ProofCompressor` trait, not the struct).

### Removed unused imports
`ark_ff::{BigInteger, PrimeField}` removed — old tree path used `into_bigint()` for 
dummy hashing; new tree path uses `Sha256::digest` directly on proof bytes.
