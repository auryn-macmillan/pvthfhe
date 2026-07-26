# Reproducing Benchmarks

This document provides instructions for reproducing the scaling and performance benchmarks reported in this repository.

> ⚠️ Benchmarks produced before 2026-05-09 measured the retired stub/surrogate
> pipeline (SHA hash chains, toy circuits) and are preserved only in git history.
> Current recipes exercise the real LatticeFold+ pipeline.

## Toolchain Versions (PINNED)

Reproducibility requires the exact toolchain versions used during development:

- **Rust**: stable channel (`rust-toolchain.toml`); artifacts here were built with `rustc 1.95.0`–`1.96.1`
- **Nargo (Noir)**: `1.0.0-beta.22` (`noirc 1.0.0-beta.22`)
- **BB CLI (Barretenberg)**: `5.0.0-nightly.20260522`
- **Forge (Foundry)**: `1.7.x` (`forge 1.7.1` used for these artifacts)

## Git Dependency Pins (PINNED)

- **`fhe`**: `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- **`fhe-traits`**: `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- **`fhe-math`**: `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b` — provides the iterative Cooley-Tukey (power-of-two) Number Theoretic Transform (NTT) used by Cyclo folding ring arithmetic (`crates/pvthfhe-cyclo/src/ring.rs`) and FHE backend `decrypt_from_shares`.
- **`e3-trbfv`**: intentionally not pinned in F1; plan A3 currently prefers direct composition of `fhe::mbfv` + `fhe::trbfv`, and `fhe::trbfv` is present at the locked `fhe.rs` rev above.

## Hardware Fingerprint

The benchmarks were executed on the following hardware:

- **CPU**: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S
- **RAM**: 32 GB (earlier runs on an 8 GB configuration; Noir N=8192 compilation needs ≥ 16 GB)
- **OS**: Ubuntu 24.04 LTS (Linux 6.8.0)

## Reproducing the Scaling Suite

To run the scaling benchmarks ($n=128$ to $n=1024$):

```bash
# Run the scaling benchmarks
just bench-scaling

# Run the reproducibility script (captures fingerprint and runs 3 repeats)
just reproduce-bench
```

Expected scaling behavior and current numbers are in
[`bench/results/comparison-2af6ac2.md`](bench/results/comparison-2af6ac2.md) and the
`scaling-n{128,256,512,1024}.json` envelopes validated by `just phase2-gate`.

### Regenerating the On-Chain Verifier

The HonkVerifier.sol is generated from the Noir `aggregator_final` circuit:

```bash
# 1. Execute the Noir circuit
(cd circuits && nargo execute --package aggregator_final --prover-name Prover_re)

# 2. Generate VK with keccak oracle hash (required for EVM-compatible 1888-byte VK)
bb write_vk --scheme ultra_honk --oracle_hash keccak \
  -b circuits/target/aggregator_final.json -o circuits/aggregator_final/target/

# 3. Generate Solidity verifier (post-process to fix EVM stack overflow)
bb write_solidity_verifier -k circuits/aggregator_final/target/vk \
  -o /tmp/raw_honk.sol -t evm-no-zk
python3 .sisyphus/scripts/split-honk-vk.py \
  /tmp/raw_honk.sol contracts/src/generated/HonkVerifier.sol

# 4. Build and test
forge build --root contracts
forge test --root contracts
```

> Note: `--oracle_hash keccak` is required to produce 1888-byte VKs compatible with
> `bb write_solidity_verifier`. Without it, VKs are 3680 bytes and the generator rejects them.
> The `split-honk-vk.py` script rewrites the single massive struct literal into sequential
> assignments to avoid exceeding the EVM's 16-slot stack limit (116 G1 points).
>
> The Noir `aggregator_final` circuit now always executes in the pipeline (no env var gate).
> Its `d_commitment` binds `aggregate_pk_hash` and `decrypt_nizk_hash` — properties previously
> verified only in deletable Rust code are now enforced on-chain through the UltraHonk proof.

## Scaling Methodology

Scaling benchmarks are performed in-process using the `pvthfhe-bench` crate. The benchmarks simulate the full pipeline:
1.  **DKG**: Simulated 3-round PVSS.
2.  **Partial Decrypt**: Generation of shares for $n$ parties.
3.  **Aggregation**: Folding $n$ proofs using the `FoldingAccumulator`.
4.  **Verification**: Final SNARK verification.

The measurements reflect end-to-end latency on the host machine.

## P4 Stack Pins

The P4 PVSS design memo fixes the Rust-side cryptographic and serialization stack to the following crate versions:

- `serde = "1.0.228"`
- `serde_json = "1.0.145"`
- `sha2 = "0.10.9"`
- `sha3 = "0.10.8"`
- `merlin = "3.0.0"`

These pins cover the frozen serde/JSON wire format, SHA-256 transcript digests, SHAKE256 transcript challenges, and the native Rust Fiat-Shamir transcript layer. (Earlier zkVM fallback pins were retired; no live code uses them.)

## Artifact Reproduction (Paper Claims)

To reproduce the core paper claims in one command:

```bash
just artifact-reproduce
```

This runs, in order:
1. `cargo build --workspace` — builds all Rust crates
2. `just p3-bench` — on-chain gas benchmark (verifies P3 gas-bound claim)
3. `just e2e-real` — end-to-end real integration test

Expected total runtime: ≤ 5 minutes on reference hardware.
Evidence files are written to `.sisyphus/evidence/p3-impl/`.

For the full gate suite:

```bash
just stage0-gate && just stage1-gate && just phase2-gate && just dkg-paper-gate
```
